"""Decode the GPIO and PWM registers the emulator observed during a run.

The emulator records the last value written to each peripheral register and
prints them on `[EMU_GPIO]` / `[EMU_PWM]` lines; this turns those into
something readable for the report.

GPIO layout (beken378/driver/gpio/gpio.h):
    per-pin config at GPIO_BASE + n*4 for n = 0..31
        bit0 input level   bit1 output level   bit2 input enable
        bit3 output enable bit4 pull up/down   bit5 pull enable
        bit6 second function enable            bit7 input monitor
    index 32 is REG_GPIO_FUNC_CFG, 46/47 are REG_GPIO_FUNC_CFG_2/_3 - function
    selects, not pins, so they are reported separately rather than decoded as
    if they were.

BK7231U/BK7252 P32..P39 are not contiguous with P0..P31: their physical
register slots are 48..55, after those function-select words.  The decoder
translates those slots back to logical pin numbers for front ends while
keeping the function words separate.

A pin the firmware never wrote is left as "factory": on real silicon that is
whatever reset state the pad has, and the emulator has not been told otherwise.
"""

import os
import re

PIN_COUNT = 32
BK7252_PIN_COUNT = 40
BK7252_EXT_SLOT = 48
FUNC_REGS = {32: "REG_GPIO_FUNC_CFG", 46: "REG_GPIO_FUNC_CFG_2",
             47: "REG_GPIO_FUNC_CFG_3"}



# Special-function pin names for BK7231N, from OpenBeken's
# HAL_PIN_GetPinNameAlias (src/hal/bk7231/hal_pins_bk7231.c). Without these a
# pin in "second function" mode is unreadable - it is precisely these aliases
# that say WHICH peripheral took the pin.
PIN_ALIAS = {
    0: "TXD2", 1: "RXD2",           # UART2 - the debug/log port
    11: "TXD1", 10: "RXD1",         # UART1 - the TuyaMCU / programming port
    6: "PWM0", 7: "PWM1", 8: "PWM2", 9: "PWM3",
    24: "PWM4/ADC2", 26: "PWM5/ADC1",
    21: "ADC6", 22: "ADC5", 28: "ADC4",
}

# What a pin in second-function mode is most likely doing, by peripheral group.
PIN_ROLE = {
    0: "UART2 TX (log)", 1: "UART2 RX (log)",
    11: "UART1 TX (TuyaMCU / programming)", 10: "UART1 RX (TuyaMCU / programming)",
    6: "PWM channel 0", 7: "PWM channel 1", 8: "PWM channel 2", 9: "PWM channel 3",
    24: "PWM channel 4 / ADC2", 26: "PWM channel 5 / ADC1",
}


def pin_alias(pin):
    return PIN_ALIAS.get(pin, "")


def pin_role(pin):
    return PIN_ROLE.get(pin, "")


# Mode words the SDK's gpio_config() actually writes, from
# beken378/driver/gpio/gpio.c - byte-identical in the BK7231T and BK7231N
# trees, so this table is not family-specific:
#
#     GMODE_OUTPUT               0x00        GMODE_SECOND_FUNC          0x48
#     GMODE_INPUT                0x0C        GMODE_SECOND_FUNC_PULL_UP  0x78
#     GMODE_INPUT_PULLUP         0x3C
#     GMODE_INPUT_PULLDOWN       0x2C
#
# Bit 3 is the trap. gpio.h names it GCFG_OUTPUT_ENABLE_POS, but the table
# above shows it SET for every input and second-function mode and CLEAR for
# GMODE_OUTPUT - it is an output *disable*. Decoding it as an active-high
# enable (as this file first did) inverts the whole picture: every
# peripheral-owned pin prints "OUTPUT = 0" and every genuinely driven output
# is missed. That is why a pin reading 0x02 is not an idle latch but a GPIO
# actively driving HIGH.
KNOWN_MODES = {
    0x00: "GMODE_OUTPUT",
    0x0C: "GMODE_INPUT",
    0x2C: "GMODE_INPUT_PULLDOWN",
    0x3C: "GMODE_INPUT_PULLUP",
    0x48: "GMODE_SECOND_FUNC",
    0x78: "GMODE_SECOND_FUNC_PULL_UP",
}


def decode_pin(value):
    """Return a readable description of one pin config word."""
    second = bool(value & (1 << 6))
    # Bit 3 clear == the GPIO output driver is active. See the note above.
    driving = not (value & (1 << 3))
    in_en = bool(value & (1 << 2))
    level = 1 if value & (1 << 1) else 0
    bits = []
    if second:
        # A peripheral owns the pad; naming which one is the whole point,
        # otherwise every UART and PWM pin looks identical.
        bits.append("second function")
    elif driving:
        bits.append("OUTPUT = %d" % level)
    if in_en:
        bits.append("input")
    if value & (1 << 5):
        bits.append("pull-%s" % ("up" if value & (1 << 4) else "down"))
    if value & (1 << 7):
        bits.append("monitor")
    if not bits:
        bits.append("configured, no direction enabled")
    return ", ".join(bits)


def mode_name(value):
    """The SDK mode constant this word corresponds to, if it is an exact match.

    gpio_config() writes these whole-word, but gpio_output() then flips bit 1
    in place, so a driven pin is "GMODE_OUTPUT with bit 1 set" rather than an
    exact hit - hence the retry with the output level masked off.
    """
    if value in KNOWN_MODES:
        return KNOWN_MODES[value]
    base = value & ~(1 << 1)
    if base in KNOWN_MODES:
        return "%s + output %d" % (KNOWN_MODES[base], 1 if value & (1 << 1) else 0)
    return ""


def parse_lines(lines):
    """Collect [EMU_GPIO]/[EMU_PWM] values from harness-captured lines."""
    gpio, pwm = {}, {}
    for line in lines:
        if line.startswith("[EMU_GPIO]"):
            parts = line.split()
            if len(parts) >= 3:
                try:
                    gpio[int(parts[1])] = int(parts[2], 16)
                except ValueError:
                    pass
        elif line.startswith("[EMU_PWM]"):
            parts = line.split()
            if len(parts) >= 3:
                try:
                    pwm[int(parts[1], 16)] = int(parts[2], 16)
                except ValueError:
                    pass
    return gpio, pwm


def parse_i2c_lines(lines):
    """Collect {(scl, sda): raw_bytes} from [EMU_I2C] lines."""
    frames = {}
    for line in lines:
        if line.startswith("[EMU_I2C]"):
            parts = line.split()
            if len(parts) >= 4:
                try:
                    scl, sda = int(parts[1]), int(parts[2])
                    frames[(scl, sda)] = bytes.fromhex(parts[3])
                except ValueError:
                    pass
    return frames


def gpio_pin_values(gpio, chip=""):
    """Return a logical ``pin -> config`` map, excluding controller words."""
    pins = {pin: value for pin, value in gpio.items() if 0 <= pin < PIN_COUNT}
    if chip in ("BK7231U", "BK7252"):
        for pin in range(PIN_COUNT, BK7252_PIN_COUNT):
            slot = BK7252_EXT_SLOT + pin - PIN_COUNT
            if slot in gpio:
                pins[pin] = gpio[slot]
    return pins


def gpio_table(gpio, pin_count=PIN_COUNT):
    """[(pin, alias, state, detail)] for every pin, touched or not."""
    rows = []
    for pin in range(pin_count):
        alias = pin_alias(pin)
        if pin in gpio:
            detail = decode_pin(gpio[pin])
            role = pin_role(pin)
            if role and "second function" in detail:
                detail = detail.replace("second function", role)
            rows.append((pin, alias, "set by firmware", detail))
        else:
            rows.append((pin, alias, "factory", "not configured"))
    return rows


def func_rows(gpio):
    return [(FUNC_REGS[i], "0x%08X" % v) for i, v in sorted(gpio.items())
            if i in FUNC_REGS]


# PWM. pwm.h selects PWM_BASE as either PWM_NEW_BASE (0x802A00) or
# PWM_NEW_BASE + 0x80 via a build switch, so the capture covers both and the
# layout is inferred from which offsets the firmware actually wrote.
#
# In the new layout each channel has a period ("counter") and a duty
# ("capture") register:
#     period(n) = PWM_BASE + 0x08 + 8*n      duty(n) = PWM_BASE + 0x0C + 8*n
#
# Verified against a real device: a Woox CW bulb wrote period 0x54A2 (21666),
# and 26 MHz / 21666 = 1200.04 Hz - exactly the pwmhz:1200 its own stored Tuya
# config declares. Two independent sources agreeing pins the layout down.
PWM_CLOCK_HZ = 26000000


def infer_base(pwm):
    """Return the offset PWM_BASE sits at within the captured window."""
    # Writes at or above +0x80 mean the shifted layout is in use. Offsets at
    # 0x100+ belong to a DIFFERENT peripheral (pwm_new on BK7231N, audio on
    # the 7252 family) and must not influence the old-block base inference.
    return 0x80 if any(0x80 <= off < 0x100 for off in pwm) else 0x00


# ---------------------------------------------------------------------------
# BK7231N "pwm_new" block (beken378/driver/pwm/pwm_new.c/h in the N SDK).
#
# A different peripheral from the old block above: REG_PWM_BASE_ADDR is
# 0x00802B00, i.e. offset 0x100 in our capture window, with three GROUPS of
# 0x40 bytes. Each group holds one shared CTRL word and two sub-channels of
# four edge-time registers T1..T4:
#
#     group g at 0x100 + 0x40*g:
#         +0x00 CTRL      +0x04..0x10 sub0 T1..T4    +0x14..0x20 sub1 T1..T4
#
# Logical channel ch (0..5) = group ch//2, sub ch%2; pad map is the same
# 6,7,8,9,24,26. CTRL packs per-sub fields at bit 8*s: mode[2:0] (1 = PWM),
# enable at +3, init level at +6, cfg-update strobe at +7; pre-divider is
# bits[23:16] (never set by the SDK - 0 means divide-by-1); int-status W1C at
# bits 30/31. The strobe and int bits read back sticky in a last-value capture
# and must be masked before interpreting.
#
# T4 is the period. T1..T3 are LEVEL-TOGGLE times: output starts at the init
# level and flips at each nonzero T < T4 (a toggle at >= T4 coincides with
# reload and never happens - the SDK's CW code relies on that). Duty therefore
# comes from replaying the toggles, not from a duty register.
#
# Why the gating on which decoder to use is by CHIP: pwm_new.c is compiled
# only for SOC_BK7231N and the old pwm.c only for everything else, and on the
# 7252 family 0x802B00 is the AUDIO block - so the same captured offsets mean
# different things per chip, and only the harness knows which chip a run is.
PWM_NEW_OFF = 0x100


def pwm_new_channels(pwm):
    """[(channel, period, high_ticks, freq_hz, duty_pct)] from pwm_new writes."""
    rows = []
    for ch in range(6):
        g, s = ch // 2, ch % 2
        base = PWM_NEW_OFF + 0x40 * g
        ctrl = pwm.get(base)
        if ctrl is None:
            continue
        if not (ctrl >> (8 * s + 3)) & 1:        # enable
            continue
        if (ctrl >> (8 * s)) & 0x7 != 1:         # mode: 1 = PWM (2 = timer)
            continue
        toff = base + 0x04 + 0x10 * s
        t = [pwm.get(toff + 4 * i) or 0 for i in range(4)]
        period = t[3]
        if not period:
            continue                              # cleared = channel stopped
        pre = (ctrl >> 16) & 0xFF                 # SDK never sets it; 0 = /1
        freq = PWM_CLOCK_HZ / (max(1, pre) * period)
        if not (PWM_FREQ_MIN_HZ <= freq <= PWM_FREQ_MAX_HZ):
            continue
        level = (ctrl >> (8 * s + 6)) & 1         # init level
        high, prev = 0, 0
        for tog in sorted(x for x in t[:3] if 0 < x < period):
            high += (tog - prev) * level
            level ^= 1
            prev = tog
        high += (period - prev) * level
        rows.append((ch, period, high, freq, 100.0 * high / period))
    return rows


# A real PWM output lands somewhere between mains-flicker and switching-supply
# territory. Anything outside this is not a period register being read as one:
# a firmware doing NO pwm still writes 0x173EED80 (390,000,000 -> 0.067 Hz) into
# this window for the FreeRTOS tick, and decoding that as a light produced a
# confident "0.1 Hz" in the report. Verified plausible values sit well inside:
# a Woox CW bulb uses 0x54A2 -> 1200 Hz, matching its own stored pwmhz:1200.
PWM_FREQ_MIN_HZ = 20
PWM_FREQ_MAX_HZ = 100000


def pwm_channels(pwm):
    """[(channel, period, duty, freq_hz, duty_pct)] for plausible channels.

    Two register layouts exist, and beken378/driver/pwm/pwm.h selects BOTH the
    base and the layout from the same switch, so they always go together:

      CFG_SOC_NAME == SOC_BK7231      other SOCs
      PWM_BASE = PWM_NEW_BASE         PWM_BASE = PWM_NEW_BASE + 0x20*4 (+0x80)
      PWM0_COUNTER = BASE + 2*4       PWM0_END       = BASE + 2*4
      PWM1_COUNTER = BASE + 4*4       PWM0_DUTY_CYCLE= BASE + 3*4
        -> stride 8                   PWM1_COUNTER   = BASE + 5*4
      END is bits 0-15 and DC is        -> stride 12, END and DUTY are
      bits 16-31 of that ONE word       SEPARATE 32-bit registers

    This function previously used stride 8 together with a separate duty
    register - a hybrid matching NEITHER layout, which is why decoded channels
    came out as nonsense. Confirmed against hardware: an OpenBeken image told
    "PWMFrequency 1400; SetPinRole 9 PWM; SetChannel 1 50" wrote 0x488B (18571
    = 26 MHz / 1400) at +0xAC and 0x2445 (9285 = 50%) at +0xB0, which is
    exactly channel 3 under the +0x80 / stride-12 reading.
    """
    base = infer_base(pwm)
    rows = []
    if not base:
        # Only the +0x80 / stride-12 layout is confirmed against hardware (see
        # the 1400 Hz case above). With every write below +0x80 there is no way
        # to tell an old-layout channel from the timer registers that share
        # this page: a firmware doing no PWM at all writes 0x173EED80 at +0x08,
        # whose low 16 bits (0xED80) read back as a perfectly believable 427 Hz
        # at 9.8% duty. Declining to decode is the honest answer - the raw
        # registers are still reported, so nothing is hidden.
        return rows, pwm.get(0, 0), base
    for ch in range(6):
        period = pwm.get(base + 0x08 + 12 * ch)
        duty = pwm.get(base + 0x0C + 12 * ch)
        if not period:
            continue
        freq = PWM_CLOCK_HZ / period
        if not (PWM_FREQ_MIN_HZ <= freq <= PWM_FREQ_MAX_HZ):
            continue
        pct = (100.0 * duty / period) if duty is not None else None
        rows.append((ch, period, duty, freq, pct))
    return rows, pwm.get(base, 0), base


def ctl_channels(ctl):
    """Channels PWM_CTL says are enabled.

    pwm.h gives each channel a 4-bit field in PWM_CTL: PWMn_EN_BIT is
    1 << (4*n), with int-enable at 4*n+1 and a 2-bit mode at 4*n+2. This is an
    INDEPENDENT witness to the channel numbering, which is the thing this
    decoder has historically got wrong - it comes from a different register
    than the period/duty pair. Confirmed on hardware: driving pin 9 (PWM3) left
    CTL = 0x1000 (1 << 12) and pin 7 (PWM1) left CTL = 0x10 (1 << 4).
    """
    return [n for n in range(6) if ctl & (1 << (4 * n))]


# PWM-capable pads, from OpenBeken's HAL_PIN_GetPinNameAlias table.
PWM_PINS = {6: 0, 7: 1, 8: 2, 9: 3, 24: 4, 26: 5}


def pwm_output_pins(gpio):
    """Pins actually handed to the PWM peripheral.

    PWM register writes on their own prove nothing: fclk_init() runs a PWM
    channel in PMODE_TIMER with duty_cycle 0 as the FreeRTOS tick, on every
    boot, bound to no pad at all (beken378/func/misc/fake_clock.c). So a
    "wrote PWM registers" test tags literally every firmware. A PWM-capable
    pad switched to second function is the thing that distinguishes a bulb
    driving its channels from the OS keeping time.
    """
    return sorted(pin for pin, val in gpio.items()
                  if pin in PWM_PINS and (val & (1 << 6)))


def pwm_registers(pwm):
    """[(offset, value)] for every PWM register the firmware wrote."""
    return [("+0x%02X" % off, "0x%08X" % val) for off, val in sorted(pwm.items())]


# ---------------------------------------------------------------------------
# LED driver & Energy Meter peripheral decoding (SM2135, SM2235/SM2135EJ,
# BP5758D, BP1658CJ, WS2812 SPI, PWM lights, BL0942 UART, BL0937 Pulse).
# ---------------------------------------------------------------------------

LED_OFF_HEX = "#181C22"

# Tuya user_param_key dmod values observed across TuyaOS/Tuya SDK dumps.
TUYA_DMOD_NAMES = {
    "0": "PWM",
    "1": "SM16726B",
    "2": "SM2135",
    "3": "SM2135EH",
    "4": "SM2135EJ",
    "5": "BP1658CJ",
    "6": "BP5758D",
    "7": "SM2235",
}


def rgbcw_to_hex(r=0.0, g=0.0, b=0.0, c=0.0, w=0.0):
    """Blend normalized (0.0..1.0) R, G, B, Cool-White, Warm-White into (#RRGGBB, is_lit).

    Warm White (~2700K) contributes a warm golden-amber tint; Cool White
    (~6500K) contributes a crisp daylight tint.  A gentle perceptual curve
    keeps low-duty dimming visible on a UI swatch without clipping full scale.
    """
    r = max(0.0, min(1.0, float(r)))
    g = max(0.0, min(1.0, float(g)))
    b = max(0.0, min(1.0, float(b)))
    c = max(0.0, min(1.0, float(c)))
    w = max(0.0, min(1.0, float(w)))
    level = max(r, g, b, c, w)
    if level <= 0.001:
        return LED_OFF_HEX, False

    # Additive contribution from RGB + Cool White (6500K) + Warm White (2700K)
    lin_r = r + 0.90 * c + 1.00 * w
    lin_g = g + 0.96 * c + 0.78 * w
    lin_b = b + 1.00 * c + 0.42 * w
    peak = max(lin_r, lin_g, lin_b, 1.0)
    lin_r /= peak
    lin_g /= peak
    lin_b /= peak

    # Brightness envelope so 10% dimming is still clearly visible on screen
    bright = 0.25 + 0.75 * (level ** 0.65)
    out_r = int(round(max(0.0, min(1.0, lin_r * bright)) * 255))
    out_g = int(round(max(0.0, min(1.0, lin_g * bright)) * 255))
    out_b = int(round(max(0.0, min(1.0, lin_b * bright)) * 255))
    return "#%02X%02X%02X" % (out_r, out_g, out_b), True


def decode_i2c_led(scl, sda, raw_bytes, channel_map=None):
    """Decode a bit-banged two-wire LED driver frame (SM2135, SM2235, BP5758D, BP1658CJ).

    Returns a dict with driver name, raw channel values, mapped R/G/B/C/W
    fractions, and blended ``hex`` color, or ``None`` when ``raw_bytes`` does
    not match any known LED driver frame format.
    """
    b = bytes(raw_bytes or b"")
    if len(b) < 2:
        return None
    b0 = b[0]
    driver = None
    max_val = 1023
    cur_info = ""
    outs = [0, 0, 0, 0, 0]

    # 1. BP5758D: command byte 10_xx_xxxx (0x80 sleep, 0x90/0xB0 active)
    if (b0 & 0xC0) == 0x80 and (len(b) == 17 or b0 == 0x80):
        driver = "BP5758D"
        max_val = 1023
        if b0 == 0x80 or len(b) < 17:
            cur_info = "sleep"
        else:
            en = b[1] & 0x1F
            curs = []
            for c_byte in b[2:7]:
                # Bit 6 selects the upper current range (+30 mA above 0x40-0x1E)
                ma = (c_byte & 0x3F) + 30 if (c_byte & 0x40) else (c_byte & 0x3F)
                curs.append(ma)
            cur_info = "%s mA" % "/".join(str(x) for x in curs)
            for i in range(5):
                if en & (1 << i):
                    lo = b[7 + 2 * i] & 0x1F
                    hi = b[8 + 2 * i] & 0x1F
                    outs[i] = lo | (hi << 5)
    # 2. SM2235 / SM2135EJ / SM2335: command byte 0xD0..0xEF, 12 bytes total from reg 0
    elif (b0 & 0xF0) in (0xD0, 0xE0) and (b0 & 0x07) == 0 and len(b) == 12:
        driver = "SM2235"
        max_val = 1023
        cur_info = "I=0x%02X" % b[1]
        for i in range(5):
            outs[i] = ((b[2 + 2 * i] & 0x03) << 8) | b[3 + 2 * i]
    # 3. BP1658CJ: command byte 0xB0..0xBF (or 0x80 sleep), 12 bytes total from reg 0
    elif (b0 & 0xF0) == 0xB0 and (b0 & 0x07) == 0 and len(b) == 12:
        driver = "BP1658CJ"
        max_val = 1023
        cur_info = "I=0x%02X" % b[1]
        for i in range(5):
            lo = b[2 + 2 * i] & 0x1F
            hi = b[3 + 2 * i] & 0x1F
            outs[i] = lo | (hi << 5)
    # 4. SM2135 / SM2135E: command byte 0xC0..0xC7, 8-bit channels at regs 2..6
    elif (b0 & 0xF8) == 0xC0 and 3 <= len(b) <= 8:
        driver = "SM2135"
        max_val = 255
        start_reg = b0 & 0x07
        regs = {}
        for idx, val in enumerate(b[1:]):
            regs[start_reg + idx] = val
        if 0 in regs:
            cur_info = "I=0x%02X" % regs[0]
        for i in range(5):
            outs[i] = regs.get(2 + i, 0)
    else:
        return None

    # Default channel ordering when no Tuya iicr..iicw mapping is supplied:
    # BP5758D RGBCCT bulbs typically wire OUT1..5 as R, G, B, C, W;
    # SM2235/SM2135 Tuya bulbs frequently wire OUT0..4 as R, G, B, W, C or R, G, B, C, W.
    cmap = channel_map or {"r": 0, "g": 1, "b": 2, "c": 3, "w": 4}
    def ch_frac(name):
        idx = cmap.get(name)
        if idx is None or not (0 <= idx < 5):
            return 0.0
        return min(1.0, max(0.0, outs[idx] / float(max_val)))

    r, g, bl, c, w = ch_frac("r"), ch_frac("g"), ch_frac("b"), ch_frac("c"), ch_frac("w")
    hex_color, is_lit = rgbcw_to_hex(r, g, bl, c, w)
    return {
        "driver": driver,
        "scl": scl,
        "sda": sda,
        "raw_channels": outs,
        "max_val": max_val,
        "cur_info": cur_info,
        "r": r, "g": g, "b": bl, "c": c, "w": w,
        "hex": hex_color,
        "is_lit": is_lit,
        "raw_hex": b.hex(" "),
    }


def decode_ws2812_spi(buf):
    """Decode SPI-DMA WS2812 bitstream (1 SPI byte per WS2812 bit, GRB order).

    Returns a list of ``(r, g, b)`` tuples (0..255).
    """
    data = bytes(buf or b"")
    if len(data) < 24:
        return []
    n_leds = len(data) // 24
    pixels = []
    for i in range(n_leds):
        chunk = data[i * 24:(i + 1) * 24]
        val = 0
        for byte in chunk:
            bit = 1 if bin(byte).count("1") >= 4 else 0
            val = (val << 1) | bit
        g = (val >> 16) & 0xFF
        r = (val >> 8) & 0xFF
        bl = val & 0xFF
        pixels.append((r, g, bl))
    return pixels


def _tuya_pairs_dict(tuya_config):
    if not tuya_config:
        return {}
    return dict((str(k), str(v)) for k, v in (tuya_config.get("pairs") or []))


def tuya_i2c_channel_map(tuya_config):
    """Extract {r,g,b,c,w -> 0..4} from Tuya user_param_key iicr/g/b/c/w."""
    pairs = _tuya_pairs_dict(tuya_config)
    cmap = {}
    for ch in ("r", "g", "b", "c", "w"):
        val = pairs.get("iic" + ch)
        if val is not None:
            try:
                cmap[ch] = int(val, 0)
            except ValueError:
                pass
    return cmap if len(cmap) >= 3 else None


def describe_peripherals(tuya_config=None, decoded_state=None, i2c_frames=None,
                         i2c_last_on=None, ws2812_spi=None, bl0942_polls=0,
                         meter_values=None):
    """Synthesize LED driver and Energy Meter state from Tuya config + live hardware.

    Returns ``{"led": dict | None, "meter": dict | None}``.
    """
    pairs = _tuya_pairs_dict(tuya_config)
    cmap = tuya_i2c_channel_map(tuya_config)
    i2c_frames = dict(i2c_frames or {})
    i2c_last_on = dict(i2c_last_on or {})

    # --- 1. LED Driver detection & live color ---
    led = None
    # Check live I2C LED frames first
    best_i2c = None
    best_on = None
    for (scl, sda), raw in sorted(i2c_frames.items()):
        dec = decode_i2c_led(scl, sda, raw, cmap)
        if dec is not None:
            best_i2c = dec
            on_raw = i2c_last_on.get((scl, sda))
            if on_raw:
                best_on = decode_i2c_led(scl, sda, on_raw, cmap)
            break

    ws_pixels = decode_ws2812_spi(ws2812_spi)
    pwm_chans = (decoded_state or {}).get("pwm_channels") or []
    pwm_by_ch = {ch: pct for ch, _per, _duty, _freq, pct in pwm_chans if pct is not None}

    # Map PWM pins from Tuya config (r_pin, g_pin, b_pin, c_pin, w_pin)
    pwm_pin_map = {}
    for ch_name in ("r", "g", "b", "c", "w"):
        p_str = pairs.get("%s_pin" % ch_name)
        if p_str is not None:
            try:
                p_num = int(p_str, 0)
                if p_num in PWM_PINS:
                    pwm_pin_map[ch_name] = PWM_PINS[p_num]
            except ValueError:
                pass

    if best_i2c is not None:
        # If the bulb is blinking in pairing mode and currently on an OFF frame,
        # keep the last-lit color accessible and note that it is blinking.
        active = best_i2c
        blinking_off = (not best_i2c["is_lit"]) and (best_on is not None and best_on["is_lit"])
        shown = best_on if blinking_off else best_i2c
        dmod_name = TUYA_DMOD_NAMES.get(pairs.get("dmod", ""), shown["driver"])
        if dmod_name in ("SM2235", "SM2135EJ", "SM2135EH") and shown["driver"] == "SM2235":
            drv_label = dmod_name
        else:
            drv_label = shown["driver"]
        cur_part = (", %s" % shown["cur_info"]) if shown["cur_info"] else ""
        pcts = "R:%.0f%% G:%.0f%% B:%.0f%% C:%.0f%% W:%.0f%%" % (
            shown["r"] * 100, shown["g"] * 100, shown["b"] * 100,
            shown["c"] * 100, shown["w"] * 100)
        if blinking_off:
            pcts += " (blink paused/off)"
        led = {
            "kind": drv_label,
            "summary": "%s (SCL=P%d SDA=P%d%s)  %s  %s" % (
                drv_label, shown["scl"], shown["sda"], cur_part, pcts, shown["hex"]),
            "hex": shown["hex"],
            "live_hex": active["hex"],
            "is_lit": shown["is_lit"],
            "pixels": [shown["hex"]],
        }
    elif ws_pixels:
        # Addressable RGB strip (WS2812 over SPI DMA), optionally with PWM CW channels
        hex_pixels = []
        r_avg = sum(p[0] for p in ws_pixels) / (255.0 * len(ws_pixels))
        g_avg = sum(p[1] for p in ws_pixels) / (255.0 * len(ws_pixels))
        b_avg = sum(p[2] for p in ws_pixels) / (255.0 * len(ws_pixels))
        for pr, pg, pb in ws_pixels:
            hx, _ = rgbcw_to_hex(pr / 255.0, pg / 255.0, pb / 255.0)
            hex_pixels.append(hx)
        c_val = pwm_by_ch.get(pwm_pin_map.get("c", -1), 0.0) / 100.0
        w_val = pwm_by_ch.get(pwm_pin_map.get("w", -1), 0.0) / 100.0
        hex_color, is_lit = rgbcw_to_hex(r_avg, g_avg, b_avg, c_val, w_val)
        mosi = pairs.get("mosi", "16")
        extra_pwm = ""
        if "c" in pwm_pin_map or "w" in pwm_pin_map:
            extra_pwm = " + PWM C:%.0f%% W:%.0f%%" % (c_val * 100, w_val * 100)
        led = {
            "kind": "WS2812 SPI",
            "summary": "WS2812 SPI (MOSI=P%s, %d LEDs)%s  R:%.0f%% G:%.0f%% B:%.0f%%  %s" % (
                mosi, len(ws_pixels), extra_pwm, r_avg * 100, g_avg * 100, b_avg * 100, hex_color),
            "hex": hex_color,
            "live_hex": hex_color,
            "is_lit": is_lit,
            "pixels": hex_pixels,
        }
    elif "iicscl" in pairs and "iicsda" in pairs:
        drv_label = TUYA_DMOD_NAMES.get(pairs.get("dmod", ""), "I2C LED")
        scl_s, sda_s = pairs.get("iicscl", "?"), pairs.get("iicsda", "?")
        cur_notes = []
        for k in ("2135ccur", "2135wcur", "2235ccur", "2235wcur", "5758ccur", "5758wcur", "rgbcur", "wcur"):
            if k in pairs:
                cur_notes.append("%s=%s" % (k, pairs[k]))
        cur_str = (", " + " ".join(cur_notes)) if cur_notes else ""
        led = {
            "kind": drv_label,
            "summary": "%s (SCL=P%s SDA=P%s%s) — waiting for I2C frames" % (
                drv_label, scl_s, sda_s, cur_str),
            "hex": LED_OFF_HEX,
            "live_hex": LED_OFF_HEX,
            "is_lit": False,
            "pixels": [LED_OFF_HEX],
        }
    elif "mosi" in pairs or "LedNum" in pairs:
        mosi = pairs.get("mosi", "16")
        led_num = pairs.get("LedNum", "?")
        c_val = pwm_by_ch.get(pwm_pin_map.get("c", -1), 0.0) / 100.0
        w_val = pwm_by_ch.get(pwm_pin_map.get("w", -1), 0.0) / 100.0
        hex_color, is_lit = rgbcw_to_hex(0.0, 0.0, 0.0, c_val, w_val)
        cw_note = ("  PWM C:%.0f%% W:%.0f%%  %s" % (c_val * 100, w_val * 100, hex_color)
                   if (c_val > 0 or w_val > 0) else " — waiting for SPI/PWM output")
        led = {
            "kind": "WS2812 SPI",
            "summary": "WS2812 SPI (MOSI=P%s, %s LEDs)%s" % (mosi, led_num, cw_note),
            "hex": hex_color,
            "live_hex": hex_color,
            "is_lit": is_lit,
            "pixels": [hex_color],
        }
    elif pwm_pin_map or pwm_chans:
        # Pure PWM light (either with Tuya r/g/b/c/w_pin mapping or generic PWM channels)
        if pwm_pin_map:
            r = pwm_by_ch.get(pwm_pin_map.get("r", -1), 0.0) / 100.0
            g = pwm_by_ch.get(pwm_pin_map.get("g", -1), 0.0) / 100.0
            bl = pwm_by_ch.get(pwm_pin_map.get("b", -1), 0.0) / 100.0
            c = pwm_by_ch.get(pwm_pin_map.get("c", -1), 0.0) / 100.0
            w = pwm_by_ch.get(pwm_pin_map.get("w", -1), 0.0) / 100.0
            pin_desc = " ".join("%s=P%s" % (k.upper(), pairs["%s_pin" % k])
                                for k in ("r", "g", "b", "c", "w") if "%s_pin" % k in pairs)
            hex_color, is_lit = rgbcw_to_hex(r, g, bl, c, w)
            led = {
                "kind": "PWM Light",
                "summary": "PWM Light (%s)  R:%.0f%% G:%.0f%% B:%.0f%% C:%.0f%% W:%.0f%%  %s" % (
                    pin_desc, r * 100, g * 100, bl * 100, c * 100, w * 100, hex_color),
                "hex": hex_color,
                "live_hex": hex_color,
                "is_lit": is_lit,
                "pixels": [hex_color],
            }
        elif pwm_chans:
            # Generic PWM channels (e.g. OpenBeken or non-Tuya PWM bulb): map ch0..4 -> R,G,B,C,W
            # or single channel -> Warm White
            if len(pwm_chans) == 1:
                r = g = bl = c = 0.0
                w = (pwm_chans[0][4] or 0.0) / 100.0
            elif len(pwm_chans) == 2:
                r = g = bl = 0.0
                c = (pwm_chans[0][4] or 0.0) / 100.0
                w = (pwm_chans[1][4] or 0.0) / 100.0
            else:
                r = pwm_by_ch.get(0, 0.0) / 100.0
                g = pwm_by_ch.get(1, 0.0) / 100.0
                bl = pwm_by_ch.get(2, 0.0) / 100.0
                c = pwm_by_ch.get(3, 0.0) / 100.0
                w = pwm_by_ch.get(4, 0.0) / 100.0
            hex_color, is_lit = rgbcw_to_hex(r, g, bl, c, w)
            ch_str = " ".join("ch%d:%.0f%%" % (ch[0], ch[4] or 0.0) for ch in pwm_chans)
            led = {
                "kind": "PWM Output",
                "summary": "PWM Output (%s)  %s" % (ch_str, hex_color),
                "hex": hex_color,
                "live_hex": hex_color,
                "is_lit": is_lit,
                "pixels": [hex_color],
            }

    # --- 2. Energy Meter detection (BL0942 UART / BL0937 Pulse) ---
    meter = None
    v_val, a_val, w_val = meter_values if meter_values else (230.0, 1.5, 345.0)
    if bl0942_polls > 0:
        meter = {
            "kind": "BL0942 (UART1)",
            "summary": "BL0942 UART1 (%d polls) — %.1fV  %.2fA  %.1fW" % (
                bl0942_polls, v_val, a_val, w_val),
            "cf_pin": None,
            "cf1_pin": None,
            "sel_pin": None,
            "sel_lv": 1,
        }
    elif "ele_pin" in pairs or "vi_pin" in pairs:
        def _pin_int(key):
            try:
                return int(pairs[key], 0)
            except (KeyError, ValueError):
                return None
        cf_pin = _pin_int("ele_pin")
        cf1_pin = _pin_int("vi_pin")
        sel_pin = _pin_int("sel_pin_pin")
        sel_lv = _pin_int("sel_pin_lv")
        meter = {
            "kind": "BL0937 (Pulse)",
            "summary": "BL0937 Pulse (CF=P%s CF1=P%s SEL=P%s) — %.1fV  %.2fA  %.1fW" % (
                pairs.get("ele_pin", "?"), pairs.get("vi_pin", "?"),
                pairs.get("sel_pin_pin", "?"), v_val, a_val, w_val),
            "cf_pin": cf_pin,
            "cf1_pin": cf1_pin,
            "sel_pin": sel_pin,
            "sel_lv": 1 if sel_lv is None else sel_lv,
        }

    return {"led": led, "meter": meter}


# Same captured offsets mean different peripherals per chip: 0x100+ is pwm_new
# on the N family but AUDIO on 7252, so the chip selects the decoder. This
# lives here rather than in the caller because it is a decoding decision, and
# there are now two callers - the self-test report and the GUI, which reads the
# emulator's live register dicts instead of captured [EMU_*] lines.
PWM_NEW_CHIPS = {"BK7231N", "BK7231M", "BL2028N", "BK7238"}


def decode_state(gpio, pwm, chip="", i2c_frames=None, i2c_last_on=None,
                 ws2812_spi=None, tuya_config=None, bl0942_polls=0,
                 meter_values=None):
    """Decode raw {pin: value} / {offset: value} register maps.

    Returns the dict the report and the GUI both render, or None when the
    firmware has not touched any peripheral yet.
    """
    if not gpio and not pwm and not i2c_frames and not ws2812_spi and not bl0942_polls:
        return None
    if chip in PWM_NEW_CHIPS and any(off >= 0x100 for off in pwm):
        channels = pwm_new_channels(pwm)
        ctl, base, layout = 0, None, "new"
    else:
        channels, ctl, base = pwm_channels(pwm)
        layout = "old"
    logical_gpio = gpio_pin_values(gpio, chip)
    pin_count = BK7252_PIN_COUNT if chip in ("BK7231U", "BK7252") else PIN_COUNT
    out = {"gpio": gpio_table(logical_gpio, pin_count),
           "pwm_layout": layout,
           # Logical pin keys are what GUI actions and report assertions need;
           # controller/function registers remain available through ``func``.
           "raw": logical_gpio,
           "pwm_pins": pwm_output_pins(gpio),
           "func": func_rows(gpio),
           "pwm_ctl": ctl,
           "pwm_base": base,
           "pwm_channels": channels,
           "pwm_regs": pwm_registers(pwm)}
    periphs = describe_peripherals(
        tuya_config=tuya_config, decoded_state=out,
        i2c_frames=i2c_frames, i2c_last_on=i2c_last_on,
        ws2812_spi=ws2812_spi, bl0942_polls=bl0942_polls,
        meter_values=meter_values)
    out["led"] = periphs["led"]
    out["meter"] = periphs["meter"]
    return out


# Silicon name implied by a dump's filename. Report chip names (BK7231N,
# BK7231T, ...) are finer-grained than the four -chip CLI identities, and
# decode_state above needs the fine-grained one, so this lives beside it and
# is shared by the self-test harness and the GUI.
CHIP_RE = re.compile(r"(BL2028N|BK7252N|BK7231[TUNMQ]|BK7238|BK7252|BK7236|BK7258|BK3231)", re.I)


def chip_from_name(filename):
    """Chip a dump's filename names, or "" when it says nothing."""
    m = CHIP_RE.search(os.path.basename(filename or ""))
    return m.group(1).upper() if m else ""

