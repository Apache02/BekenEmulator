"""Beken GPIO input and interrupt register model.

Each GPIO config word carries both firmware-controlled configuration and the
physical input sample.  Bit 0 is the sample; bits 4/5 select the pull used when
nothing external is driving the pad.  A host-side button therefore changes
only the physical level -- it must not rewrite the guest's config register.

The interrupt controller has one two-bit mode per pin:

    0  low level       1  high level
    2  rising edge     3  falling edge

INTSTA is latched and write-one-to-clear.  Level conditions are sampled again
after a clear, so a held button reasserts its interrupt just as the pin does on
silicon.  This class deliberately has no locks: BekenEmulator queues external
changes under a lock and applies them here only from the emulation thread.
That also keeps the model pickleable as part of an emulator snapshot.
"""


INPUT_BIT = 1 << 0
PULL_MODE_BIT = 1 << 4       # 1 = up, 0 = down
PULL_ENABLE_BIT = 1 << 5

INT_LEVEL_LOW = 0
INT_LEVEL_HIGH = 1
INT_EDGE_RISING = 2
INT_EDGE_FALLING = 3


class GpioModel:
    """Physical input levels plus GPIO interrupt enable/mode/status state."""

    def __init__(self, pin_count=32):
        if not isinstance(pin_count, int) or isinstance(pin_count, bool) or pin_count <= 0:
            raise ValueError("GPIO pin count must be a positive integer")
        self.pin_count = pin_count
        self.inputs = {}             # pin -> externally driven 0/1; absent = released
        self.int_enable = 0
        self.int_status = 0
        self.int_modes = [INT_LEVEL_LOW] * pin_count

    @property
    def pin_mask(self):
        return (1 << self.pin_count) - 1

    def check_pin(self, pin):
        if (not isinstance(pin, int) or isinstance(pin, bool)
                or not 0 <= pin < self.pin_count):
            raise ValueError("GPIO pin must be in the range 0-%d" % (self.pin_count - 1))
        return pin

    @staticmethod
    def check_level(level):
        if level is None:
            return None
        if isinstance(level, bool):
            return int(level)
        if not isinstance(level, int) or level not in (0, 1):
            raise ValueError("GPIO input level must be 0, 1, or None (released)")
        return level

    def effective_level(self, pin, config):
        """Return the sampled level for one config word.

        An external drive wins over the on-chip pull.  A released pad with an
        enabled pull follows that pull.  With no pull, retain config bit 0; this
        is the only deterministic representation available for a floating pad.
        """
        self.check_pin(pin)
        forced = self.inputs.get(pin)
        if forced is not None:
            return forced
        if config & PULL_ENABLE_BIT:
            return 1 if config & PULL_MODE_BIT else 0
        return 1 if config & INPUT_BIT else 0

    def read_config(self, pin, config):
        """Return a config word with its read-only input sample updated."""
        level = self.effective_level(pin, config)
        return (config & ~INPUT_BIT) | level

    def _mode_matches_transition(self, pin, before, after):
        mode = self.int_modes[pin]
        return ((mode == INT_EDGE_RISING and before == 0 and after == 1)
                or (mode == INT_EDGE_FALLING and before == 1 and after == 0))

    def _mode_matches_level(self, pin, level):
        mode = self.int_modes[pin]
        return ((mode == INT_LEVEL_LOW and level == 0)
                or (mode == INT_LEVEL_HIGH and level == 1))

    def _latch_change(self, pin, before, after):
        bit = 1 << pin
        if not (self.int_enable & bit):
            return
        if (self._mode_matches_transition(pin, before, after)
                or self._mode_matches_level(pin, after)):
            self.int_status |= bit

    def drive(self, pin, level, config):
        """Apply an external 0/1, or release with ``None``.

        Returns ``(before, after)`` to make host/UI diagnostics straightforward.
        """
        pin = self.check_pin(pin)
        level = self.check_level(level)
        before = self.effective_level(pin, config)
        if level is None:
            self.inputs.pop(pin, None)
        else:
            self.inputs[pin] = level
        after = self.effective_level(pin, config)
        self._latch_change(pin, before, after)
        return before, after

    def config_changed(self, pin, old_config, new_config):
        """Observe a firmware config write which may change the pulled level."""
        pin = self.check_pin(pin)
        before = self.effective_level(pin, old_config)
        after = self.effective_level(pin, new_config)
        self._latch_change(pin, before, after)

    def write_enable(self, value):
        self.int_enable = value & self.pin_mask
        self.int_status &= self.pin_mask

    def write_mode_word(self, first_pin, value, count=16):
        """Program one INTLV register (two bits per pin)."""
        if (not isinstance(first_pin, int) or first_pin < 0
                or first_pin >= self.pin_count):
            raise ValueError("bad first GPIO pin for interrupt mode register")
        count = min(count, self.pin_count - first_pin)
        for i in range(count):
            self.int_modes[first_pin + i] = (value >> (2 * i)) & 0x3

    def read_mode_word(self, first_pin, count=16):
        if (not isinstance(first_pin, int) or first_pin < 0
                or first_pin >= self.pin_count):
            raise ValueError("bad first GPIO pin for interrupt mode register")
        count = min(count, self.pin_count - first_pin)
        value = 0
        for i in range(count):
            value |= (self.int_modes[first_pin + i] & 0x3) << (2 * i)
        return value

    def clear_status(self, value):
        """INTSTA write-one-to-clear; level sources may reassert on refresh."""
        self.int_status &= ~(value & self.pin_mask)

    def refresh_level_interrupts(self, config_for_pin):
        """Resample enabled level-mode pins after W1C or configuration changes."""
        enabled = self.int_enable
        if not enabled:
            return
        # The common firmware case has zero or one GPIO interrupt enabled.
        # Walk only set bits rather than scanning every one of the 32/40 pads
        # at every emulator pacing boundary.
        while enabled:
            bit = enabled & -enabled
            enabled ^= bit
            pin = bit.bit_length() - 1
            mode = self.int_modes[pin]
            if mode not in (INT_LEVEL_LOW, INT_LEVEL_HIGH):
                continue
            if self._mode_matches_level(pin, self.effective_level(pin, config_for_pin(pin))):
                self.int_status |= bit

    def irq_asserted(self):
        return bool(self.int_status & self.int_enable)


def _run_selftests():
    checks = 0

    def check(condition, message):
        nonlocal checks
        assert condition, "FAIL: " + message
        checks += 1
        print("  [PASS]", message)

    print("== external drive and pull fallback ==")
    gpio = GpioModel()
    pull_up, pull_down = 0x3C, 0x2C
    check(gpio.read_config(9, pull_up) & 1, "a released pull-up input reads high")
    gpio.drive(9, 0, pull_up)
    check((gpio.read_config(9, pull_up) & 1) == 0,
          "an external low wins over the pull-up")
    gpio.drive(9, None, pull_up)
    check(gpio.read_config(9, pull_up) & 1,
          "releasing the external drive falls back to the pull-up")
    gpio.drive(10, 1, pull_down)
    check(gpio.read_config(10, pull_down) & 1,
          "an external high wins over a pull-down")
    gpio.drive(10, None, pull_down)
    check((gpio.read_config(10, pull_down) & 1) == 0,
          "release falls back to the pull-down as well")
    check(gpio.read_config(9, pull_up | 0xA00) == (pull_up | 0xA01),
          "sampling changes only input bit 0")

    print("== interrupt mode registers and INTEN gate ==")
    gpio = GpioModel()
    # P3 falling, P4 rising; packed exactly as INTLV0 stores them.
    modes = (INT_EDGE_FALLING << (2 * 3)) | (INT_EDGE_RISING << (2 * 4))
    gpio.write_mode_word(0, modes)
    check(gpio.read_mode_word(0) == modes,
          "INTLV packs one two-bit mode per pin")
    gpio.drive(3, 0, pull_up)
    check(gpio.int_status == 0, "a disabled edge does not latch INTSTA")
    gpio.drive(3, None, pull_up)
    gpio.write_enable((1 << 3) | (1 << 4))
    gpio.drive(3, 0, pull_up)
    check(gpio.int_status == (1 << 3) and gpio.irq_asserted(),
          "an enabled falling edge latches its pin and asserts GPIO IRQ")
    gpio.clear_status(1 << 3)
    gpio.refresh_level_interrupts(lambda pin: pull_up if pin == 3 else pull_down)
    check(gpio.int_status == 0,
          "a held edge input does not reassert after W1C")
    gpio.drive(4, 1, pull_down)
    check(gpio.int_status == (1 << 4), "rising mode latches only the rising edge")

    print("== low/high level interrupts and W1C ==")
    gpio = GpioModel()
    gpio.write_mode_word(0, INT_LEVEL_LOW << (2 * 6))
    gpio.write_enable(1 << 6)
    gpio.refresh_level_interrupts(lambda _pin: pull_up)
    check(gpio.int_status == 0, "low-level mode stays quiet while its pin is high")
    gpio.drive(6, 0, pull_up)
    check(gpio.int_status == (1 << 6), "low-level mode asserts when the pin is low")
    gpio.clear_status(1 << 6)
    check(gpio.int_status == 0, "INTSTA clears only the bits written as one")
    gpio.refresh_level_interrupts(lambda _pin: pull_up)
    check(gpio.int_status == (1 << 6),
          "a held level condition reasserts after status is cleared")
    gpio.drive(6, None, pull_up)
    gpio.clear_status(1 << 6)
    gpio.refresh_level_interrupts(lambda _pin: pull_up)
    check(gpio.int_status == 0, "release removes the low-level condition")

    gpio = GpioModel()
    gpio.write_mode_word(0, INT_LEVEL_HIGH << (2 * 7))
    gpio.write_enable(1 << 7)
    gpio.refresh_level_interrupts(lambda _pin: pull_up)
    check(gpio.int_status == (1 << 7),
          "high-level mode asserts immediately when enabled on a high pin")

    print("== validation and extended bank ==")
    try:
        gpio.drive(32, 0, pull_up)
    except ValueError:
        check(True, "a 32-pin model rejects an interrupt-register index as a pin")
    else:
        check(False, "a 32-pin model rejects an interrupt-register index as a pin")
    extended = GpioModel(40)
    extended.write_mode_word(32, INT_EDGE_RISING << (2 * 7), count=8)
    extended.write_enable(1 << 39)
    extended.drive(39, 1, pull_down)
    check(extended.int_status == (1 << 39),
          "the BK7231U/BK7252 upper GPIO bank keeps logical pins 32-39 separate")

    print("\nAll %d GPIO model self-tests passed." % checks)
    return checks


if __name__ == "__main__":
    _run_selftests()
