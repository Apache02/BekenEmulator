"""Inject an OpenBeken config (with a startup command) into a BK7231 flash image.

OBK keeps its config in the BK_PARTITION_NET_PARAM partition at flash 0x1e1000,
as a 3584-byte mainConfig_t:

    offset 0..2   ident 'C','F','G'
    offset 3      crc      - Tiny_CRC8 over config[4:3584]
    offset 4      version  - int, MAIN_CFG_VERSION (5)
    offset 0x5E0  initCommandLine[1568] - the startup command

CRC note: OBK's Tiny_CRC8 (src/tiny_crc8.c) is written with plain `char`, and
this firmware is built with *signed* char, so `crc >>= 1` is an arithmetic
shift. Computing it as unsigned yields a different byte and the config is
rejected with "Config crc or ident mismatch", so the signed form is required.

Flash images carry a CRC stripe every 32 bytes (32 data + 2 big-endian CRC16).
Only the blocks actually touched are patched and re-stripped, so the rest of the
image stays byte-identical to the input. App-only images are shorter than the
config partition, so the image is first extended with erased (0xFF) blocks.
"""
import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.crypto import block_crc_check, crc16, detect_stripe_offset

# BK_PARTITION_NET_PARAM start, as a PHYSICAL offset into the dump - which is
# what the firmware asks the flash controller for. Confirmed against a real
# OpenBeken BK7231N dump: its config (valid CRC, real SSID) sits at physical
# 0x1D1000, the exact address in that SDK's partition table, and NOT at the
# 0x1EE000 a CRC-stripped/logical mapping would imply. The address differs per
# chip family, so pick by image or pass --addr.
CONFIG_ADDR = 0x1E1000          # BK7231T/U family
CONFIG_ADDR_N = 0x1D1000        # BK7231N/M family
CONFIG_SIZE = 3584              # MAGIC_CONFIG_SIZE_V4 == sizeof(mainConfig_t)
CFG_VERSION = 5                 # MAIN_CFG_VERSION
CMDLINE_OFF = 0x5E0             # offsetof(mainConfig_t, initCommandLine)
# mainConfig_t stores the 64 OBK feature flags as two uint32s: genericFlags
# (flags 0..31) at offset 0x08 and genericFlags2 (flags 32..63) at 0x0C. Both
# sit inside the CRC-covered range [4:3584], so the crc is recomputed after
# setting any. Flag 31 (OBK_FLAG_CMD_ACCEPT_UART_COMMANDS) turns UART1 into a
# command console at boot - the console is brought up in CMD_Init_Delayed,
# which reads the flag straight from the persisted config, so it must be set
# HERE rather than by a startup command (that runs too late for this boot).
FLAGS_OFF = 0x08
# Station credentials: wifi_ssid[64] follows the two counters at 0x10, and
# wifi_pass[64] follows it (new_pins.h mainConfig_t). An empty password means
# an open network; OBK then joins as a station instead of raising its own AP.
SSID_OFF = 0x14
PASS_OFF = 0x54
CRED_MAX = 64
# MQTT broker (mainConfig_t: mqtt_host[256] at 0x94, mqtt_port int at 0x294).
MQTT_HOST_OFF = 0x94
MQTT_HOST_MAX = 256
MQTT_PORT_OFF = 0x294
MQTT_CLIENT_OFF = 0x194           # mqtt_clientId[64]; OBK builds its topics from it
MQTT_CLIENT_MAX = 64
CMDLINE_MAX = 1568              # sizeof(initCommandLine)
SECTOR_SIZE = 4096              # flash sector; images grow to a whole sector


def tiny_crc8_signed(data):
    """OBK's Tiny_CRC8 as compiled with signed char (arithmetic >>)."""
    def to_signed(x):
        x &= 0xFF
        return x - 256 if x >= 128 else x

    crc = 0
    for byte in data:
        extract = to_signed(byte)
        for _ in range(8):
            total = (crc ^ extract) & 0x01
            crc >>= 1
            if total:
                crc = to_signed(crc ^ 0x8C)
            extract >>= 1
        crc = to_signed(crc)
    return crc & 0xFF


def build_config(startup_command, flags=(), ssid=None, password=None, mqtt_host=None, mqtt_port=1883,
                 mqtt_client=None):
    """Build a 3584-byte mainConfig_t with the given startup command and flags.

    flags is an iterable of OBK flag bit numbers (0..63) to set. ssid/password
    fill the station credentials; with an SSID set OBK connects as a station
    (password "" = open network) rather than starting its own access point.
    """
    cmd = startup_command.encode("ascii")
    if len(cmd) >= CMDLINE_MAX:
        raise ValueError("startup command too long (max %d bytes)" % (CMDLINE_MAX - 1))
    ssid_b = (ssid or "").encode("utf-8")
    pass_b = (password or "").encode("utf-8")
    if len(ssid_b) >= CRED_MAX or len(pass_b) >= CRED_MAX:
        raise ValueError("SSID/password too long (max %d bytes)" % (CRED_MAX - 1))
    mqtt_b = (mqtt_host or "").encode("utf-8")
    client_b = (mqtt_client or "").encode("utf-8")
    if len(client_b) >= MQTT_CLIENT_MAX:
        raise ValueError("MQTT client id too long (max %d bytes)" % (MQTT_CLIENT_MAX - 1))
    if len(mqtt_b) >= MQTT_HOST_MAX:
        raise ValueError("MQTT host too long (max %d bytes)" % (MQTT_HOST_MAX - 1))

    generic0 = generic1 = 0
    for f in flags:
        if not 0 <= f <= 63:
            raise ValueError("flag out of range 0..63: %d" % f)
        if f < 32:
            generic0 |= 1 << f
        else:
            generic1 |= 1 << (f - 32)

    cfg = bytearray(CONFIG_SIZE)
    cfg[0:3] = b"CFG"
    cfg[4:8] = struct.pack("<i", CFG_VERSION)
    cfg[FLAGS_OFF:FLAGS_OFF + 8] = struct.pack("<II", generic0, generic1)
    cfg[SSID_OFF:SSID_OFF + len(ssid_b)] = ssid_b
    cfg[PASS_OFF:PASS_OFF + len(pass_b)] = pass_b
    if mqtt_b:
        cfg[MQTT_HOST_OFF:MQTT_HOST_OFF + len(mqtt_b)] = mqtt_b
        cfg[MQTT_PORT_OFF:MQTT_PORT_OFF + 4] = struct.pack("<i", mqtt_port)
    if client_b:
        cfg[MQTT_CLIENT_OFF:MQTT_CLIENT_OFF + len(client_b)] = client_b
    cfg[CMDLINE_OFF:CMDLINE_OFF + len(cmd)] = cmd
    cfg[3] = tiny_crc8_signed(cfg[4:CONFIG_SIZE])
    return bytes(cfg)



def extend_striped(raw, offset, needed_stripped):
    """Grow a striped image until stripped space covers needed_stripped bytes.

    Added blocks are erased flash (0xFF) with a correct CRC16, and the result is
    rounded up to a whole sector of stripped space.
    """
    have_blocks = (len(raw) - offset) // 34
    if have_blocks * 32 >= needed_stripped:
        return raw          # a full dump already covers the config partition

    want = -(-needed_stripped // SECTOR_SIZE) * SECTOR_SIZE
    want_blocks = -(-want // 32)

    out = bytearray(raw[:offset + have_blocks * 34])

    # An app-only image can end mid-block; keep that data and round it out to a
    # whole block, or the last bytes of the app would be lost.
    leftover = raw[offset + have_blocks * 34:][:32]
    if leftover:
        block = leftover.ljust(32, b"\xff")
        out += block + struct.pack(">H", crc16(block, initial_value=0xFFFF))
        have_blocks += 1

    blank = b"\xff" * 32
    tail = struct.pack(">H", crc16(blank, initial_value=0xFFFF))
    out += (blank + tail) * (want_blocks - have_blocks)
    return bytes(out)


def patch_striped(raw, stripped_addr, payload, offset):
    """Write payload at a *stripped-space* address, fixing each block's CRC16."""
    raw = extend_striped(raw, offset, stripped_addr + len(payload))
    out = bytearray(raw)
    for i, value in enumerate(payload):
        block, within = divmod(stripped_addr + i, 32)
        raw_index = offset + block * 34 + within
        if raw_index >= len(out):
            raise ValueError("config extends past the end of the image")
        out[raw_index] = value

    first_block = stripped_addr // 32
    last_block = (stripped_addr + len(payload) - 1) // 32
    for block in range(first_block, last_block + 1):
        start = offset + block * 34
        crc = crc16(bytes(out[start:start + 32]), initial_value=0xFFFF)
        out[start + 32:start + 34] = struct.pack(">H", crc)
    return bytes(out)


def inject(raw, startup_command, addr=CONFIG_ADDR, flags=(), ssid=None, password=None,
           mqtt_host=None, mqtt_port=1883, mqtt_client=None):
    """Return a copy of raw carrying a valid config at PHYSICAL offset addr.

    No CRC re-striping: the firmware reads this partition through the flash
    controller by physical address, so the config is a plain contiguous blob at
    that offset. The image is padded with erased flash if it is too short (an
    app-only image ends well before the config partition).
    """
    cfg = build_config(startup_command, flags, ssid, password, mqtt_host, mqtt_port, mqtt_client)
    out = bytearray(raw)
    end = addr + CONFIG_SIZE
    if len(out) < end:
        want = -(-end // SECTOR_SIZE) * SECTOR_SIZE      # round up to a sector
        out += b"\xff" * (want - len(out))
    out[addr:end] = cfg
    return bytes(out), addr, cfg


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("input", help="Base BK7231 flash image")
    parser.add_argument("output", help="Image to write with the config injected")
    parser.add_argument("-c", "--command", default="",
                        help="Startup command placed in initCommandLine, e.g. "
                             "\"uartInit 9600; uartSendHex 55AA00000000FF\"")
    parser.add_argument("--ssid", default=None,
                        help="Wi-Fi SSID for OBK to join as a station (wifi_ssid). Without it "
                             "OBK starts its own open access point.")
    parser.add_argument("--mqtt-host", dest="mqtt_host", default=None,
                        help="MQTT broker host OBK connects to once it is on the network.")
    parser.add_argument("--mqtt-client", dest="mqtt_client", default=None,
                        help="MQTT client id (mqtt_clientId). OBK publishes under <client id>/...")
    parser.add_argument("--mqtt-port", dest="mqtt_port", type=int, default=1883,
                        help="MQTT broker port (default 1883).")
    parser.add_argument("--pass", dest="password", default=None,
                        help="Wi-Fi password for --ssid; omit or \"\" for an open network.")
    parser.add_argument("--addr", default=None,
                        help="Physical config address. Default: 0x1E1000, or "
                             "0x1D1000 when the filename looks like a BK7231N/M image.")
    parser.add_argument("--flag", type=int, action="append", default=[],
                        metavar="N", dest="flags",
                        help="Set OBK config flag bit N (0..63). Repeatable. "
                             "E.g. --flag 31 enables the UART1 command console.")
    args = parser.parse_args()

    with open(args.input, "rb") as f:
        raw = f.read()

    if args.addr:
        addr = int(args.addr, 0)
    else:
        name = os.path.basename(args.input).upper()
        addr = CONFIG_ADDR_N if ("7231N" in name or "7231M" in name) else CONFIG_ADDR

    patched, addr, cfg = inject(raw, args.command, addr, args.flags, args.ssid, args.password,
                                args.mqtt_host, args.mqtt_port, args.mqtt_client)

    with open(args.output, "wb") as f:
        f.write(patched)

    print("Wrote %s (%d bytes, was %d)" % (args.output, len(patched), len(raw)))
    print("  config addr   : 0x%06X (physical)" % addr)
    print("  config crc    : 0x%02x" % cfg[3])
    print("  startup cmd   : %s" % args.command)
    if args.flags:
        print("  flags set     : %s" % ", ".join(str(f) for f in args.flags))
    if args.ssid is not None:
        print("  station ssid  : %s (%s)" % (args.ssid, "open" if not args.password else "with password"))
    if args.mqtt_host:
        print("  mqtt broker   : %s:%d" % (args.mqtt_host, args.mqtt_port))
    if args.mqtt_client:
        print("  mqtt client id: %s" % args.mqtt_client)


if __name__ == "__main__":
    main()
