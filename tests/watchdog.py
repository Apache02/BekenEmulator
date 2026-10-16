"""Watchdog register and full-chip reboot regression tests."""

import struct
import sys
import threading
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.emulator import BekenEmulator
from src import netstack


def make_emulator(app=b"", wifi=False):
    # Only enough flash for the application window and SPI mirror is needed.
    emu = BekenEmulator(b"\xff" * 0x20000, None, app,
                        only_uart=True, wifi=wifi)
    emu.setup()
    return emu


def write(emu, address, value):
    emu.hook_mem_write_mmio(emu.mu, 0, address, 4, value, None)


def test_key_sequence_and_clock_gate():
    emu = make_emulator()
    state = emu.state

    # A period programmed while the ICU has gated the watchdog clock is
    # retained, but cannot count until that clock is powered again.
    write(emu, emu.ICU_PERI_CLK_PWD, emu.ICU_WDT_CLK_PWD)
    write(emu, emu.WDT_CTRL, emu.WDT_FIRST_KEY << 16 | 5)
    write(emu, emu.WDT_CTRL, emu.WDT_SECOND_KEY << 16 | 5)
    assert state.wdt_period_ms == 5
    assert state.wdt_deadline is None

    write(emu, emu.ICU_PERI_CLK_PWD, 0)
    assert state.wdt_deadline == 5 * emu.WDT_INSNS_PER_MS

    # A mismatched second key neither changes nor reloads an active watchdog.
    original = state.wdt_deadline
    state.insn_count = 100
    write(emu, emu.WDT_CTRL, emu.WDT_FIRST_KEY << 16 | 9)
    write(emu, emu.WDT_CTRL, emu.WDT_SECOND_KEY << 16 | 8)
    assert state.wdt_period_ms == 5
    assert state.wdt_deadline == original

    # A complete pair is also the SDK's feed/reload operation.
    write(emu, emu.WDT_CTRL, emu.WDT_FIRST_KEY << 16 | 5)
    write(emu, emu.WDT_CTRL, emu.WDT_SECOND_KEY << 16 | 5)
    assert state.wdt_deadline == 100 + 5 * emu.WDT_INSNS_PER_MS


def watchdog_firmware():
    """ARM code matching bk_reboot(): gate, program 5 ms, ungate, spin."""
    words = [
        0xE59F0024,              # ldr r0, [pc, #36]  ; ICU_PERI_CLK_PWD
        0xE59F1024,              # ldr r1, [pc, #36]  ; bit 8
        0xE5801000,              # str r1, [r0]       ; watchdog power down
        0xE59F2020,              # ldr r2, [pc, #32]  ; WDT_CTRL
        0xE59F3020,              # ldr r3, [pc, #32]  ; first key + 5 ms
        0xE5823000,              # str r3, [r2]
        0xE59F301C,              # ldr r3, [pc, #28]  ; second key + 5 ms
        0xE5823000,              # str r3, [r2]
        0xE3A01000,              # mov r1, #0
        0xE5801000,              # str r1, [r0]       ; watchdog power up
        0xEAFFFFFE,              # b .                 ; wait for hardware reset
        0x00802008,
        0x00000100,
        0x00802900,
        0x005A0005,
        0x00A50005,
    ]
    return struct.pack("<%dI" % len(words), *words)


def test_expiry_reboots_and_restarts_firmware():
    emu = make_emulator(watchdog_firmware())
    messages = []

    # An external button remains physically held through a chip reset.
    emu.set_gpio_input(14, 0)

    def logged(message):
        messages.append(message)
        # A second expiry proves that the first one did not merely stop the
        # CPU: the application restarted and programmed the watchdog again.
        if emu.reset_count == 2:
            emu.stop()

    emu.net_sink = logged
    thread = threading.Thread(target=emu.run, daemon=True)
    thread.start()
    thread.join(5.0)
    if thread.is_alive():
        emu.stop()
        thread.join(1.0)
        raise AssertionError("watchdog firmware did not reset within five seconds")

    assert emu.run_error is None
    assert emu.reset_count == 2
    assert sum(line.startswith("[WDT] watchdog expired") for line in messages) == 2
    assert emu.state.gpio_hw.inputs == {14: 0}


def test_network_peer_survives_without_stale_device_sessions():
    emu = make_emulator(watchdog_firmware(), wifi=True)
    peer = emu.attach_wifi_peer(role="ap", ssid="HomeNet", forwards=((0, 80),))
    net = peer.net
    listener = net.listeners[0]
    io_thread = net.io.thread

    # Prime state that belongs to the old boot.  A large external clock makes
    # a rollback obvious: beacon/TCP deadlines must not wait for that old time
    # to be reached again after the on-chip instruction counter restarts.
    emu._network_insn_offset = 50_000_000
    before_us = peer.now_us()
    device_mac = bytes.fromhex("c8478c000001")
    device_ip = netstack.str2ip("192.168.1.100")
    remote_ip = netstack.str2ip("10.200.0.1")
    peer.stations[device_mac] = {"state": "ASSOC", "aid": 1}
    peer.auth[device_mac] = object()
    peer._outq.append((before_us + 1_000_000, b"stale", None))
    net.link = True
    net.link_up_us = before_us - 1_000_000
    net.device_mac = device_mac
    net.device_ip = device_ip
    conn = netstack.TcpConn(net, remote_ip, 443, device_ip, 49152, "relay")
    conn.state = "ESTABLISHED"
    net.conns[(remote_ip, 443, device_ip, 49152)] = conn

    observed = {}

    def logged(_message):
        if emu.reset_count == 1:
            observed.update(
                now_us=peer.now_us(),
                stations=dict(peer.stations),
                auth=dict(peer.auth),
                queued=list(peer._outq),
                conns=dict(net.conns),
                link=net.link,
                listener_alive=listener in net.listeners,
                io_alive=io_thread.is_alive(),
            )
            emu.stop()

    emu.net_sink = logged
    thread = threading.Thread(target=emu.run, daemon=True)
    thread.start()
    thread.join(5.0)
    if thread.is_alive():
        emu.stop()
        thread.join(1.0)
        emu.close_network()
        raise AssertionError("networked watchdog firmware did not reset")

    try:
        assert observed["now_us"] >= before_us
        assert observed["stations"] == {}
        assert observed["auth"] == {}
        assert observed["queued"] == []
        assert observed["conns"] == {}
        assert observed["link"] is False
        assert observed["listener_alive"]
        assert observed["io_alive"]
    finally:
        emu.close_network()


def main():
    test_key_sequence_and_clock_gate()
    test_expiry_reboots_and_restarts_firmware()
    test_network_peer_survives_without_stale_device_sessions()
    print("Watchdog register and reboot self-tests passed.")


if __name__ == "__main__":
    main()
