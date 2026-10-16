"""Real-firmware regression for host-driven GPIO button input.

This deliberately uses stock Tuya wall-switch images rather than a synthetic
guest.  Their own hardware tables identify the active-low buttons and
active-high relays, so a successful press must travel through the emulated
GPIO input, each firmware's key scanner, and its relay-output code.  The
BK7231Q case additionally proves that its channel-3 RTOS timer drives the
polling-based scanner.
"""

import sys
import threading
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.crypto import parse_key
from src.main import build_emulator


T_IMAGE = ROOT / "firmwares" / "BK7231T_Tuya_1G_Switch_WB3S-IPEX_1.0.4.bin"
Q_IMAGE = ROOT / "firmwares" / "BK7231Q_Tuya_MOES_Relay_WA2_1.1.3.bin"
BUTTON_PIN = 7
RELAY_PIN = 6
PRESS_INSNS = 1_000_000       # 200 ms of guest time (5M insns == one second)


def _wait_for(emu, worker, predicate, description, max_insns, max_seconds):
    """Wait on live model state with both guest-time and wall-time bounds."""
    start_insns = emu.state.insn_count
    deadline = time.monotonic() + max_seconds
    while not predicate():
        if not worker.is_alive():
            raise AssertionError("emulator stopped before " + description)
        elapsed_insns = emu.state.insn_count - start_insns
        if elapsed_insns > max_insns:
            raise AssertionError(
                "%s not reached after %d guest instructions" %
                (description, elapsed_insns))
        if time.monotonic() > deadline:
            raise AssertionError(
                "%s not reached within %.1f seconds" %
                (description, max_seconds))
        time.sleep(0.005)


def _wait_guest_time(emu, worker, insns):
    start = emu.state.insn_count
    _wait_for(emu, worker,
              lambda: emu.state.insn_count - start >= insns,
              "%d instructions of pressed guest time" % insns,
              insns + 1_000_000, 10.0)


def test_stock_tuya_button_toggles_relay():
    if not T_IMAGE.is_file():
        raise AssertionError("firmware image is missing: %s" % T_IMAGE)

    ready = threading.Event()
    uart_tail = bytearray()

    def uart_sink(uart, byte):
        if uart != 2:
            return
        uart_tail.append(byte)
        if len(uart_tail) > 256:
            del uart_tail[:-256]
        if b"device_init ok" in uart_tail:
            ready.set()

    emu = build_emulator(
        str(T_IMAGE), key=parse_key("TUYA"), only_uart=True,
        save_decrypted=False, uart_sink=uart_sink)
    emu.setup()
    worker = threading.Thread(target=emu.run, name="gpio-button-firmware")
    worker.start()

    try:
        _wait_for(emu, worker, ready.is_set,
                  "the stock firmware's device_init checkpoint",
                  80_000_000, 45.0)

        # The dump itself reports this map on UART:
        #   IO - relay[0]:  pin-6  type high
        #   IO - button[0]: pin-7  type low
        # Confirm that it reached that real configuration before injecting an
        # input, and establish the relay's pre-press state.
        _wait_for(emu, worker,
                  lambda: (emu.state.gpio_cfg.get(RELAY_PIN) == 0x02
                           and emu.state.gpio_cfg.get(BUTTON_PIN) == 0x3C),
                  "P6 high relay and P7 pull-up button configuration",
                  2_000_000, 5.0)

        emu.set_gpio_input(BUTTON_PIN, 0)
        _wait_for(emu, worker,
                  lambda: emu.state.gpio_hw.inputs.get(BUTTON_PIN) == 0,
                  "the queued active-low press",
                  2_000_000, 5.0)
        _wait_guest_time(emu, worker, PRESS_INSNS)

        # None means physical release, not an artificial drive-high.  Waiting
        # for the model to remove its override also verifies that the pin falls
        # back to the firmware's pull-up before checking the application result.
        emu.set_gpio_input(BUTTON_PIN, None)
        _wait_for(emu, worker,
                  lambda: BUTTON_PIN not in emu.state.gpio_hw.inputs,
                  "button release",
                  2_000_000, 5.0)
        button_cfg = emu.state.gpio_cfg[BUTTON_PIN]
        if emu.state.gpio_hw.effective_level(BUTTON_PIN, button_cfg) != 1:
            raise AssertionError("released P7 did not return to its pull-up level")

        _wait_for(emu, worker,
                  lambda: emu.state.gpio_cfg.get(RELAY_PIN) == 0x00,
                  "stock firmware toggling relay P6 low",
                  8_000_000, 15.0)
    finally:
        emu.stop()
        worker.join(5.0)

    if worker.is_alive():
        raise AssertionError("emulator worker did not stop")


def test_moes_q_button_toggles_relay():
    """Prove the Q SDK's channel-3 RTOS timer services its polled key."""
    if not Q_IMAGE.is_file():
        raise AssertionError("firmware image is missing: %s" % Q_IMAGE)

    ready = threading.Event()
    uart_tail = bytearray()

    def uart_sink(uart, byte):
        if uart != 2:
            return
        uart_tail.append(byte)
        if len(uart_tail) > 512:
            del uart_tail[:-512]
        if b"Initializing TCP/IP stack" in uart_tail:
            ready.set()

    emu = build_emulator(
        str(Q_IMAGE), only_uart=True, save_decrypted=False, uart_sink=uart_sink)
    emu.setup()
    worker = threading.Thread(target=emu.run, name="gpio-button-moes-q")
    worker.start()

    try:
        _wait_for(emu, worker, ready.is_set,
                  "the MOES firmware's TCP/IP checkpoint",
                  60_000_000, 45.0)

        # This SDK puts its FreeRTOS tick on old-PWM channel 3, not channel 0:
        # nibble 3 of PWM_CTL is 0b0111 (enabled, interrupt enabled, timer
        # mode), and PWM3's period is 0x6590.  The button is deliberately
        # polling-driven by a 30 ms Tuya timer, so its relay response is also
        # an end-to-end regression for dispatching the correct PWM status bit.
        _wait_for(emu, worker,
                  lambda: (emu.state.pwm_regs.get(0) == 0x7000
                           and emu.state.pwm_regs.get(0x20) == 0x6590
                           and emu.state.gpio_cfg.get(18) == 0x02
                           and emu.state.gpio_cfg.get(6) == 0x3C),
                  "MOES channel-3 OS timer, P18 relay, and P6 button setup",
                  2_000_000, 5.0)

        emu.set_gpio_input(6, 0)
        _wait_for(emu, worker,
                  lambda: emu.state.gpio_hw.inputs.get(6) == 0,
                  "the MOES active-low press",
                  2_000_000, 5.0)
        _wait_guest_time(emu, worker, PRESS_INSNS)

        emu.set_gpio_input(6, None)
        _wait_for(emu, worker,
                  lambda: 6 not in emu.state.gpio_hw.inputs,
                  "MOES button release",
                  2_000_000, 5.0)
        if emu.state.gpio_hw.effective_level(6, emu.state.gpio_cfg[6]) != 1:
            raise AssertionError("released MOES P6 did not return to its pull-up level")

        _wait_for(emu, worker,
                  lambda: emu.state.gpio_cfg.get(18) == 0x00,
                  "MOES firmware toggling relay P18 low",
                  8_000_000, 15.0)
    finally:
        emu.stop()
        worker.join(5.0)

    if worker.is_alive():
        raise AssertionError("MOES emulator worker did not stop")


def main():
    print("== stock Tuya GPIO button integration ==")
    test_stock_tuya_button_toggles_relay()
    print("  [PASS] active-low P7 press toggles active-high relay P6")
    test_moes_q_button_toggles_relay()
    print("  [PASS] MOES Q active-low P6 press toggles active-high relay P18")
    print("\nGPIO button firmware regression passed.")


if __name__ == "__main__":
    main()
