"""RivieraWaves nxmac Wi-Fi MAC hardware model (the block Beken maps at 0xC0000000).

Why this exists: every Beken Wi-Fi image here - OpenBeken, stock Tuya 1.x/2.x/3.x,
TuyaOS - runs the same RivieraWaves LMAC/UMAC on the same MAC hardware. With the
block served as plain memory the whole stack still comes up (OBK configures its
soft-AP, DHCP server and HTTP server), but nothing can ever move: the 1 MHz
monotonic counter the LMAC keeps time with reads 0 forever, TX descriptors are
never completed, RX descriptors are never filled, and the ABS timers that drive
scan dwell / connection / TX timeouts never expire. Modelling the hardware side
of that interface - and only that - is what makes one network path work for
all of them, without knowing anything about the firmware above the driver.

What is modelled (register offsets from reg_mac_core.h / reg_mac_pl.h, the
descriptor layouts from hal_desc.h):

  core +0x038 STATE_CNTRL      nextState is taken immediately; ACTIVE->IDLE raises
                               the IDLE general interrupt (hal_machw_idle_req waits
                               for it before a channel switch / scan step)
  core +0x0C4 ENCR_CNTRL       key storage RAM: newWrite/newRead/newSearch complete
                               instantly; the cipher type per entry is kept so
                               protected frames can be passed through as plaintext
  core +0x11C/+0x120/+0x124    monotonic counters: device microseconds
  core +0x128.. ABS_TIMER0..9  compared against that counter; an expired armed
                               timer sets its TIMERS_INT_EVENT bit and raises
                               ABS_GEN_TIMERS when unmasked
  pl   +0x06C/+0x070/+0x074    general interrupt status / ack / enable
  pl   +0x078/+0x07C/+0x080    TX/RX interrupt status / ack / enable
  pl   +0x084/+0x088/+0x08C    timer event set (reads as status) / clear / unmask
  pl   +0x0A4/+0x0A8 TSF       64-bit TSF, SW-writable, adopted from beacons
  pl   +0x160..+0x168          time-on-air calculator (COMPUTE_DURATION -> VALID)
  pl   +0x180 DMA_CNTRL_SET    TX queue kicks (newHead/newTail per AC and BCN) and
                               RX chain head loads
  pl   +0x198..+0x1A8          TX head pointers;  +0x1B8/+0x1BC RX header/payload heads

TX: on a queue kick the model walks the THD list (upattern CAFEBABE) from the
head pointer, gathers the MPDU from the THD data range and the TBD chain
(CAFEFADE), hands it to the attached peer, and - a little later in device
time, like a real transmission - writes DESC_DONE|FRAME_SUCCESSFUL into
statinfo and raises the queue's TX trigger when the THD asked for one.
Verified against an OpenBeken boot trace: a host data frame's THD has no
header buffer, the whole MPDU sits in one TBD and frmlen is that plus the FCS.

RX: a frame for the device is written into the payload buffers of the RBD
chain (C0DEDBAD) the firmware handed over, the current RHD (BAADF00D) gets
length / status / RX vector / TSF, and the RX trigger bits are raised. The
MAC header goes into the payload buffers (the RHDs the firmware chains have
no header buffer of their own - also from that trace).

Interrupts: the six MAC FIQ lines of the ICU (bits 16..22) are LEVELS derived
from (status & enable) of the two status registers, split the way the
hardware splits them: prot/tx/rx triggers, misc, tx-rx timers, general. The
firmware's TX-trigger FIQ (traced at app 0x980b4) reads TX_RX_INT_STATUS,
masks 0x7C0, takes the lowest AC bit and acks exactly that bit - which is
the per-queue bit this model raises.

Not modelled: encryption (frames cross the model in the clear - the peer never
sees a cipher), A-MPDU aggregation (the peer never agrees to a block-ack
session, so the firmware never builds one), doze/power-save timing beyond
immediate wake-up, RTS/CTS, rate control.
"""
import os
import struct
import sys

CORE = 0xC0000000
PL = 0xC0008000
SIZE = 0x9000                       # window claimed: core 0x800 + pl 0x600 (page aligned)

# ---- core registers (offsets from CORE)
SIGNATURE, VERSION_1, VERSION_2 = 0x000, 0x004, 0x008
MAC_ADDR_LOW, MAC_ADDR_HI = 0x010, 0x014
BSS_ID_LOW, BSS_ID_HI = 0x020, 0x024
STATE_CNTRL = 0x038
DOZE_CNTRL_1 = 0x044
MAC_CNTRL_1 = 0x04C
MAC_ERR_REC_CNTRL = 0x054
RX_CNTRL = 0x060
BCN_CNTRL_1 = 0x064
ENCR_KEY = (0x0AC, 0x0B0, 0x0B4, 0x0B8)
ENCR_MAC_ADDR_LOW, ENCR_MAC_ADDR_HIGH = 0x0BC, 0x0C0
ENCR_CNTRL = 0x0C4
ENCR_RAM_CONFIG = 0x0D8               # staKeyStartIndex [7:0], staKeyEndIndex [15:8]
MONOTONIC_COUNTER_1 = 0x11C
MONOTONIC_COUNTER_2_LO = 0x120
MONOTONIC_COUNTER_2_HI = 0x124
ABS_TIMER = 0x128                   # 10 timers, 4 bytes apart
ABS_TIMER_CNT = 10
# ---- platform registers (offsets from PL)
NEXT_TBTT = 0x040
DOZE_CNTRL_2 = 0x048
MAC_CNTRL_2 = 0x050
GEN_INT_STATUS, GEN_INT_ACK, GEN_INT_ENABLE = 0x06C, 0x070, 0x074
TX_RX_INT_STATUS, TX_RX_INT_ACK, TX_RX_INT_ENABLE = 0x078, 0x07C, 0x080
TIMERS_INT_EVENT_SET, TIMERS_INT_EVENT_CLEAR, TIMERS_INT_UN_MASK = 0x084, 0x088, 0x08C
TSF_LO, TSF_HI = 0x0A4, 0x0A8
TIME_ON_AIR_PARAM_1, TIME_ON_AIR_PARAM_2, TIME_ON_AIR_VALUE = 0x160, 0x164, 0x168
DMA_CNTRL_SET, DMA_CNTRL_CLEAR = 0x180, 0x184
DMA_STATUS_1 = 0x188
TX_HEAD_PTR = {4: 0x198, 0: 0x19C, 1: 0x1A0, 2: 0x1A4, 3: 0x1A8}   # queue -> register
RX_HEADER_HEAD_PTR, RX_PAYLOAD_HEAD_PTR = 0x1B8, 0x1BC

# ---- bits
HW_IDLE, HW_RESERVED, HW_DOZE, HW_ACTIVE = 0, 1, 2, 3
MASTER_INT_EN = 1 << 31
# general interrupt status
IMP_PRI_TBTT = 1 << 0
IDLE_INTERRUPT = 1 << 2
ABS_GEN_TIMERS = 1 << 3
# tx/rx interrupt status
AC_TX_TRIGGER = {0: 1 << 6, 1: 1 << 7, 2: 1 << 8, 3: 1 << 9, 4: 1 << 10}   # 4 = BCN
RX_TRIGGER = 1 << 16
TIMER_RX_TRIGGER = 1 << 17
COUNTER_RX_TRIGGER = 1 << 19
TIMER_TX_TRIGGER = 1 << 14
# which ICU FIQ line each status bit belongs to (ICU bit numbers, icu_pub.h)
FIQ_MODEM, FIQ_MAC_TX_RX_TIMER, FIQ_MAC_TX_RX_MISC = 16, 17, 18
FIQ_MAC_RX_TRIGGER, FIQ_MAC_TX_TRIGGER, FIQ_MAC_PROT_TRIGGER, FIQ_MAC_GENERAL = 19, 20, 21, 22
LINE_MASK = 0x007F0000
TXRX_LINES = (
    (FIQ_MAC_PROT_TRIGGER, 0x0000003F),
    (FIQ_MAC_TX_TRIGGER, 0x00009FC0),      # AC/BCN/HCCA/RD tx triggers + secUser
    (FIQ_MAC_RX_TRIGGER, RX_TRIGGER),
    (FIQ_MAC_TX_RX_TIMER, TIMER_TX_TRIGGER | TIMER_RX_TRIGGER),
    (FIQ_MAC_TX_RX_MISC, 0x1FFC2000 & ~(TIMER_RX_TRIGGER | RX_TRIGGER | TIMER_TX_TRIGGER)),
)
# DMA_CNTRL_SET
RX_PAYLOAD_NEW_HEAD, RX_HEADER_NEW_HEAD = 1 << 27, 1 << 26
TX_NEW_HEAD = {4: 1 << 8, 0: 1 << 9, 1: 1 << 10, 2: 1 << 11, 3: 1 << 12}
TX_NEW_TAIL = {4: 1 << 0, 0: 1 << 1, 1: 1 << 2, 2: 1 << 3, 3: 1 << 4}
# key storage control
NEW_READ, NEW_WRITE, NEW_SEARCH, SEARCH_ERROR = 1 << 31, 1 << 30, 1 << 29, 1 << 28
# time on air
COMPUTE_DURATION, TIME_ON_AIR_VALID = 1 << 31, 1 << 30
# descriptors (hal_desc.h)
TX_HEADER_DESC_PATTERN = 0xCAFEBABE
TX_PAYLOAD_DESC_PATTERN = 0xCAFEFADE
RX_HEADER_DESC_PATTERN = 0xBAADF00D
RX_PAYLOAD_DESC_PATTERN = 0xC0DEDBAD
INTERRUPT_EN_TX = 1 << 8            # macctrlinfo2
DONT_ENCRYPT = 1 << 30              # macctrlinfo2
FRAME_SUCCESSFUL_TX_BIT = 1 << 23   # statinfo
DESC_DONE_TX_BIT = 1 << 31
TBD_DONE_HW = 1 << 31
RX_PD_LASTBUF, RX_PD_DONE = 0x0001, 0x0002
RX_HD_DONE, RX_HD_SUCCESS, RX_HD_GA_FRAME = 0x4000, 0x2000, 0x0400
RX_HD_KEYIDV, RX_HD_KEYID_LSB = 0x02000000, 15
RX_HD_DECR_UNENC, RX_HD_DECR_CCMPSUCCESS, RX_HD_DECR_TKIPSUCCESS, RX_HD_DECR_WEPSUCCESS = 0x0, 0x1C, 0x18, 0x14
MAC_FCS_LEN = 4
TU_US = 1024

THD_FMT = "<17I"                    # struct tx_hd
THD_SIZE = 68
TBD_FMT = "<5I"
RHD_FMT = "<17I"                    # struct rx_hd (frmlen/ampdu_stat packed in word 7)
RBD_FMT = "<5I"

# legacy / HT rates for the time-on-air calculator, Mbit/s
LEGACY_RATE_MBPS = (1, 2, 5.5, 11, 6, 9, 12, 18, 24, 36, 48, 54)
HT_RATE_MBPS = (6.5, 13, 19.5, 26, 39, 52, 58.5, 65)
# Legacy rate field of RX vector 1A: the PHY's L-SIG RATE code, NOT a rate
# index. The LMAC maps it through rxv2macrate[16] (in the OBK 1.18.300 image at
# 0xCB2EE): DSSS 0..3 = 1/2/5.5/11 Mbps, OFDM 0xB,0xF,0xA,0xE,0x9,0xD,0x8,0xC =
# 6..54 Mbps, every other code = 0xFF - which hal_machw_rx_duration passes to
# nxmac_ppdu_mcs_index_setf, whose ASSERT_ERR (reg_mac_pl.h:6833) then wedges a
# connected station. Code 4 did exactly that.
LSIG_RATE_1M = 0x0
LSIG_VALID_CODES = (0x0, 0x1, 0x2, 0x3, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF)
# how long a transmission "takes" before it is reported done, device microseconds
TX_AIR_TIME_US = 150


def fctl_info(frame):
    """(type, subtype, flags, header_len) of an 802.11 MPDU, or None if too short."""
    if len(frame) < 10:
        return None
    fctl = frame[0] | (frame[1] << 8)
    ftype = (fctl >> 2) & 3
    subtype = (fctl >> 4) & 0xF
    hdr = 24
    if ftype == 1:                              # control
        hdr = 16 if subtype in (0x4, 0x5, 0x6, 0x8, 0x9, 0xA, 0xB) else 10
    elif ftype == 2:
        if (fctl & 0x0300) == 0x0300:           # ToDS+FromDS: addr4
            hdr += 6
        if subtype & 0x8:                       # QoS data
            hdr += 2
        if fctl & 0x8000:                       # order: HT control
            hdr += 4
    elif ftype == 0 and fctl & 0x8000:
        hdr += 4
    return ftype, subtype, fctl, hdr


class MacHw:
    """One nxmac. Drive it with write()/read()/tick(); poll .lines for the ICU."""

    def __init__(self, insns_per_us, log=None):
        self.insns_per_us = max(1, insns_per_us)
        self.log = log or (lambda *a: None)
        # (read(addr, n) -> bytes, write(addr, data)) over guest memory, set by the emulator.
        self.mem = None
        self.regs = {}                          # offset-from-CORE -> value, for the registers we track
        self.state = HW_IDLE
        self.next_state = HW_IDLE
        self.gen_raw = 0
        self.txrx_raw = 0
        self.timers_pending = 0
        self.timer_armed = [False] * ABS_TIMER_CNT
        self.timer_value = [0] * ABS_TIMER_CNT
        self.mono_offset = 0                    # added to insn-derived microseconds
        self.tsf_offset = 0
        self.keys = {}                          # key index -> dict(addr, key, ctype, ...)
        self.lines = 0                          # ICU level mask, bits 16..22
        # TX queues: queue -> address of the THD the hardware is parked at
        self.tx_cur = {q: 0 for q in TX_HEAD_PTR}
        self.tx_last = {q: 0 for q in TX_HEAD_PTR}
        self.tx_inflight = []                   # [(done_at_us, queue, thd_addr, want_irq)]
        self.rx_cur_rhd = 0
        self.rx_cur_rbd = 0
        self.rx_last_rhd = 0                    # last RHD/RBD consumed: the firmware
        self.rx_last_rbd = 0                    # re-chains recycled ones behind them
        self.rx_queue = []                      # frames waiting for descriptors
        self.rx_dropped = 0
        self.last_tbtt_idx = None
        self.on_tx = None                       # callback(frame_bytes, info_dict)
        self.stats = {"tx": 0, "rx": 0, "rx_nodesc": 0, "tx_bad": 0}
        self.events = []                        # for the self-tests
        self.debug = bool(os.environ.get("WIFIDBG"))
        self._dbg_insns = 0

    def dbg(self, msg):
        sys.__stderr__.write("WIFIDBG %10d %s\n" % (self._dbg_insns, msg))
        sys.__stderr__.flush()

    # ------------------------------------------------------------------ time
    def now_us(self, insns):
        return insns // self.insns_per_us

    def mono(self, insns):
        return (self.now_us(insns) + self.mono_offset) & 0xFFFFFFFF

    def tsf(self, insns):
        return (self.now_us(insns) + self.tsf_offset) & 0xFFFFFFFFFFFFFFFF

    def set_tsf(self, value, insns):
        """Adopt a TSF value (a received beacon timestamp or an SW write)."""
        self.tsf_offset = (value - self.now_us(insns)) & 0xFFFFFFFFFFFFFFFF

    # --------------------------------------------------------------- helpers
    def _r32(self, addr):
        return struct.unpack("<I", self.mem[0](addr, 4))[0]

    def _w32(self, addr, value):
        self.mem[1](addr, struct.pack("<I", value & 0xFFFFFFFF))

    def _update_lines(self):
        lines = 0
        gen_en = self.regs.get(GEN_INT_ENABLE + PL - CORE, 0)
        if gen_en & MASTER_INT_EN and self.gen_raw & gen_en & 0x7FFFFFFF:
            lines |= 1 << FIQ_MAC_GENERAL
        txrx_en = self.regs.get(TX_RX_INT_ENABLE + PL - CORE, 0)
        if txrx_en & MASTER_INT_EN:
            act = self.txrx_raw & txrx_en & 0x7FFFFFFF
            for bit, mask in TXRX_LINES:
                if act & mask:
                    lines |= 1 << bit
        self.lines = lines
        return lines

    # -------------------------------------------------------------- register
    def read(self, address, insns):
        """Value to serve for a read in the block, or None to leave plain memory."""
        off = address - CORE
        if off == VERSION_1:
            return 0x00001C03                   # NXMAC_VERSION_1_RESET: no BFMER/MU-MIMO
        if off == STATE_CNTRL:
            return (self.next_state << 4) | self.state
        if off in (MONOTONIC_COUNTER_1, MONOTONIC_COUNTER_2_LO):
            return self.mono(insns)
        if off == MONOTONIC_COUNTER_2_HI:
            return ((self.now_us(insns) + self.mono_offset) >> 32) & 0xFFFF
        if off == ENCR_CNTRL:
            return self.regs.get(off, 0) & ~(NEW_READ | NEW_WRITE | NEW_SEARCH)
        if off == MAC_ERR_REC_CNTRL or off == MAC_CNTRL_2 + PL - CORE:
            return self.regs.get(off, 0)
        p = address - PL
        if p == GEN_INT_STATUS:
            return self.gen_raw & self.regs.get(GEN_INT_ENABLE + PL - CORE, 0) & 0x7FFFFFFF
        if p == TX_RX_INT_STATUS:
            return self.txrx_raw & self.regs.get(TX_RX_INT_ENABLE + PL - CORE, 0) & 0x7FFFFFFF
        if p in (TIMERS_INT_EVENT_SET, TIMERS_INT_EVENT_CLEAR):
            return self.timers_pending
        if p == TSF_LO:
            return self.tsf(insns) & 0xFFFFFFFF
        if p == TSF_HI:
            return (self.tsf(insns) >> 32) & 0xFFFFFFFF
        if p == TIME_ON_AIR_PARAM_2:
            return self.regs.get(off, 0)
        if p == TIME_ON_AIR_VALUE:
            # computeDuration is a command bit: it reads back clear, with
            # timeOnAirValid and the result in its place (see write()).
            return self.regs.get(off, 0) & ~COMPUTE_DURATION
        if p == DMA_STATUS_1:
            return 0                            # every DMA state machine idle
        if p in (DMA_CNTRL_SET, DMA_CNTRL_CLEAR):
            return 0
        return None

    def write(self, address, value, insns):
        """Apply a write in the block. The caller still lets it land in memory."""
        value &= 0xFFFFFFFF
        off = address - CORE
        self.regs[off] = value
        p = address - PL
        self._dbg_insns = insns
        if self.debug and (p in (GEN_INT_ACK, TX_RX_INT_ACK, GEN_INT_ENABLE, TX_RX_INT_ENABLE,
                                 TIMERS_INT_EVENT_SET, TIMERS_INT_EVENT_CLEAR, TIMERS_INT_UN_MASK,
                                 DMA_CNTRL_SET) or off in (STATE_CNTRL, MAC_CNTRL_1, RX_CNTRL, BCN_CNTRL_1)):
            self.dbg("W %08x <= %08x" % (address, value))
        if off == STATE_CNTRL:
            nxt = (value >> 4) & 0xF
            self.next_state = nxt
            prev = self.state
            self.state = nxt
            if nxt == HW_IDLE and prev != HW_IDLE:
                self.gen_raw |= IDLE_INTERRUPT
                self.events.append(("idle", insns))
            if nxt == HW_ACTIVE:
                if prev != HW_DOZE:
                    self.last_tbtt_idx = None   # re-sync TBTT to the current TSF
                if self.rx_queue:
                    self._rx_flush(insns)       # frames buffered while dozing
            self._update_lines()
            return
        if off == MAC_ERR_REC_CNTRL:
            self.regs[off] = value & ~0xFC      # FSM/FIFO reset bits complete at once
            return
        if off == ENCR_CNTRL:
            self._key_ram(value)
            return
        if off == MONOTONIC_COUNTER_2_HI and value & 0x80000000:
            lo = self.regs.get(MONOTONIC_COUNTER_2_LO, 0)
            want = ((value & 0xFFFF) << 32) | lo
            self.mono_offset = want - self.now_us(insns)
            return
        if ABS_TIMER <= off < ABS_TIMER + 4 * ABS_TIMER_CNT:
            i = (off - ABS_TIMER) >> 2
            self.timer_value[i] = value
            # The hardware compares for a match, so a target already behind
            # the counter does not fire (the firmware forces those through
            # TIMERS_INT_EVENT_SET itself). Only a target ahead is armed.
            ahead = ((value - self.mono(insns)) & 0xFFFFFFFF) < 0x80000000
            self.timer_armed[i] = ahead and value != self.mono(insns)
            if self.debug:
                self.dbg("abs_timer[%d] = %u (now %u) %s" % (i, value, self.mono(insns), "armed" if self.timer_armed[i] else "past, not armed"))
            return
        if p == GEN_INT_ACK:
            self.gen_raw &= ~value
            self._update_lines()
            return
        if p == TX_RX_INT_ACK:
            self.txrx_raw &= ~value
            self._update_lines()
            return
        if p in (GEN_INT_ENABLE, TX_RX_INT_ENABLE, TIMERS_INT_UN_MASK):
            self._update_lines()
            return
        if p == TIMERS_INT_EVENT_SET:
            self.timers_pending |= value & 0x3FF
            if self.timers_pending & self.regs.get(TIMERS_INT_UN_MASK + PL - CORE, 0):
                self.gen_raw |= ABS_GEN_TIMERS
            self._update_lines()
            return
        if p == TIMERS_INT_EVENT_CLEAR:
            self.timers_pending &= ~value
            return
        if p == TSF_LO:
            self.set_tsf((self.tsf(insns) & ~0xFFFFFFFF) | value, insns)
            return
        if p == TSF_HI:
            self.set_tsf((value << 32) | (self.tsf(insns) & 0xFFFFFFFF), insns)
            return
        if p == MAC_CNTRL_2:
            self.regs[off] = value & ~1         # softReset self-clears
            return
        if p == DOZE_CNTRL_2:
            if value & 1 and self.state == HW_DOZE:
                self.state = self.next_state = HW_ACTIVE
            return
        if p == TIME_ON_AIR_VALUE:
            # nxmac_compute_duration_setf() writes computeDuration (bit 31)
            # into TIME_ON_AIR_VALUE itself - not PARAM_2 - and the firmware
            # then spins on timeOnAirValid (bit 30) of the same register.
            # hal_machw_rx_duration's spin has no timeout: modelling the bit
            # in PARAM_2 hung a connected station's Wi-Fi task for good.
            if value & COMPUTE_DURATION:
                self._time_on_air(self.regs.get(TIME_ON_AIR_PARAM_2 + PL - CORE, 0))
            return
        if p == DMA_CNTRL_SET:
            self._dma_kick(value, insns)
            return

    # ------------------------------------------------------------- key RAM
    def _key_ram(self, value):
        idx = (value >> 16) & 0x3FF
        if value & NEW_WRITE:
            lo = self.regs.get(ENCR_MAC_ADDR_LOW, 0)
            hi = self.regs.get(ENCR_MAC_ADDR_HIGH, 0)
            addr = struct.pack("<IH", lo, hi & 0xFFFF)
            self.keys[idx] = {
                "addr": addr,
                "key": b"".join(struct.pack("<I", self.regs.get(k, 0)) for k in ENCR_KEY),
                "ctype": (value >> 8) & 7, "vlan": (value >> 4) & 0xF,
                "spp": (value >> 2) & 3, "usedef": (value >> 1) & 1, "clen": value & 1,
            }
            self.events.append(("key_write", idx, self.keys[idx]["ctype"]))
        elif value & NEW_READ:
            ent = self.keys.get(idx)
            if ent:
                self.regs[ENCR_MAC_ADDR_LOW] = struct.unpack("<I", ent["addr"][:4])[0]
                self.regs[ENCR_MAC_ADDR_HIGH] = struct.unpack("<H", ent["addr"][4:6])[0]
                for i, k in enumerate(ENCR_KEY):
                    self.regs[k] = struct.unpack("<I", ent["key"][4 * i:4 * i + 4])[0]
                    self._w32(CORE + k, self.regs[k])
                self._w32(CORE + ENCR_MAC_ADDR_LOW, self.regs[ENCR_MAC_ADDR_LOW])
                self._w32(CORE + ENCR_MAC_ADDR_HIGH, self.regs[ENCR_MAC_ADDR_HIGH])
                value = (value & ~0x7FF) | (ent["ctype"] << 8) | (ent["vlan"] << 4) | (ent["spp"] << 2) | (ent["usedef"] << 1) | ent["clen"]
        elif value & NEW_SEARCH:
            lo = self.regs.get(ENCR_MAC_ADDR_LOW, 0)
            hi = self.regs.get(ENCR_MAC_ADDR_HIGH, 0)
            addr = struct.pack("<IH", lo, hi & 0xFFFF)
            found = None
            for i, ent in self.keys.items():
                if ent["addr"] == addr:
                    found = i
                    break
            if found is None:
                value |= SEARCH_ERROR
            else:
                value = (value & ~(SEARCH_ERROR | (0x3FF << 16))) | (found << 16)
        self.regs[ENCR_CNTRL] = value & ~(NEW_READ | NEW_WRITE | NEW_SEARCH)

    def key_for_addr(self, addr):
        for ent in self.keys.values():
            if ent["addr"] == addr:
                return ent
        return None

    # --------------------------------------------------------- time on air
    def _time_on_air(self, param2):
        p1 = self.regs.get(TIME_ON_AIR_PARAM_1 + PL - CORE, 0)
        length = p1 & 0xFFFFF
        mcs = param2 & 0x7F
        pre_type = (p1 >> 24) & 7               # 0 = non-HT short/long, 2/3 = HT
        if pre_type >= 2:
            rate = HT_RATE_MBPS[min(mcs, 7)]
            overhead = 40
        else:
            rate = LEGACY_RATE_MBPS[min(mcs, len(LEGACY_RATE_MBPS) - 1)]
            overhead = 192 if rate < 6 else 20
        dur = int(overhead + (length * 8) / rate) & 0xFFFF
        self.regs[TIME_ON_AIR_VALUE + PL - CORE] = dur | TIME_ON_AIR_VALID
        self._w32(PL + TIME_ON_AIR_VALUE, dur | TIME_ON_AIR_VALID)

    # ------------------------------------------------------------- TX side
    def _dma_kick(self, value, insns):
        if value & RX_HEADER_NEW_HEAD:
            self.rx_cur_rhd = self.regs.get(RX_HEADER_HEAD_PTR + PL - CORE, 0) & ~3
            self.rx_last_rhd = 0
        if value & RX_PAYLOAD_NEW_HEAD:
            self.rx_cur_rbd = self.regs.get(RX_PAYLOAD_HEAD_PTR + PL - CORE, 0) & ~3
            self.rx_last_rbd = 0
        for q, bit in TX_NEW_HEAD.items():
            if value & bit:
                self.tx_cur[q] = self.regs.get(TX_HEAD_PTR[q] + PL - CORE, 0)
                self._tx_run(q, insns)
        for q, bit in TX_NEW_TAIL.items():
            if value & bit:
                if not self.tx_cur[q] and self.tx_last[q]:
                    try:
                        self.tx_cur[q] = self._r32(self.tx_last[q] + 4)   # nextfrmexseq_ptr
                    except Exception:
                        self.tx_cur[q] = 0
                self._tx_run(q, insns)
        if self.rx_queue:
            self._rx_flush(insns)

    def _tx_run(self, q, insns):
        """Transmit every THD chained on queue q, following nextfrmexseq_ptr."""
        guard = 0
        while self.tx_cur[q] and guard < 64:
            guard += 1
            thd = self.tx_cur[q]
            ok = self._tx_one(q, thd, insns)
            self.tx_last[q] = thd
            if not ok:
                self.tx_cur[q] = 0
                break
            try:
                nxt = self._r32(thd + 4)
            except Exception:
                nxt = 0
            self.tx_cur[q] = nxt

    def _tx_one(self, q, thd_addr, insns):
        try:
            f = struct.unpack(THD_FMT, self.mem[0](thd_addr, THD_SIZE))
        except Exception:
            self.stats["tx_bad"] += 1
            return False
        if f[0] != TX_HEADER_DESC_PATTERN:
            self.stats["tx_bad"] += 1
            self.log("[WIFI] THD %08x bad pattern %08x" % (thd_addr, f[0]))
            return False
        upat, nextfrm, nextmpdu, first_pbd, dstart, dend, frmlen, life, phy, pol, o1, o2, o3, mac1, mac2, stat, mtu = f
        if nextmpdu:
            # An A-MPDU chain: the extra descriptor carries no data; each MPDU
            # descriptor hangs off nextmpdudesc_ptr and is sent on its own.
            node = nextmpdu
            guard = 0
            while node and guard < 64:
                guard += 1
                self._tx_one(q, node, insns)
                try:
                    node = self._r32(node + 8)
                except Exception:
                    break
            self._tx_done(q, thd_addr, mac2, insns)
            return True
        data = b""
        if dstart and dend >= dstart and dend - dstart < 4096:
            data += bytes(self.mem[0](dstart, dend - dstart + 1))
        pbd = first_pbd
        guard = 0
        while pbd and guard < 32:
            guard += 1
            try:
                t = struct.unpack(TBD_FMT, self.mem[0](pbd, 20))
            except Exception:
                break
            if t[0] != TX_PAYLOAD_DESC_PATTERN:
                break
            if t[3] >= t[2] and t[3] - t[2] < 4096:
                data += bytes(self.mem[0](t[2], t[3] - t[2] + 1))
            self._w32(pbd + 16, t[4] | TBD_DONE_HW)
            pbd = t[1]
        if not data:
            # A THD with nothing to send yet (payload still being downloaded):
            # park here, the firmware will kick the tail again.
            return False
        on_air = frmlen - MAC_FCS_LEN
        frame = self._plaintext(data, on_air, mac2)
        self.stats["tx"] += 1
        if self.debug:
            self.dbg("tx q%d thd %08x len %d frmlen %d: %s" % (q, thd_addr, len(frame), frmlen, frame[:32].hex()))
        if self.on_tx is not None:
            try:
                self.on_tx(frame, {"queue": q, "insns": insns, "frmlen": frmlen,
                                   "policy": pol, "statinfo": stat})
            except Exception as e:      # the peer must never take the guest down
                self.log("[WIFI] peer error on TX: %r" % (e,))
        self._tx_done(q, thd_addr, mac2, insns)
        return True

    def _plaintext(self, data, on_air, mac2):
        """Strip the room the firmware left for the cipher around the body.

        With a key in the storage RAM the hardware would encrypt in place: the
        buffer already holds the IV/EIV after the MAC header and (usually) the
        MIC space at the end. The peer talks to the firmware in the clear, so
        those bytes go.
        """
        info = fctl_info(data)
        if info is None:
            return data
        ftype, subtype, fctl, hdr = info
        if not (fctl & 0x4000) or (mac2 & DONT_ENCRYPT):
            return data[:on_air] if on_air > 0 else data
        if len(data) < hdr + 8:
            return data
        body = data[hdr + 8:]                   # drop CCMP/TKIP IV+EIV
        if len(data) >= on_air and on_air - hdr - 8 - 8 >= 0:
            body = body[:on_air - hdr - 8 - 8]  # drop MIC space
        hdr_bytes = bytearray(data[:hdr])
        hdr_bytes[1] &= ~0x40                   # no longer protected
        return bytes(hdr_bytes) + body

    def _tx_done(self, q, thd_addr, mac2, insns):
        done_at = self.now_us(insns) + TX_AIR_TIME_US
        self.tx_inflight.append((done_at, q, thd_addr, bool(mac2 & INTERRUPT_EN_TX)))

    def _tx_complete(self, insns):
        now = self.now_us(insns)
        self._dbg_insns = insns
        keep = []
        changed = False
        for item in self.tx_inflight:
            done_at, q, thd_addr, want_irq = item
            if done_at > now:
                keep.append(item)
                continue
            try:
                stat = self._r32(thd_addr + 60)
                self._w32(thd_addr + 60, stat | DESC_DONE_TX_BIT | FRAME_SUCCESSFUL_TX_BIT)
                self._w32(thd_addr + 64, TX_AIR_TIME_US)   # mediumtimeused
            except Exception:
                pass
            if want_irq:
                self.txrx_raw |= AC_TX_TRIGGER[q]
                changed = True
            if self.debug:
                self.dbg("tx done q%d thd %08x irq=%d" % (q, thd_addr, want_irq))
        self.tx_inflight = keep
        if changed:
            self._update_lines()

    # ------------------------------------------------------------- RX side
    def inject(self, frame, insns, rssi=-45, rate=LSIG_RATE_1M, decr=None, keyidx=None):
        """Hand an MPDU (no FCS) to the receiver; delivered on the next flush.

        Only a MAC in the ACTIVE state is listening. A frame that arrives
        while it is IDLE is lost, as on air: queueing it instead delivered a
        backlog of stale beacons the moment the firmware first enabled RX, in
        the middle of its RF calibration. A DOZING station is different: the
        access point buffers unicast frames for it and it collects them when
        it wakes for the next beacon, so those wait (see tick()).
        """
        if self.state == HW_DOZE and len(frame) >= 10 and not (frame[4] & 1):
            self.rx_queue.append((bytes(frame), rssi, rate, decr, keyidx))
            return
        if self.state != HW_ACTIVE:
            self.stats["rx_not_listening"] = self.stats.get("rx_not_listening", 0) + 1
            return
        self.rx_queue.append((bytes(frame), rssi, rate, decr, keyidx))
        self._rx_flush(insns)

    def _sta_key_index(self, addr2):
        """Key RAM index of the pairwise entry whose address is addr2, or None.

        The hardware compares a received frame's transmitter address with the
        station entries of the key storage RAM and reports a hit in the RHD
        (keyIndexValid + keyIndex). The UMAC derives the sending station from
        that index; without it every data frame counts as coming from an
        unknown station and is dropped - which is how DHCP to OpenBeken's AP
        went unanswered although the station had associated. The station range
        comes from ENCR_RAM_CONFIG when the firmware programmed it, else from
        hal_machw.h (KEY_ENTRY_MIN_ID 24 .. KEY_ENTRY_MAX_ID 63).
        """
        cfg = self.regs.get(ENCR_RAM_CONFIG)
        lo, hi = (cfg & 0xFF, (cfg >> 8) & 0xFF) if cfg else (24, 63)
        if hi < lo:
            lo, hi = 24, 63
        for idx, ent in self.keys.items():
            if lo <= idx <= hi and ent["addr"] == addr2:
                return idx
        return None

    def _rx_flush(self, insns):
        if self.state != HW_ACTIVE:
            return
        changed = False
        while self.rx_queue:
            frame, rssi, rate, decr, keyidx = self.rx_queue[0]
            r = self._rx_one(frame, rssi, rate, decr, keyidx, insns)
            if r is None:
                break                           # no descriptors right now
            self.rx_queue.pop(0)
            changed = True
        if len(self.rx_queue) > 64:
            self.rx_dropped += len(self.rx_queue) - 64
            del self.rx_queue[:-64]
        if changed:
            self.txrx_raw |= RX_TRIGGER | TIMER_RX_TRIGGER | COUNTER_RX_TRIGGER
            self._update_lines()

    def _rx_one(self, frame, rssi, rate, decr, keyidx, insns):
        rhd = self.rx_cur_rhd
        if not rhd and self.rx_last_rhd:
            # The chain ended at the last descriptor we used; the firmware may
            # have appended recycled ones behind it since (RX_HEADER_NEW_TAIL).
            try:
                rhd = self.rx_cur_rhd = self._r32(self.rx_last_rhd + 4)
            except Exception:
                return None
        if not rhd:
            return None
        try:
            h = struct.unpack(RHD_FMT, self.mem[0](rhd, 68))
        except Exception:
            return None
        if h[0] != RX_HEADER_DESC_PATTERN:
            self.stats["rx_nodesc"] += 1
            return None
        if h[16] & RX_HD_DONE:
            return None                         # firmware has not recycled it yet
        # frmlen is what the firmware takes as the frame length (see below), so
        # no FCS is written after the body.
        payload = frame
        # Collect enough payload descriptors first, so a shortage leaves nothing half-written.
        rbds = []
        rbd = self.rx_cur_rbd
        if not rbd and self.rx_last_rbd:
            try:
                rbd = self._r32(self.rx_last_rbd + 4)
            except Exception:
                return None
        need = len(payload)
        while need > 0 and rbd:
            try:
                b = struct.unpack(RBD_FMT, self.mem[0](rbd, 20))
            except Exception:
                return None
            if b[0] != RX_PAYLOAD_DESC_PATTERN or b[3] < b[2]:
                return None
            cap = b[3] - b[2] + 1
            rbds.append((rbd, b, min(cap, need)))
            need -= cap
            rbd = b[1]
        if need > 0:
            self.stats["rx_nodesc"] += 1
            return None
        pos = 0
        for i, (addr, b, take) in enumerate(rbds):
            self.mem[1](b[2], payload[pos:pos + take])
            pos += take
            stat = RX_PD_DONE | (RX_PD_LASTBUF if i == len(rbds) - 1 else 0)
            self._w32(addr + 16, (b[4] & 0xFFFF0000) | stat)
        self.rx_last_rbd = rbds[-1][0]
        self.rx_cur_rbd = rbds[-1][1][1]
        # Header descriptor: length, vectors, status.
        group = len(frame) >= 10 and bool(frame[4] & 1)
        statinfo = RX_HD_DONE | RX_HD_SUCCESS | (RX_HD_GA_FRAME if group else 0)
        if decr:
            statinfo |= decr
        if keyidx is None and len(frame) >= 16:
            keyidx = self._sta_key_index(bytes(frame[10:16]))
        if keyidx is not None:
            statinfo |= RX_HD_KEYIDV | ((keyidx & 0x3FF) << RX_HD_KEYID_LSB)
        tsf = self.tsf(insns)
        frmlen = len(frame)
        recvec1a = ((frmlen + MAC_FCS_LEN) & 0xFFF) | ((rate & 0xF) << 12)
        recvec1b = 0                            # non-HT, long preamble, 20 MHz
        # RSSI: hal_desc.h's RXVEC1C_RSSI1 macro reads bits 0-7, but Beken's
        # packed struct rx_vector_1 lands rssi1 at bit 88 = the top byte of
        # this word (the firmware printed "rssi 0" with only the low byte
        # set). Fill both.
        recvec1c = (rssi & 0xFF) | ((rssi & 0xFF) << 24)
        words = [h[0], h[1], rbds[0][0], h[3], h[4], h[5], h[6],
                 (frmlen & 0xFFFF), tsf & 0xFFFFFFFF, (tsf >> 32) & 0xFFFFFFFF,
                 recvec1a, recvec1b, recvec1c, 0, 0, 0, statinfo]
        self.mem[1](rhd, struct.pack(RHD_FMT, *words))
        if self.debug:
            self._dbg_insns = insns
            self.dbg("rx -> rhd %08x len %d: %s" % (rhd, len(frame), frame[:32].hex()))
        self.rx_last_rhd = rhd
        self.rx_cur_rhd = h[1]
        self.stats["rx"] += 1
        return True

    # ------------------------------------------------------------------ time
    def tick(self, insns):
        """Advance timers / completions; returns the ICU level mask."""
        if self.tx_inflight:
            self._tx_complete(insns)
        if self.rx_queue:
            self._rx_flush(insns)
        now = self.mono(insns)
        fired = 0
        unmask = self.regs.get(TIMERS_INT_UN_MASK + PL - CORE, 0)
        for i in range(ABS_TIMER_CNT):
            if self.timer_armed[i] and ((now - self.timer_value[i]) & 0xFFFFFFFF) < 0x80000000:
                self.timer_armed[i] = False
                fired |= 1 << i
        # A masked timer expires silently: its event bit is not latched. The
        # firmware's handler reads the raw event register and treats every
        # set bit as a timeout, so a stale bit from a timer it had already
        # disarmed was reported as an AC TX timeout and triggered recovery.
        fired &= unmask
        if fired:
            self.timers_pending |= fired
            self.gen_raw |= ABS_GEN_TIMERS
            self.events.append(("timer", insns, fired))
            if self.debug:
                self._dbg_insns = insns
                self.dbg("timers fired %03x (unmask %03x)" % (fired, self.regs.get(TIMERS_INT_UN_MASK + PL - CORE, 0)))
        # TBTT: every beacon interval of the TSF while the MAC is active - and
        # while it dozes, because the hardware wakes itself to ACTIVE for the
        # beacon (radioWakeUpTime ahead of TBTT) and lets the firmware decide
        # whether to sleep again. Without that a power-saving station never
        # woke up at all.
        bcn_int = self.regs.get(BCN_CNTRL_1, 0) & 0xFFFF
        if bcn_int and self.state in (HW_ACTIVE, HW_DOZE):
            idx = self.tsf(insns) // (bcn_int * TU_US)
            if self.last_tbtt_idx is None:
                self.last_tbtt_idx = idx
            elif idx != self.last_tbtt_idx:
                self.last_tbtt_idx = idx
                if self.state == HW_DOZE:
                    self.state = self.next_state = HW_ACTIVE
                    self.events.append(("doze_wake", insns))
                    if self.rx_queue:
                        self._rx_flush(insns)
                self.gen_raw |= IMP_PRI_TBTT
        return self._update_lines()

    @property
    def busy(self):
        return bool(self.tx_inflight or self.rx_queue)


# ---------------------------------------------------------------------------
# Standalone self-tests, no emulator: a fake guest memory and the register
# writes an OpenBeken AP boot was traced making. Run:  python src/wifimac.py
# ---------------------------------------------------------------------------
def _run_selftests():
    n = 0

    def check(cond, msg):
        nonlocal n
        assert cond, "FAIL: " + msg
        n += 1
        print("  [PASS]", msg)

    mem = bytearray(0x100000)
    BASE = 0x400000

    def rd(a, s):
        return bytes(mem[a - BASE:a - BASE + s])

    def wr(a, d):
        mem[a - BASE:a - BASE + len(d)] = d

    m = MacHw(5)
    m.mem = (rd, wr)
    sent = []
    m.on_tx = lambda f, info: sent.append((f, info))

    print("== clocks ==")
    check(m.read(CORE + MONOTONIC_COUNTER_2_LO, 5_000) == 1000, "monotonic counter counts device microseconds")
    m.write(CORE + STATE_CNTRL, 0x30, 0)
    check(m.read(CORE + STATE_CNTRL, 0) == 0x33, "nextState ACTIVE is taken at once (reads 0x33)")
    m.write(PL + GEN_INT_ENABLE, 0x8377f14d, 0)
    m.write(CORE + STATE_CNTRL, 0x00, 0)
    check(m.gen_raw & IDLE_INTERRUPT and m.lines & (1 << FIQ_MAC_GENERAL), "ACTIVE->IDLE raises the idle interrupt on the general line")
    m.write(PL + GEN_INT_ACK, IDLE_INTERRUPT, 0)
    check(not m.lines, "acked: line drops")
    m.write(CORE + STATE_CNTRL, 0x00, 0)
    check(not (m.gen_raw & IDLE_INTERRUPT), "IDLE->IDLE does not re-raise it")

    print("== ABS timers ==")
    m.write(CORE + ABS_TIMER + 4 * 7, 100_000, 0)       # MM timer at 100 ms
    m.write(PL + TIMERS_INT_UN_MASK, 0x80, 0)
    m.tick(5 * 99_999)
    check(m.timers_pending == 0, "not before its time")
    m.tick(5 * 100_000)
    check(m.timers_pending == 0x80 and m.read(PL + TIMERS_INT_EVENT_SET, 0) == 0x80,
          "timer 7 fires at 100 ms, EVENT_SET reads the pending bit")
    check(m.lines & (1 << FIQ_MAC_GENERAL) and m.gen_raw & ABS_GEN_TIMERS, "ABS_GEN_TIMERS on the general line")
    m.write(PL + TIMERS_INT_EVENT_CLEAR, 0x80, 0)
    m.write(PL + GEN_INT_ACK, ABS_GEN_TIMERS, 0)
    m.tick(5 * 200_000)
    check(m.timers_pending == 0 and not m.lines, "cleared and not re-fired for the same value")
    m.write(CORE + ABS_TIMER + 4 * 2, 50, 5 * 300_000)   # a target already in the past
    m.write(PL + TIMERS_INT_UN_MASK, 0x84, 0)
    m.tick(5 * 300_001)
    check(not (m.timers_pending & 0x4), "a target already behind the counter does not fire (match semantics)")
    m.write(PL + TIMERS_INT_EVENT_SET, 0x4, 0)
    check(m.timers_pending & 0x4 and m.gen_raw & ABS_GEN_TIMERS, "the firmware forces it through TIMERS_INT_EVENT_SET instead")
    m.write(PL + TIMERS_INT_EVENT_CLEAR, 0x4, 0); m.write(PL + GEN_INT_ACK, ABS_GEN_TIMERS, 0)

    print("== key storage RAM ==")
    m.write(CORE + ENCR_MAC_ADDR_LOW, 0x44332211, 0); m.write(CORE + ENCR_MAC_ADDR_HIGH, 0x6655, 0)
    for i, k in enumerate(ENCR_KEY):
        m.write(CORE + k, 0x01010101 * (i + 1), 0)
    m.write(CORE + ENCR_CNTRL, NEW_WRITE | (30 << 16) | (3 << 8), 0)
    check(m.read(CORE + ENCR_CNTRL, 0) & NEW_WRITE == 0, "newWrite completes instantly")
    check(m.keys[30]["addr"] == bytes.fromhex("112233445566") and m.keys[30]["ctype"] == 3, "entry 30 stored with CCMP")
    m.write(CORE + ENCR_MAC_ADDR_LOW, 0x44332211, 0); m.write(CORE + ENCR_MAC_ADDR_HIGH, 0x6655, 0)
    m.write(CORE + ENCR_CNTRL, NEW_SEARCH, 0)
    v = m.read(CORE + ENCR_CNTRL, 0)
    check(not (v & SEARCH_ERROR) and ((v >> 16) & 0x3FF) == 30, "search by address finds index 30")
    m.write(CORE + ENCR_MAC_ADDR_LOW, 0, 0)
    m.write(CORE + ENCR_CNTRL, NEW_SEARCH, 0)
    check(m.read(CORE + ENCR_CNTRL, 0) & SEARCH_ERROR, "unknown address -> searchError")

    print("== time on air ==")
    m.write(PL + TIME_ON_AIR_PARAM_1, 100, 0)
    m.write(PL + TIME_ON_AIR_PARAM_2, 0, 0)            # nxmac_ppdu_mcs_index_setf(0)
    check(not (m.read(PL + TIME_ON_AIR_VALUE, 0) & TIME_ON_AIR_VALID), "no result before the compute command")
    m.write(PL + TIME_ON_AIR_VALUE, COMPUTE_DURATION, 0)   # nxmac_compute_duration_setf(1)
    v = m.read(PL + TIME_ON_AIR_VALUE, 0)
    check(v & TIME_ON_AIR_VALID and (v & 0xFFFF) == 192 + 800, "100 bytes at 1 Mbps = 992 us, valid")

    print("== TX: THD + TBD chain -> peer, done status, trigger ==")
    THD, TBD, BUF, POL = 0x41cff0, 0x420c10, 0x420c2a, 0x417ecc
    frame = bytes.fromhex("08020000ffffffffffffc8478c000001c8478c0000011000aaaa0300000008060001080006040001c8478c000001c0a80401000000000000c0a80401")
    wr(BUF, frame)
    wr(TBD, struct.pack(TBD_FMT, TX_PAYLOAD_DESC_PATTERN, 0, BUF, BUF + len(frame) - 1, 0))
    wr(THD, struct.pack(THD_FMT, TX_HEADER_DESC_PATTERN, 0, 0, TBD, 0, 0, len(frame) + 4, 0, 0x3f0002, POL, 0, 0, 0, 0, INTERRUPT_EN_TX, 0, 0))
    m.write(PL + TX_RX_INT_ENABLE, 0x800207c0, 0)
    m.write(PL + TX_HEAD_PTR[2], THD, 0)
    m.write(PL + DMA_CNTRL_SET, TX_NEW_HEAD[2], 1000)
    check(len(sent) == 1 and sent[0][0] == frame and sent[0][1]["queue"] == 2, "the MPDU reached the peer from queue AC2")
    check(struct.unpack("<I", rd(THD + 60, 4))[0] == 0, "statinfo untouched until the air time has passed")
    m.tick(1000 + 5 * TX_AIR_TIME_US)
    st = struct.unpack("<I", rd(THD + 60, 4))[0]
    check(st & DESC_DONE_TX_BIT and st & FRAME_SUCCESSFUL_TX_BIT, "DESC_DONE|FRAME_SUCCESSFUL written after the air time")
    check(struct.unpack("<I", rd(TBD + 16, 4))[0] & TBD_DONE_HW, "TBD marked handled")
    check(m.lines & (1 << FIQ_MAC_TX_TRIGGER) and m.read(PL + TX_RX_INT_STATUS, 0) & AC_TX_TRIGGER[2], "AC2 TX trigger on the tx-trigger line")
    m.write(PL + TX_RX_INT_ACK, AC_TX_TRIGGER[2], 0)
    check(not m.lines, "acked")
    # chain a second THD behind it and kick the tail
    THD2 = THD + 0x100
    wr(THD2, struct.pack(THD_FMT, TX_HEADER_DESC_PATTERN, 0, 0, TBD, 0, 0, len(frame) + 4, 0, 0, POL, 0, 0, 0, 0, 0, 0, 0))
    wr(THD + 4, struct.pack("<I", THD2))
    m.write(PL + DMA_CNTRL_SET, TX_NEW_TAIL[2], 2000)
    check(len(sent) == 2, "newTail resumes from the last descriptor's nextfrmexseq_ptr")
    m.tick(2000 + 5 * TX_AIR_TIME_US)
    check(not (m.lines & (1 << FIQ_MAC_TX_TRIGGER)), "a THD without INTERRUPT_EN_TX completes silently")
    # a protected data frame: IV and MIC space are stripped for the peer
    prot = bytearray(frame); prot[1] |= 0x40
    body = bytes(prot[24:])
    buf2 = bytes(prot[:24]) + bytes(8) + body + bytes(8)
    wr(BUF, buf2)
    wr(TBD, struct.pack(TBD_FMT, TX_PAYLOAD_DESC_PATTERN, 0, BUF, BUF + len(buf2) - 1, 0))
    wr(THD, struct.pack(THD_FMT, TX_HEADER_DESC_PATTERN, 0, 0, TBD, 0, 0, len(buf2) + 4, 0, 0, POL, 0, 0, 0, 0, 0, 0, 0))
    m.write(PL + DMA_CNTRL_SET, TX_NEW_HEAD[2], 3000)
    check(sent[-1][0] == frame, "protected frame handed over as the plaintext MPDU")

    print("== RX: payload buffers, header descriptor, trigger ==")
    RHD0, RHD1, RBD0, RBD1, PB0, PB1 = 0x41a4c0, 0x41a524, 0x41ad24, 0x41af48, 0x41ad48, 0x41af6c
    wr(RHD0, struct.pack(RHD_FMT, RX_HEADER_DESC_PATTERN, RHD1, 0, 0x41f16c, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
    wr(RHD1, struct.pack(RHD_FMT, RX_HEADER_DESC_PATTERN, 0, 0, 0x41f17c, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
    wr(RBD0, struct.pack(RBD_FMT, RX_PAYLOAD_DESC_PATTERN, RBD1, PB0, PB0 + 511, 0))
    wr(RBD1, struct.pack(RBD_FMT, RX_PAYLOAD_DESC_PATTERN, 0, PB1, PB1 + 511, 0))
    m.write(PL + RX_HEADER_HEAD_PTR, RHD0 | 1, 0); m.write(PL + DMA_CNTRL_SET, RX_HEADER_NEW_HEAD, 0)
    m.write(PL + RX_PAYLOAD_HEAD_PTR, RBD0 | 1, 0); m.write(PL + DMA_CNTRL_SET, RX_PAYLOAD_NEW_HEAD, 0)
    probe = bytes.fromhex("40000000ffffffffffff020000000001ffffffffffff1000") + b"\x00\x00\x01\x08\x82\x84\x8b\x96\x0c\x12\x18\x24"
    m.write(CORE + STATE_CNTRL, 0x00, 3900)
    m.inject(probe, 3900, rssi=-40)
    check(struct.unpack(RHD_FMT, rd(RHD0, 68))[16] == 0 and not m.rx_queue,
          "a MAC in IDLE is not listening: the frame is lost, not queued")
    m.write(CORE + STATE_CNTRL, 0x30, 4000)
    m.write(PL + GEN_INT_ACK, 0xFFFFFFFF, 4000)
    m.inject(probe, 4000, rssi=-40)
    h = struct.unpack(RHD_FMT, rd(RHD0, 68))
    check(h[16] & RX_HD_DONE and h[16] & RX_HD_SUCCESS and h[16] & RX_HD_GA_FRAME, "RHD0 done|success|group-addressed")
    check((h[7] & 0xFFFF) == len(probe) and h[2] == RBD0, "frmlen is the MPDU length (no FCS); first_pbd_ptr -> RBD0")
    check(rd(PB0, len(probe)) == probe, "payload landed in the first buffer")
    check(((h[10] >> 12) & 0xF) in LSIG_VALID_CODES,
          "RX vector legacy rate is a valid L-SIG code (an invalid one trips the firmware's MCS assert)")
    b0 = struct.unpack(RBD_FMT, rd(RBD0, 20))
    check((b0[4] & 0xFFFF) == (RX_PD_DONE | RX_PD_LASTBUF), "RBD0 done|lastbuf")
    check(m.read(PL + TX_RX_INT_STATUS, 0) & TIMER_RX_TRIGGER and m.lines & (1 << FIQ_MAC_TX_RX_TIMER),
          "timerRxTrigger raised (the one this firmware enables) on the tx-rx-timer line")
    check(not (m.lines & (1 << FIQ_MAC_RX_TRIGGER)), "rxTrigger itself stays masked: not enabled by the firmware")
    check(not (h[16] & RX_HD_KEYIDV), "a sender with no key RAM entry is reported without a key index")
    m.write(PL + TX_RX_INT_ACK, 0xFFFFFFFF, 0)
    # The firmware registers an associated station in the key RAM (index 24+ = sta 0+).
    m.write(CORE + ENCR_MAC_ADDR_LOW, 0x00000002, 0); m.write(CORE + ENCR_MAC_ADDR_HIGH, 0x0100, 0)
    m.write(CORE + ENCR_CNTRL, NEW_WRITE | (24 << 16), 0)
    big = bytes.fromhex("08010000c8478c000001020000000001ffffffffffff2000") + bytes(range(256)) + bytes(20)
    m.inject(big, 5000)
    h1 = struct.unpack(RHD_FMT, rd(RHD1, 68))
    check(h1[16] & RX_HD_DONE and h1[2] == RBD1, "second frame uses RHD1 and starts at RBD1")
    check(h1[16] & RX_HD_KEYIDV and ((h1[16] >> RX_HD_KEYID_LSB) & 0x3FF) == 24,
          "transmitter address found in the key RAM: keyIndexValid with index 24 (station 0)")
    m.inject(b"\x08\x02" + bytes(30), 6000)
    check(len(m.rx_queue) == 1, "no free RHD: the frame waits in the queue, nothing half-written")
    wr(RHD1 + 4, struct.pack("<I", RHD0))         # firmware re-chains RHD0 behind RHD1...
    wr(RHD0 + 64, struct.pack("<I", 0))           # ...after clearing its status
    wr(RHD0 + 4, struct.pack("<I", 0))
    wr(RBD1 + 4, struct.pack("<I", RBD0))
    wr(RBD0 + 16, struct.pack("<I", 0)); wr(RBD0 + 4, struct.pack("<I", 0))
    m.write(PL + DMA_CNTRL_SET, 1 << 24, 7000)    # RX_HEADER_NEW_TAIL
    check(len(m.rx_queue) == 0 and struct.unpack(RHD_FMT, rd(RHD0, 68))[16] & RX_HD_DONE,
          "queued frame delivered once the firmware recycled a descriptor")

    print("== TSF / TBTT ==")
    m.write(PL + TSF_LO, 1_000_000, 5 * 10); m.write(PL + TSF_HI, 0, 5 * 10)
    check(m.read(PL + TSF_LO, 5 * 10) == 1_000_000, "TSF set by software")
    check(m.read(PL + TSF_LO, 5 * 20) == 1_000_010, "and it runs")
    m.write(CORE + BCN_CNTRL_1, 0xff900064, 0)
    m.write(CORE + STATE_CNTRL, 0x30, 5 * 20)
    m.write(PL + GEN_INT_ACK, 0xFFFFFFFF, 0)
    m.tick(5 * 30)
    check(not (m.gen_raw & IMP_PRI_TBTT), "no TBTT inside the current interval")
    m.tick(5 * (102400 + 30))
    check(m.gen_raw & IMP_PRI_TBTT and m.lines & (1 << FIQ_MAC_GENERAL), "TBTT raised once the TSF crosses a 100 TU boundary")

    print("== power save: doze, buffered unicast, wake at TBTT ==")
    m.write(PL + GEN_INT_ACK, 0xFFFFFFFF, 0)
    for r in (RHD0, RHD1):                         # give the receiver fresh descriptors
        wr(r + 64, struct.pack("<I", 0))
    for b_ in (RBD0, RBD1):
        wr(b_ + 16, struct.pack("<I", 0))
    wr(RHD0 + 4, struct.pack("<I", RHD1)); wr(RHD1 + 4, struct.pack("<I", 0))
    wr(RBD0 + 4, struct.pack("<I", RBD1)); wr(RBD1 + 4, struct.pack("<I", 0))
    m.write(PL + RX_HEADER_HEAD_PTR, RHD0 | 1, 0); m.write(PL + DMA_CNTRL_SET, RX_HEADER_NEW_HEAD, 0)
    m.write(PL + RX_PAYLOAD_HEAD_PTR, RBD0 | 1, 0); m.write(PL + DMA_CNTRL_SET, RX_PAYLOAD_NEW_HEAD, 0)
    t0 = 5 * (2 * 102400 + 100)
    m.tick(t0)
    m.write(CORE + STATE_CNTRL, HW_DOZE << 4, t0)
    uni = bytes.fromhex("08020000c8478c000000020000000001020000000001e000") + b"\xaa\xaa\x03\x00\x00\x00\x08\x00" + bytes(20)
    m.inject(uni, t0 + 5)
    m.inject(bytes.fromhex("80000000ffffffffffff020000000001020000000001") + bytes(40), t0 + 6)
    check(len(m.rx_queue) == 1 and struct.unpack(RHD_FMT, rd(RHD0, 68))[16] == 0,
          "dozing: the unicast frame is buffered (as the AP would), the broadcast one is lost")
    m.tick(5 * (3 * 102400 + 10))
    check(m.state == HW_ACTIVE and m.gen_raw & IMP_PRI_TBTT, "the MAC wakes itself to ACTIVE at the next TBTT")
    check(not m.rx_queue and struct.unpack(RHD_FMT, rd(RHD0, 68))[16] & RX_HD_DONE,
          "and the buffered frame is delivered on waking")

    print("\nAll %d Wi-Fi MAC self-tests passed." % n)
    return n


if __name__ == "__main__":
    _run_selftests()
