"""The other end of the air: a virtual station or access point for the device.

The MAC model (src/wifimac.py) hands over every MPDU the firmware transmits
and takes MPDUs to deliver. This module is the 802.11 peer on the far side:

  * when the device runs an access point (OpenBeken's default open AP, a Tuya
    device in AP pairing mode), the peer is a STATION: it finds the BSS from
    the device's own beacons/probe responses, authenticates (open system),
    associates, and then bridges Ethernet frames between the device and the
    user-mode IP stack (src/netstack.py), which obtains a DHCP lease from the
    device and can open TCP connections into it (e.g. the HTTP panel).

  * when the device runs as a station (a configured OpenBeken, a paired Tuya
    device) the peer is an ACCESS POINT: it beacons the SSID the device is
    looking for, answers probe requests, open-system authentication and
    association, and bridges data frames to the IP stack, which is then the
    device's DHCP server, DNS, NTP and gateway.

The role is picked from what the device does on air (role "auto"): beacons or
probe responses mean the device is an AP; probe requests, authentication or
association requests mean it is a station. Either can be forced.

Every frame crossing the peer can be written to a pcap file (link type 105,
IEEE 802.11 without FCS) so the exchange opens in Wireshark.

As an access point the peer is open, or WPA2-PSK when given a passphrase:
it then advertises RSN and runs the four-way handshake (src/wpa2.py) before
carrying any traffic. As a station it joins open BSSs only; a protected AP
on the device would need key material this peer does not model.
"""
import struct
import time

try:
    from . import wpa2
except ImportError:        # run directly, not as a package
    import wpa2

# frame control subtypes (type in bits 2-3, subtype in bits 4-7)
MGMT_ASSOC_REQ, MGMT_ASSOC_RESP, MGMT_PROBE_REQ, MGMT_PROBE_RESP = 0x0, 0x1, 0x4, 0x5
MGMT_BEACON, MGMT_DISASSOC, MGMT_AUTH, MGMT_DEAUTH, MGMT_ACTION = 0x8, 0xA, 0xB, 0xC, 0xD
DATA_DATA, DATA_NULL, DATA_QOS = 0x0, 0x4, 0x8
FC_TODS, FC_FROMDS, FC_PROTECTED = 0x0100, 0x0200, 0x4000

IE_SSID, IE_RATES, IE_DS, IE_TIM, IE_ERP, IE_EXT_RATES, IE_RSN, IE_HT_CAP, IE_HT_OP = 0, 1, 3, 5, 42, 50, 48, 45, 61
RATES_BG = bytes([0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24])
EXT_RATES_BG = bytes([0x30, 0x48, 0x60, 0x6C])
LLC_SNAP = b"\xaa\xaa\x03\x00\x00\x00"
BCAST = b"\xff" * 6
BEACON_INTERVAL_TU = 100
# SSIDs stock Tuya firmware probes for at boot to detect its production line
# (tuya_main.c "current product ssid name:tuya_mdev_test1").
FACTORY_TEST_SSIDS = ("tuya_mdev_test1", "tuya_mdev_test2")
TU_US = 1024


def mac2str(b):
    return ":".join("%02x" % x for x in b)


def str2mac(s):
    return bytes(int(x, 16) for x in s.replace("-", ":").split(":"))


def ie(eid, payload):
    return bytes([eid, len(payload)]) + payload


def parse_ies(data):
    out = []
    p = 0
    while p + 2 <= len(data):
        eid, ln = data[p], data[p + 1]
        if p + 2 + ln > len(data):
            break
        out.append((eid, data[p + 2:p + 2 + ln]))
        p += 2 + ln
    return out


def ie_get(ies, eid):
    for e, v in ies:
        if e == eid:
            return v
    return None


def fc_fields(frame):
    fc = frame[0] | (frame[1] << 8)
    return (fc >> 2) & 3, (fc >> 4) & 0xF, fc


def hdr_len(fc):
    ftype = (fc >> 2) & 3
    subtype = (fc >> 4) & 0xF
    n = 24
    if ftype == 2:
        if (fc & 0x0300) == 0x0300:
            n += 6
        if subtype & 0x8:
            n += 2
        if fc & 0x8000:
            n += 4
    elif ftype == 1:
        n = 16 if subtype in (0x4, 0x5, 0x6, 0x8, 0x9, 0xA, 0xB) else 10
    elif fc & 0x8000:
        n += 4
    return n


class Pcap:
    """Minimal pcap writer, DLT_IEEE802_11 (105): frames without FCS."""

    def __init__(self, path):
        self.f = open(path, "wb")
        self.f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 105))
        self.f.flush()

    def write(self, frame, us):
        self.f.write(struct.pack("<IIII", us // 1_000_000, us % 1_000_000, len(frame), len(frame)))
        self.f.write(frame)
        self.f.flush()

    def close(self):
        try:
            self.f.close()
        except Exception:
            pass


# The roles a peer can take. auto: the opposite of whatever the device turns
# out to be. The command line's --wifi-peer choices and the GUI's role list
# both come from here.
WIFI_ROLES = ("auto", "sta", "ap")


class WifiPeer:
    """The virtual counterpart on air. role: one of WIFI_ROLES."""

    def __init__(self, mac, netstack, inject, log=None, role="auto", ssid=None, channel=1,
                 pcap=None, now_us=None, bssid=None, latency_us=0, passphrase=None):
        self.mac = mac
        self.net = netstack
        self.inject = inject                     # callback(frame_bytes, decr=None)
        # When set, the access point this peer raises is WPA2-PSK rather than
        # open: it advertises RSN, and a station must complete the four-way
        # handshake before any of its traffic is carried (see src/wpa2.py).
        self.passphrase = passphrase
        self.auth = {}                           # station mac -> Authenticator
        self.log = log or (lambda *a: None)
        self.role = role
        self.active_role = None if role == "auto" else role
        self.ssid = ssid                         # AP role: what we beacon; STA role: what we join (None = first seen)
        self.channel = channel
        self._own_pcap = isinstance(pcap, str)      # opened here, so closed here
        self.pcap = Pcap(pcap) if self._own_pcap else pcap
        self.now_us = now_us or (lambda: 0)
        self.seq = 0
        self.ap_bssid = bssid or mac             # AP role: our BSSID
        # STA role state
        self.bss = None                          # dict(bssid, ssid, channel, rates, caps)
        self.sta_state = "SCAN"
        self.sta_next_us = 0
        self.sta_tries = 0
        self.aid = 0
        # AP role state
        self.stations = {}                       # mac -> dict(state, aid)
        self.next_aid = 1
        self.last_beacon_us = None
        self.tsf_start = None
        self._skipped_factory = set()
        self.stats = {"tx": 0, "rx": 0}
        if self.net is not None:
            self.net.output = self.send_eth
        self.events = []
        # Frames to the device leave after this much device time. A real
        # network is never instant, and firmware relies on that: OpenBeken's
        # MQTT code records "DNS lookup in flight" only AFTER
        # dns_gethostbyname() returns, so a zero-latency reply resolved first
        # and the bookkeeping then overwrote the result - every retry, forever.
        self.latency_us = latency_us
        self._outq = []                          # [(release_us, frame, decr)]

    # --------------------------------------------------------------- helpers
    def _seq(self):
        s = self.seq
        self.seq = (self.seq + 1) & 0xFFF
        return s << 4

    def _send(self, frame, decr=None):
        self.stats["tx"] += 1
        if self.latency_us:
            self._outq.append((self.now_us() + self.latency_us, frame, decr))
            return
        self._deliver(frame, decr)

    def _deliver(self, frame, decr=None):
        if self.pcap:
            self.pcap.write(frame, self.now_us())
        self.inject(frame, decr)

    def _release(self, now):
        if self._outq and self._outq[0][0] <= now:
            due = [(f, d) for t, f, d in self._outq if t <= now]
            self._outq = [(t, f, d) for t, f, d in self._outq if t > now]
            for f, d in due:
                self._deliver(f, d)

    def _mgmt(self, subtype, da, sa, bssid, body):
        fc = (subtype << 4)
        return struct.pack("<HH", fc, 0) + da + sa + bssid + struct.pack("<H", self._seq()) + body

    def _data(self, da, sa, bssid, payload, to_ds):
        if to_ds:
            fc = (2 << 2) | FC_TODS
            a1, a2, a3 = bssid, sa, da
        else:
            fc = (2 << 2) | FC_FROMDS
            a1, a2, a3 = da, bssid, sa
        return struct.pack("<HH", fc, 0) + a1 + a2 + a3 + struct.pack("<H", self._seq()) + payload

    # ---------------------------------------------------- from the IP stack
    def send_eth(self, eth):
        dst, src, etype = eth[:6], eth[6:12], eth[12:14]
        payload = LLC_SNAP + etype + eth[14:]
        if self.active_role == "sta":
            if self.bss is None or self.sta_state != "RUN":
                return
            self._send(self._data(dst, src, self.bss["bssid"], payload, to_ds=True))
        elif self.active_role == "ap":
            if not self.stations and not (dst[0] & 1):
                return
            self._send(self._data(dst, src, self.ap_bssid, payload, to_ds=False),
                       self._decr_for(dst))

    # ------------------------------------------------------ from the device
    def close(self):
        """Release the host side: the network stack's sockets and a capture
        file this peer opened itself."""
        self.net.close()
        if self._own_pcap and self.pcap is not None:
            self.pcap.close()

    def on_device_tx(self, frame, info=None):
        self.stats["rx"] += 1
        if self.pcap:
            self.pcap.write(frame, self.now_us())
        if len(frame) < 24:
            return
        ftype, subtype, fc = fc_fields(frame)
        if ftype == 0:
            self._on_mgmt(subtype, fc, frame)
        elif ftype == 2:
            self._on_data(subtype, fc, frame)

    def _connected(self):
        if self.active_role == "sta":
            return self.sta_state == "RUN"
        if self.active_role == "ap":
            return any(st["state"] == "ASSOC" for st in self.stations.values())
        return False

    def _pick_role(self, role, why):
        # In auto mode the role follows the device until something connects:
        # a stock Tuya image probes as a station for its factory network at
        # boot and only afterwards raises its own pairing AP, so the first
        # guess must not be final.
        if (self.role == "auto" and self.active_role not in (None, role)
                and not self._connected()):
            self.log("[WIFI] device changed role (%s)" % why)
            self.active_role = None
            self.bss = None
            self.sta_state = "SCAN"
            self.stations = {}
        if self.active_role is None:
            self.active_role = role
            self.log("[WIFI] device acts as %s (%s): peer takes the %s role"
                     % ("an access point" if role == "sta" else "a station", why,
                        "station" if role == "sta" else "access point"))
            if self.net is not None:
                self.net.gateway = (role == "ap")
                if role == "ap" and self.net.ip is None:
                    self.net.ip = bytes([192, 168, 1, 1])
                if role == "sta":
                    self.net.ip = None

    def _on_mgmt(self, subtype, fc, frame):
        da, sa, bssid = frame[4:10], frame[10:16], frame[16:22]
        body = frame[24:]
        if subtype in (MGMT_BEACON, MGMT_PROBE_RESP):
            self._pick_role("sta", "it sends %s" % ("beacons" if subtype == MGMT_BEACON else "probe responses"))
            if self.active_role == "sta":
                self._sta_learn_bss(sa, bssid, body, subtype)
            return
        if subtype in (MGMT_PROBE_REQ, MGMT_AUTH, MGMT_ASSOC_REQ) and (self.active_role in (None, "ap")):
            if subtype == MGMT_PROBE_REQ:
                self._pick_role("ap", "it probes for networks")
            else:
                self._pick_role("ap", "it authenticates")
        if self.active_role == "ap":
            self._ap_mgmt(subtype, da, sa, bssid, body)
        elif self.active_role == "sta":
            self._sta_mgmt(subtype, da, sa, bssid, body)

    # ------------------------------------------------------------ STA role
    def _sta_learn_bss(self, sa, bssid, body, subtype):
        if len(body) < 12:
            return
        tsf, bint, caps = struct.unpack("<QHH", body[:12])
        ies = parse_ies(body[12:])
        ssid = ie_get(ies, IE_SSID)
        if ssid is None:
            return
        ssid = ssid.decode("utf-8", "replace")
        ch = ie_get(ies, IE_DS)
        rsn = ie_get(ies, IE_RSN)
        if self.ssid and ssid != self.ssid:
            return
        if self.bss is None:
            self.bss = {"bssid": bssid, "ssid": ssid, "channel": ch[0] if ch else self.channel,
                        "caps": caps, "privacy": bool(caps & 0x10), "rsn": rsn, "bint": bint}
            self.log("[WIFI] found BSS '%s' %s ch %d%s" % (ssid, mac2str(bssid), self.bss["channel"],
                                                           " (privacy)" if self.bss["privacy"] else " (open)"))
            if self.bss["privacy"]:
                self.log("[WIFI] the device's AP requires a cipher; this peer only joins open networks")
            else:
                self.sta_state = "AUTH"
                self.sta_next_us = self.now_us() + 50_000

    def _sta_mgmt(self, subtype, da, sa, bssid, body):
        if self.bss is None or da != self.mac:
            return
        if subtype == MGMT_AUTH and len(body) >= 6:
            alg, seq, status = struct.unpack("<HHH", body[:6])
            if seq == 2 and status == 0 and self.sta_state == "AUTH":
                self.log("[WIFI] authenticated with %s" % mac2str(bssid))
                self.sta_state = "ASSOC"
                self.sta_next_us = self.now_us()
                self._sta_assoc()
            elif status:
                self.log("[WIFI] authentication refused, status %d" % status)
                self.sta_state = "AUTH"
                self.sta_next_us = self.now_us() + 2_000_000
        elif subtype == MGMT_ASSOC_RESP and len(body) >= 6:
            caps, status, aid = struct.unpack("<HHH", body[:6])
            if status == 0 and self.sta_state == "ASSOC":
                self.aid = aid & 0x3FFF
                self.sta_state = "RUN"
                self.log("[WIFI] associated with '%s' (AID %d)" % (self.bss["ssid"], self.aid))
                self.events.append(("assoc", self.now_us()))
                if self.net is not None:
                    self.net.link_up(device_mac=self.bss["bssid"])
            elif status:
                self.log("[WIFI] association refused, status %d" % status)
                self.sta_state = "AUTH"
                self.sta_next_us = self.now_us() + 2_000_000
        elif subtype in (MGMT_DEAUTH, MGMT_DISASSOC):
            reason = struct.unpack("<H", body[:2])[0] if len(body) >= 2 else 0
            self.log("[WIFI] %s from the device, reason %d" % ("deauthenticated" if subtype == MGMT_DEAUTH else "disassociated", reason))
            self.sta_state = "AUTH"
            self.sta_next_us = self.now_us() + 1_000_000

    def _sta_auth(self):
        body = struct.pack("<HHH", 0, 1, 0)
        self._send(self._mgmt(MGMT_AUTH, self.bss["bssid"], self.mac, self.bss["bssid"], body))

    def _sta_assoc(self):
        caps = 0x0421                              # ESS, short preamble, short slot
        ssid = self.bss["ssid"].encode("utf-8")
        body = struct.pack("<HH", caps, 10) + ie(IE_SSID, ssid) + ie(IE_RATES, RATES_BG) + ie(IE_EXT_RATES, EXT_RATES_BG)
        self._send(self._mgmt(MGMT_ASSOC_REQ, self.bss["bssid"], self.mac, self.bss["bssid"], body))

    def _sta_probe(self):
        ssid = (self.ssid or "").encode("utf-8")
        body = ie(IE_SSID, ssid) + ie(IE_RATES, RATES_BG) + ie(IE_EXT_RATES, EXT_RATES_BG)
        self._send(self._mgmt(MGMT_PROBE_REQ, BCAST, self.mac, BCAST, body))

    def _sta_tick(self, now):
        if self.bss is None:
            if now >= self.sta_next_us:
                self._sta_probe()
                self.sta_next_us = now + 1_000_000
            return
        if self.sta_state == "AUTH" and now >= self.sta_next_us:
            self._sta_auth()
            self.sta_tries += 1
            self.sta_next_us = now + 1_000_000
        elif self.sta_state == "ASSOC" and now >= self.sta_next_us + 1_000_000:
            self._sta_assoc()
            self.sta_next_us = now

    # ------------------------------------------------------------- AP role
    # ------------------------------------------------- protected network (WPA2)
    def _eapol_to(self, sta, payload):
        """Send one handshake message to a station, as an ordinary data frame.

        These travel in the clear by definition: they are what establishes the
        key, so they cannot themselves be protected.
        """
        body = LLC_SNAP + struct.pack("!H", wpa2.ETH_EAPOL) + payload
        self._send(self._data(sta, self.mac, self.ap_bssid, body, to_ds=False))

    def _start_handshake(self, sta):
        """Open the four-way handshake with a station that has just associated."""
        auth = wpa2.Authenticator(self.passphrase, self.ssid or "BekenSim",
                                  self.ap_bssid, sta, log=self.log)
        self.auth[sta] = auth
        self.log("[WIFI] station %s associated to a protected network; starting the "
                 "four-way handshake" % mac2str(sta))
        self._eapol_to(sta, auth.start())

    def _on_eapol(self, sta, payload):
        """A handshake message from the station. True if it was consumed here."""
        auth = self.auth.get(sta)
        if auth is None:
            return False
        reply = auth.on_message(payload)
        if reply is not None:
            self._eapol_to(sta, reply)
        if auth.done and sta in self.stations and not self.stations[sta].get("encrypted"):
            self.stations[sta]["encrypted"] = True
            self.log("[WIFI] station %s completed the four-way handshake; the link is "
                     "encrypted and open for traffic" % mac2str(sta))
            self.events.append(("encrypted", self.now_us()))
            if self.net is not None:
                self.net.link_up(device_mac=sta)
        return True

    def _decr_for(self, dst):
        """What the receiving hardware should report about a frame we send.

        On a protected link the device's MAC would have decrypted the frame
        before the firmware ever saw it, so the status says CCMP succeeded;
        a firmware that enforces its own key policy drops anything else.
        """
        if not self.passphrase:
            return None
        if dst[0] & 1:                            # group traffic
            # Only once some station actually holds the group key - i.e. has
            # finished its handshake - not merely because one has started.
            enc = any(s.get("encrypted") for s in self.stations.values())
            return wpa2.DECR_CCMP_SUCCESS if enc else None
        st = self.stations.get(dst)
        return wpa2.DECR_CCMP_SUCCESS if st and st.get("encrypted") else None

    def _ap_caps(self):
        """Capability field: ESS, plus the privacy bit when this network is protected."""
        return 0x0421 | (wpa2.CAP_PRIVACY if self.passphrase else 0)

    def _ap_ies(self, probe=False):
        ssid = (self.ssid or "BekenSim").encode("utf-8")
        ies = ie(IE_SSID, ssid) + ie(IE_RATES, RATES_BG) + ie(IE_DS, bytes([self.channel]))
        if not probe:
            ies += ie(IE_TIM, bytes([0, 1, 0, 0]))
        ies += ie(IE_ERP, b"\x00") + ie(IE_EXT_RATES, EXT_RATES_BG)
        if self.passphrase:
            # Without this a device that stored a protected network sees ours
            # as a different, open one and will not even try to join.
            ies += ie(IE_RSN, wpa2.RSN_IE_BODY)
        return ies

    def _ap_tsf(self, now):
        if self.tsf_start is None:
            self.tsf_start = now
        return now - self.tsf_start

    def _ap_beacon(self, now):
        body = struct.pack("<QHH", self._ap_tsf(now), BEACON_INTERVAL_TU, self._ap_caps()) + self._ap_ies()
        self._send(self._mgmt(MGMT_BEACON, BCAST, self.ap_bssid, self.ap_bssid, body))

    def _ap_mgmt(self, subtype, da, sa, bssid, body):
        now = self.now_us()
        if subtype == MGMT_PROBE_REQ:
            ies = parse_ies(body)
            want = ie_get(ies, IE_SSID)
            if want:
                want = want.decode("utf-8", "replace")
                if self.ssid is None and want in FACTORY_TEST_SSIDS:
                    # Stock Tuya firmware scans for its factory test network
                    # at every boot and, if it is there, switches into
                    # production-test mode (light_prod.c "PROD FACTORY
                    # START"). Answering that by default would change what
                    # the firmware does; it takes an explicit --wifi-ssid.
                    if want not in self._skipped_factory:
                        self._skipped_factory.add(want)
                        self.log("[WIFI] device probes for its factory test network '%s': not "
                                 "answering (pass --wifi-ssid %s to offer it)" % (want, want))
                    return
                if self.ssid is None:
                    self.ssid = want
                    self.log("[WIFI] device probes for '%s': adopting it as our SSID" % want)
                if want != self.ssid:
                    return
            resp = struct.pack("<QHH", self._ap_tsf(now), BEACON_INTERVAL_TU, self._ap_caps()) + self._ap_ies(probe=True)
            self._send(self._mgmt(MGMT_PROBE_RESP, sa, self.ap_bssid, self.ap_bssid, resp))
            return
        if da != self.ap_bssid and da != self.mac:
            return
        if subtype == MGMT_AUTH and len(body) >= 6:
            alg, seq, status = struct.unpack("<HHH", body[:6])
            if alg != 0:
                self.log("[WIFI] device asks for authentication algorithm %d; only open system is offered" % alg)
                resp = struct.pack("<HHH", alg, 2, 13)
            else:
                resp = struct.pack("<HHH", 0, 2, 0)
                self.stations[sa] = {"state": "AUTH", "aid": 0}
                self.log("[WIFI] station %s authenticated (open system)" % mac2str(sa))
            self._send(self._mgmt(MGMT_AUTH, sa, self.ap_bssid, self.ap_bssid, resp))
        elif subtype == MGMT_ASSOC_REQ and len(body) >= 4:
            st = self.stations.get(sa)
            if st is None:
                self._send(self._mgmt(MGMT_DEAUTH, sa, self.ap_bssid, self.ap_bssid, struct.pack("<H", 7)))
                return
            ies = parse_ies(body[4:])
            want = ie_get(ies, IE_SSID)
            rsn = ie_get(ies, IE_RSN)
            status = 0
            if self.passphrase:
                # A protected network: the station must ask for one, and the
                # link stays shut until it proves it holds the passphrase.
                if rsn is None:
                    self.log("[WIFI] station %s asks to join '%s' unprotected, but this "
                             "network is protected" % (mac2str(sa), self.ssid))
                    status = 40
            elif rsn is not None:
                self.log("[WIFI] station %s offers RSN (a cipher) in its association; this open BSS cannot take it" % mac2str(sa))
                status = 40
            st["aid"] = self.next_aid
            self.next_aid += 1
            st["state"] = "ASSOC" if status == 0 else "AUTH"
            resp = struct.pack("<HHH", self._ap_caps(), status, 0xC000 | st["aid"]) + ie(IE_RATES, RATES_BG) + ie(IE_EXT_RATES, EXT_RATES_BG)
            self._send(self._mgmt(MGMT_ASSOC_RESP, sa, self.ap_bssid, self.ap_bssid, resp))
            if status == 0:
                self.log("[WIFI] station %s associated to '%s' (AID %d)" % (mac2str(sa), self.ssid, st["aid"]))
                self.events.append(("assoc", now))
                if self.passphrase:
                    self._start_handshake(sa)
                elif self.net is not None:
                    self.net.link_up(device_mac=sa)
        elif subtype in (MGMT_DEAUTH, MGMT_DISASSOC):
            if sa in self.stations:
                reason = struct.unpack("<H", body[:2])[0] if len(body) >= 2 else 0
                self.log("[WIFI] station %s left (%s, reason %d)" % (mac2str(sa), "deauth" if subtype == MGMT_DEAUTH else "disassoc", reason))
                self.stations.pop(sa, None)
        elif subtype == MGMT_ACTION and body:
            if body[0] == 3 and len(body) > 1 and body[1] == 0:
                # ADDBA request: decline, so the device never aggregates
                token = body[2] if len(body) > 2 else 0
                params = struct.unpack("<H", body[3:5])[0] if len(body) >= 5 else 0
                resp = bytes([3, 1, token]) + struct.pack("<HHH", 37, params, 0)
                self._send(self._mgmt(MGMT_ACTION, sa, self.ap_bssid, self.ap_bssid, resp))

    def _ap_tick(self, now):
        if self.last_beacon_us is None or now - self.last_beacon_us >= BEACON_INTERVAL_TU * TU_US:
            self.last_beacon_us = now
            self._ap_beacon(now)

    # -------------------------------------------------------------- data
    def _on_data(self, subtype, fc, frame):
        if subtype & 0x4:                               # null / QoS null: keep-alive
            return
        hl = hdr_len(fc)
        if len(frame) < hl + 8:
            return
        to_ds, from_ds = bool(fc & FC_TODS), bool(fc & FC_FROMDS)
        a1, a2, a3 = frame[4:10], frame[10:16], frame[16:22]
        if self.active_role == "ap":
            if not to_ds:
                return
            sa, da = a2, a3
            if a2 not in self.stations or self.stations[a2]["state"] != "ASSOC":
                return
        elif self.active_role == "sta":
            if not from_ds:
                return
            da, sa = a1, a3
            if da != self.mac and not (da[0] & 1):
                return
        else:
            return
        body = frame[hl:]
        if body[:6] != LLC_SNAP:
            return
        etype = body[6:8]
        # Handshake traffic is ours to answer, and must never be handed to the
        # IP stack: it is how the link gets its key, not traffic on the link.
        # So it stops here whether or not we had an Authenticator for the
        # sender - an EAPOL frame is never IP traffic to forward.
        if (self.active_role == "ap" and self.passphrase
                and struct.unpack("!H", etype)[0] == wpa2.ETH_EAPOL):
            self._on_eapol(sa, body[8:])
            return
        eth = da + sa + etype + body[8:]
        if self.net is not None:
            self.net.input(eth)

    # ------------------------------------------------------------------ tick
    def tick(self, insns=None):
        now = self.now_us()
        self._release(now)
        if self.active_role == "sta":
            self._sta_tick(now)
        elif self.active_role == "ap":
            self._ap_tick(now)
        elif self.role == "auto" and self.ssid:
            # nothing heard yet but an SSID was given: start beaconing it so a
            # station firmware that scans passively finds us
            if now > 2_000_000:
                self._pick_role("ap", "an SSID was configured")
        if self.net is not None:
            self.net.tick(now)


# ---------------------------------------------------------------------------
# Self-tests. Run: python src/wifipeer.py
# ---------------------------------------------------------------------------
def _run_selftests():
    n = 0

    def check(cond, msg):
        nonlocal n
        assert cond, "FAIL: " + msg
        n += 1
        print("  [PASS]", msg)

    class FakeNet:
        def __init__(self):
            self.gateway = True; self.ip = None; self.frames = []; self.up = None; self.output = None
        def input(self, eth): self.frames.append(eth)
        def link_up(self, device_mac=None): self.up = device_mac
        def tick(self, now): pass
        def close(self): self.closed = True

    clock = [0]
    sent = []
    net = FakeNet()
    p = WifiPeer(str2mac("02:00:00:00:00:01"), net, lambda f, d=None, _s=sent: _s.append(f), log=lambda *a: None, now_us=lambda: clock[0])
    dev = str2mac("c8:47:8c:00:00:01")

    print("== STA role: device beacons an open AP ==")
    beacon = p._mgmt(MGMT_BEACON, BCAST, dev, dev, struct.pack("<QHH", 0, 100, 0x0421) + ie(IE_SSID, b"OpenBK7231T_8C000000") + ie(IE_RATES, RATES_BG) + ie(IE_DS, b"\x01"))
    p.on_device_tx(beacon)
    check(p.active_role == "sta" and p.bss and p.bss["ssid"] == "OpenBK7231T_8C000000", "beacon -> peer becomes a station, BSS learned")
    clock[0] = 100_000
    p.tick()
    check(sent and fc_fields(sent[-1])[1] == MGMT_AUTH, "authentication request sent")
    auth_ok = p._mgmt(MGMT_AUTH, p.mac, dev, dev, struct.pack("<HHH", 0, 2, 0))
    p.on_device_tx(auth_ok)
    check(fc_fields(sent[-1])[1] == MGMT_ASSOC_REQ and p.sta_state == "ASSOC", "auth response -> association request")
    assoc_ok = p._mgmt(MGMT_ASSOC_RESP, p.mac, dev, dev, struct.pack("<HHH", 0x0421, 0, 0xC001))
    p.on_device_tx(assoc_ok)
    check(p.sta_state == "RUN" and net.up == dev and p.aid == 1, "association response -> RUN, IP stack told the link is up")
    eth = BCAST + p.mac + b"\x08\x06" + bytes(28)
    p.send_eth(eth)
    f = sent[-1]
    check(fc_fields(f)[0] == 2 and (f[1] & 1) and f[4:10] == dev and f[16:22] == BCAST and f[24:30] == LLC_SNAP, "Ethernet -> ToDS data frame with LLC/SNAP")
    down = p._data(p.mac, dev, dev, LLC_SNAP + b"\x08\x00" + b"IPDATA", to_ds=False)
    p.on_device_tx(down)
    check(net.frames and net.frames[-1] == p.mac + dev + b"\x08\x00" + b"IPDATA", "FromDS data frame -> Ethernet into the IP stack")

    print("== AP role: device probes and joins ==")
    sent2 = []
    net2 = FakeNet()
    q = WifiPeer(str2mac("02:00:00:00:00:02"), net2, lambda f, d=None, _s=sent2: _s.append(f), log=lambda *a: None, now_us=lambda: clock[0])
    probe = q._mgmt(MGMT_PROBE_REQ, BCAST, dev, BCAST, ie(IE_SSID, b"HomeNet") + ie(IE_RATES, RATES_BG))
    q.on_device_tx(probe)
    check(q.active_role == "ap" and q.ssid == "HomeNet", "probe request -> peer becomes an AP and adopts the SSID")
    sent3 = []
    t = WifiPeer(str2mac("02:00:00:00:00:03"), FakeNet(), lambda f, d=None, _s=sent3: _s.append(f), log=lambda *a: None, now_us=lambda: clock[0])
    t.on_device_tx(t._mgmt(MGMT_PROBE_REQ, BCAST, dev, BCAST, ie(IE_SSID, b"tuya_mdev_test1") + ie(IE_RATES, RATES_BG)))
    check(t.ssid is None and not sent3, "Tuya factory-test SSID is not adopted or answered by default")
    t2 = WifiPeer(str2mac("02:00:00:00:00:04"), FakeNet(), lambda f, d=None, _s=sent3: _s.append(f), log=lambda *a: None, now_us=lambda: clock[0],
                  role="ap", ssid="tuya_mdev_test1")
    t2.on_device_tx(t2._mgmt(MGMT_PROBE_REQ, BCAST, dev, BCAST, ie(IE_SSID, b"tuya_mdev_test1") + ie(IE_RATES, RATES_BG)))
    check(sent3 and fc_fields(sent3[-1])[1] == MGMT_PROBE_RESP, "...but answered when given explicitly as --wifi-ssid")
    sent4 = []
    r = WifiPeer(str2mac("02:00:00:00:00:05"), FakeNet(), lambda f, d=None, _s=sent4: _s.append(f), log=lambda *a: None, now_us=lambda: clock[0])
    r.on_device_tx(r._mgmt(MGMT_PROBE_REQ, BCAST, dev, BCAST, ie(IE_SSID, b"tuya_mdev_test1") + ie(IE_RATES, RATES_BG)))
    check(r.active_role == "ap", "auto: a boot-time probe makes the peer an AP first")
    r.on_device_tx(r._mgmt(MGMT_BEACON, BCAST, dev, dev, struct.pack("<QHH", 0, 100, 0x0421)
                           + ie(IE_SSID, b"SmartLife-E9FF") + ie(IE_RATES, RATES_BG) + ie(IE_DS, b"\x06")))
    check(r.active_role == "sta" and r.bss and r.bss["ssid"] == "SmartLife-E9FF",
          "auto: the device raising its own AP afterwards flips the peer to station and it finds the BSS")
    check(sent2 and fc_fields(sent2[-1])[1] == MGMT_PROBE_RESP, "probe response sent")
    q.on_device_tx(q._mgmt(MGMT_AUTH, q.mac, dev, q.mac, struct.pack("<HHH", 0, 1, 0)))
    r = sent2[-1]
    check(fc_fields(r)[1] == MGMT_AUTH and struct.unpack("<HHH", r[24:30]) == (0, 2, 0), "open-system auth answered seq 2 status 0")
    q.on_device_tx(q._mgmt(MGMT_ASSOC_REQ, q.mac, dev, q.mac, struct.pack("<HH", 0x0421, 10) + ie(IE_SSID, b"HomeNet") + ie(IE_RATES, RATES_BG)))
    r = sent2[-1]
    check(fc_fields(r)[1] == MGMT_ASSOC_RESP and struct.unpack("<HHH", r[24:30])[1] == 0 and net2.up == dev, "association accepted, link up")
    clock[0] = 300_000
    q.tick()
    check(any(fc_fields(x)[1] == MGMT_BEACON for x in sent2), "AP beacons")
    up = q._data(BCAST, dev, q.mac, LLC_SNAP + b"\x08\x06" + b"ARP", to_ds=True)
    q.on_device_tx(up)
    check(net2.frames and net2.frames[-1][12:14] == b"\x08\x06", "ToDS data from the associated station reaches the IP stack")
    net2.output = None
    q.send_eth(dev + q.mac + b"\x08\x00" + b"X")
    f = sent2[-1]
    check((f[1] & 2) and f[4:10] == dev and f[10:16] == q.mac, "Ethernet -> FromDS data frame to the station")

    print("== latency: frames reach the device after a delay ==")
    clk = [0]
    got = []
    lp = WifiPeer(str2mac("02:00:00:00:00:06"), FakeNet(), lambda f, d=None, _s=got: _s.append(f), log=lambda *a: None,
                  now_us=lambda: clk[0], role="ap", ssid="Lat", latency_us=3000)
    lp.on_device_tx(lp._mgmt(MGMT_PROBE_REQ, BCAST, dev, BCAST, ie(IE_SSID, b"Lat") + ie(IE_RATES, RATES_BG)))
    check(not got, "probe response held back at first")
    clk[0] = 2999
    lp.tick()
    check(not [f for f in got if fc_fields(f)[1] == MGMT_PROBE_RESP], "...still held 1 us before the latency")
    clk[0] = 3000
    lp.tick()
    check(any(fc_fields(f)[1] == MGMT_PROBE_RESP for f in got), "...and delivered once it has passed")

    print("== pcap: both directions recorded, readable back ==")
    import os
    import tempfile
    fd, cap = tempfile.mkstemp(suffix=".pcap")
    os.close(fd)
    try:
        clk2 = [1_500_000]
        got2 = []
        cp = WifiPeer(str2mac("02:00:00:00:00:07"), FakeNet(), lambda f, d=None, _s=got2: _s.append(f), log=lambda *a: None,
                      now_us=lambda: clk2[0], role="ap", ssid="Cap", pcap=cap, latency_us=3000)
        probe2 = cp._mgmt(MGMT_PROBE_REQ, BCAST, dev, BCAST, ie(IE_SSID, b"Cap") + ie(IE_RATES, RATES_BG))
        cp.on_device_tx(probe2)
        clk2[0] = 1_503_000
        cp.tick()
        cp.close()
        check(cp.net.closed and cp.pcap.f.closed,
              "close() releases the network's host side and the capture file the peer opened")
        with open(cap, "rb") as fh:
            raw = fh.read()
        shared = Pcap(cap)
        sp = WifiPeer(str2mac("02:00:00:00:00:08"), FakeNet(), lambda f, d=None: None, pcap=shared)
        sp.close()
        check(not shared.f.closed, "...but leaves a capture it was handed to whoever opened it")
        shared.close()
    finally:
        os.remove(cap)
    magic, vmaj, vmin, _, _, snap, link = struct.unpack("<IHHiIII", raw[:24])
    check((magic, vmaj, vmin, link) == (0xA1B2C3D4, 2, 4, 105) and snap >= 2346,
          "global header: pcap 2.4, link type 105 (802.11 without FCS), snap length fits any MPDU")
    recs, off = [], 24
    while off + 16 <= len(raw):
        sec, usec, incl, orig = struct.unpack("<IIII", raw[off:off + 16])
        recs.append((sec * 1_000_000 + usec, incl, orig, raw[off + 16:off + 16 + incl]))
        off += 16 + incl
    check(recs and off == len(raw) and all(i == o == len(b) for _, i, o, b in recs),
          "records parse back to back; captured length = frame length (nothing truncated)")
    check(recs[0][0] == 1_500_000 and recs[0][3] == probe2,
          "the device's frame is recorded byte for byte, stamped with the time it was sent")
    resp = [r for r in recs[1:] if fc_fields(r[3])[1] == MGMT_PROBE_RESP]
    check(resp and resp[0][0] == 1_503_000 and resp[0][3] in got2,
          "the peer's reply is recorded as delivered, stamped when the device received it (after the latency)")

    print("\nAll %d Wi-Fi peer self-tests passed." % n)
    return n


if __name__ == "__main__":
    _run_selftests()
