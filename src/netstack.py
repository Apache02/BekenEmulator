"""A small user-mode IP network for the emulated device.

The device's own LwIP talks Ethernet frames (inside 802.11 data frames) to
"the network". This module is that network: it answers ARP, hands out or
obtains a DHCP lease, answers pings, proxies DNS, serves NTP, and terminates
or relays TCP and UDP - the way a user-mode NAT (slirp) does for a VM, with
nothing installed on the host and no privileges. Everything in here is plain
Python sockets; the host OS never sees the device's addresses.

Two policies decide what happens to the device's outbound traffic:

  offline (default)  nothing leaves the host. DNS names resolve to private
                     sinkhole addresses (one per name, so a later TCP connect
                     can be logged by hostname), TCP connections are accepted
                     and whatever the firmware sends is captured - HTTP
                     request lines and TLS server names are printed, the
                     bytes go to the pcap - then closed; NTP is answered with
                     the host clock so the firmware gets a valid time.
  online (--net-out) DNS resolves for real and TCP/UDP flows are relayed to
                     the real destinations through host sockets.

Inbound: --net-forward LPORT:DPORT listens on 127.0.0.1:LPORT and opens a TCP
connection from this network into the device at DPORT, so a browser on the
host reaches the firmware's own HTTP server.

Time: the stack's own timers run on DEVICE time (the emulator's instruction
count), like the firmware; host sockets are serviced from a helper thread
that only moves bytes in and out of queues.
"""
import hashlib
import hmac
import os
import select
import socket
import struct
import threading
import time
import collections

ETH_IP, ETH_ARP = 0x0800, 0x0806
IP_ICMP, IP_TCP, IP_UDP = 1, 6, 17
BCAST_MAC = b"\xff" * 6

TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK = 0x01, 0x02, 0x04, 0x08, 0x10
MSS = 1400
RCV_WINDOW = 16384
RETRANSMIT_US = 1_000_000           # device microseconds before we resend unacked data
SYN_MAX_TRIES = 6                   # SYN resends before a connection attempt is abandoned
CAPTURE_IDLE_US = 3_000_000         # offline TCP capture: close this long after the last byte
CAPTURE_LIMIT = 4096                # bytes of a captured flow kept for decoding
HTTP_METHODS = (b"GET", b"POST", b"PUT", b"HEAD", b"DELETE", b"OPTIONS", b"PATCH")
STATIC_FALLBACK_US = 12_000_000     # station side: give up on DHCP after this and pick an address
# Gateway addresses Beken soft-APs come up with: the SDK/OpenBeken default
# (APP_DRONE_DEF_NET_IP) first, then the usual consumer-router ones.
SOFTAP_GUESSES = tuple(bytes(int(x) for x in a.split(".")) for a in (
    "192.168.4.1", "192.168.175.1", "192.168.0.1", "192.168.1.1", "10.0.0.1"))


def ip2str(b):
    return "%d.%d.%d.%d" % tuple(b)


def str2ip(s):
    return bytes(int(x) for x in s.split("."))


def mac2str(b):
    return ":".join("%02x" % x for x in b)


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def ipv4_packet(src, dst, proto, payload, ident=0, ttl=64):
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, 0, ttl, proto, 0, src, dst)
    hdr = hdr[:10] + struct.pack("!H", checksum(hdr)) + hdr[12:]
    return hdr + payload


def l4_checksum(src, dst, proto, segment):
    pseudo = src + dst + struct.pack("!BBH", 0, proto, len(segment))
    return checksum(pseudo + segment)


def udp_packet(src, dst, sport, dport, payload):
    seg = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    c = l4_checksum(src, dst, IP_UDP, seg) or 0xFFFF
    seg = seg[:6] + struct.pack("!H", c) + seg[8:]
    return ipv4_packet(src, dst, IP_UDP, seg)


def tcp_segment(src, dst, sport, dport, seq, ack, flags, window, payload=b"", options=b""):
    doff = (20 + len(options)) // 4
    seg = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
                      doff << 4, flags, window, 0, 0) + options + payload
    c = l4_checksum(src, dst, IP_TCP, seg)
    seg = seg[:16] + struct.pack("!H", c) + seg[18:]
    return ipv4_packet(src, dst, IP_TCP, seg)


def eth_frame(dst, src, ethertype, payload):
    return dst + src + struct.pack("!H", ethertype) + payload


# ---------------------------------------------------------------- decoders
def dns_name(data, off):
    """Decode a DNS name at off; returns (name, next_off)."""
    labels = []
    jumped = False
    nxt = None
    guard = 0
    while guard < 64:
        guard += 1
        if off >= len(data):
            break
        n = data[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:
            ptr = ((n & 0x3F) << 8) | data[off + 1]
            if not jumped:
                nxt = off + 2
            jumped = True
            off = ptr
            continue
        labels.append(data[off + 1:off + 1 + n].decode("ascii", "replace"))
        off += 1 + n
    return ".".join(labels), (nxt if nxt is not None else off)


def tls_sni(payload):
    """Server name from a TLS ClientHello, or None."""
    try:
        if len(payload) < 6 or payload[0] != 0x16 or payload[5] != 0x01:
            return None
        p = 5 + 4 + 2 + 32              # record hdr, handshake hdr, version, random
        sid = payload[p]; p += 1 + sid
        cs = struct.unpack("!H", payload[p:p + 2])[0]; p += 2 + cs
        cm = payload[p]; p += 1 + cm
        ext_len = struct.unpack("!H", payload[p:p + 2])[0]; p += 2
        end = p + ext_len
        while p + 4 <= end:
            et, el = struct.unpack("!HH", payload[p:p + 4]); p += 4
            if et == 0:
                q = p + 2
                while q + 3 <= p + el:
                    nt, nl = payload[q], struct.unpack("!H", payload[q + 1:q + 3])[0]
                    if nt == 0:
                        return payload[q + 3:q + 3 + nl].decode("ascii", "replace")
                    q += 3 + nl
            p += el
    except Exception:
        return None
    return None


def mqtt_connect_info(data):
    """'MQTT CONNECT ...' summary if data starts with an MQTT CONNECT packet, else None."""
    if len(data) < 12 or data[0] != 0x10:
        return None
    # Remaining length is a 1-4 byte varint after the fixed header byte.
    p = 1
    while p < 5 and data[p] & 0x80:
        p += 1
    p += 1
    name_len = int.from_bytes(data[p:p + 2], "big")
    name = data[p + 2:p + 2 + name_len]
    if name not in (b"MQTT", b"MQIsdp"):
        return None
    q = p + 2 + name_len
    if q + 6 > len(data):
        return "MQTT CONNECT"
    level, flags = data[q], data[q + 1]
    keepalive = int.from_bytes(data[q + 2:q + 4], "big")
    cid_len = int.from_bytes(data[q + 4:q + 6], "big")
    cid = data[q + 6:q + 6 + cid_len].decode("utf-8", "replace")
    extra = []
    if flags & 0x80:
        extra.append("username")
    if flags & 0x40:
        extra.append("password")
    if flags & 0x04:
        extra.append("will")
    return "MQTT CONNECT (v%s, client id '%s', keepalive %ds%s)" % (
        {3: "3.1", 4: "3.1.1", 5: "5"}.get(level, level), cid, keepalive,
        (", with " + "/".join(extra)) if extra else "")


# Tuya's LAN protocol. A Tuya device announces itself on these UDP ports every
# few seconds once it has an address, so this broadcast is the first thing a
# stock dump says about itself: its cloud gateway id and product key. Protocol
# 3.1 sends the JSON in clear on 6666; 3.3 encrypts it with one well-known key
# (the md5 below) that is the same in every Tuya device, so the announcement is
# readable without knowing anything about this particular unit.
TUYA_LAN_PORTS = (6666, 6667)
TUYA_PREFIX = b"\x00\x00\x55\xaa"
TUYA_SUFFIX = b"\x00\x00\xaa\x55"
# Protocol 3.4/3.5 reframed the same announcement and encrypts it with AES-GCM
# under the device's OWN key rather than the shared one, so its contents cannot
# be read here. It is still worth naming rather than printing as random bytes.
TUYA_PREFIX_35 = b"\x00\x00\x66\x99"
TUYA_SUFFIX_35 = b"\x00\x00\x99\x66"
TUYA_BROADCAST_KEY = hashlib.md5(b"yGAdlopoPVldABfn").digest()


# TLS cipher suites worth naming. Tuya's devices talk to their cloud over
# TLS-PSK: there is no certificate and no server name, the two sides already
# share a secret from provisioning. That is why a device's cloud connection
# offers only these suites, and why the identity it claims is readable.
TLS_PSK_SUITES = {
    0x008A: "TLS_PSK_WITH_RC4_128_SHA",
    0x008B: "TLS_PSK_WITH_3DES_EDE_CBC_SHA",
    0x008C: "TLS_PSK_WITH_AES_128_CBC_SHA",
    0x008D: "TLS_PSK_WITH_AES_256_CBC_SHA",
    0x00A8: "TLS_PSK_WITH_AES_128_GCM_SHA256",
    0x00AE: "TLS_PSK_WITH_AES_128_CBC_SHA256",
    0x00AF: "TLS_PSK_WITH_AES_256_CBC_SHA384",
    0xC0A4: "TLS_PSK_WITH_AES_128_CCM",
    0xC0A8: "TLS_PSK_WITH_AES_128_CCM_8",
}
TLS_VERSIONS = {0x0301: "1.0", 0x0302: "1.1", 0x0303: "1.2", 0x0304: "1.3"}

TLS12 = b"\x03\x03"
TLS_PSK_AES_128_GCM_SHA256 = 0x00A8
TLS_EXT_EXTENDED_MASTER_SECRET = 0x0017
TLS_MAX_PLAINTEXT = 1 << 14
TLS_MAX_CIPHERTEXT = TLS_MAX_PLAINTEXT + 2048
TLS_MAX_FRAGMENT_LENGTHS = {1: 512, 2: 1024, 3: 2048, 4: 4096}


class TLSProtocolError(ValueError):
    """A malformed, unexpected, or unauthenticated TLS record.

    The exception deliberately carries no key-dependent detail.  Callers may
    report the generic failure, but must never turn candidate PSKs into log
    messages while diagnosing it.
    """


def tls12_prf(secret, label, seed, length):
    """TLS 1.2 PRF using SHA-256 (RFC 5246 section 5)."""
    secret, label, seed = bytes(secret), bytes(label), bytes(seed)
    out = bytearray()
    prf_seed = label + seed
    a = hmac.new(secret, prf_seed, hashlib.sha256).digest()
    while len(out) < length:
        out.extend(hmac.new(secret, a + prf_seed, hashlib.sha256).digest())
        a = hmac.new(secret, a, hashlib.sha256).digest()
    return bytes(out[:length])


def tls_psk_premaster(psk):
    """Plain-PSK premaster secret from RFC 4279 section 2."""
    psk = bytes(psk)
    if not psk or len(psk) > 0xFFFF:
        raise TLSProtocolError("invalid TLS PSK length")
    size = struct.pack("!H", len(psk))
    return size + bytes(len(psk)) + size + psk


class TLS12PSKGCMServer:
    """The encrypted half of a TLS 1.2 plain-PSK server handshake.

    This intentionally implements one suite: TLS_PSK_WITH_AES_128_GCM_SHA256,
    with Extended Master Secret.  Candidate keys stay opaque.  Each candidate
    is tried against the authenticated client Finished record and only the one
    that verifies is retained indirectly, as the derived traffic keys.  The
    PSK itself is then discarded.
    """

    def __init__(self, psks, client_random, server_random,
                 client_hello, server_handshakes,
                 max_plaintext=TLS_MAX_PLAINTEXT,
                 tuya_legacy_identity_psk=False):
        candidates = []
        for psk in psks:
            if not isinstance(psk, (bytes, bytearray, memoryview)):
                raise TypeError("TLS PSK candidates must be byte strings")
            psk = bytes(psk)
            if psk and len(psk) <= 0xFFFF:
                candidates.append(psk)
        if not candidates:
            raise TLSProtocolError("no usable TLS PSK candidates")
        if len(client_random) != 32 or len(server_random) != 32:
            raise TLSProtocolError("TLS randoms must be 32 bytes")
        if not (client_hello[:1] == b"\x01" and server_handshakes[:1] == b"\x02"):
            raise TLSProtocolError("incomplete TLS handshake transcript")
        if not 1 <= max_plaintext <= TLS_MAX_PLAINTEXT:
            raise TLSProtocolError("invalid TLS plaintext limit")

        self._psks = tuple(candidates)
        self._tuya_legacy_identity_psk = bool(tuya_legacy_identity_psk)
        self.client_random = bytes(client_random)
        self.server_random = bytes(server_random)
        self.transcript = bytearray(client_hello + server_handshakes)
        self.state = "client_key_exchange"
        self.client_seq = 0
        self.server_seq = 0
        self.client_key = self.server_key = None
        self.client_iv = self.server_iv = None
        self.max_plaintext = max_plaintext

    @staticmethod
    def _decrypt(key, implicit_iv, seq, content_type, version, fragment):
        if (len(version) != 2 or len(fragment) < 8 + 16
                or len(fragment) > TLS_MAX_CIPHERTEXT):
            raise TLSProtocolError("malformed encrypted TLS record")
        explicit, sealed = fragment[:8], fragment[8:]
        ciphertext, tag = sealed[:-16], sealed[-16:]
        aad = struct.pack("!Q", seq) + bytes([content_type]) + version + struct.pack("!H", len(ciphertext))
        try:
            from Crypto.Cipher import AES
            cipher = AES.new(key, AES.MODE_GCM, nonce=implicit_iv + explicit, mac_len=16)
            cipher.update(aad)
            return cipher.decrypt_and_verify(ciphertext, tag)
        except (ImportError, ValueError, KeyError) as exc:
            raise TLSProtocolError("TLS record authentication failed") from exc

    @staticmethod
    def _encrypt(key, implicit_iv, seq, content_type, version, plaintext):
        if len(version) != 2 or len(plaintext) > TLS_MAX_PLAINTEXT:
            raise TLSProtocolError("invalid TLS record plaintext")
        # RFC 5288 leaves construction of the 8-byte explicit part to the
        # implementation.  The record sequence number is deterministic and
        # unique within this traffic-key epoch, which satisfies its MUST.
        seq_bytes = struct.pack("!Q", seq)
        explicit = seq_bytes
        aad = seq_bytes + bytes([content_type]) + version + struct.pack("!H", len(plaintext))
        try:
            from Crypto.Cipher import AES
            cipher = AES.new(key, AES.MODE_GCM, nonce=implicit_iv + explicit, mac_len=16)
            cipher.update(aad)
            ciphertext, tag = cipher.encrypt_and_digest(bytes(plaintext))
        except ImportError as exc:
            raise TLSProtocolError("AES-GCM support is unavailable") from exc
        fragment = explicit + ciphertext + tag
        return bytes([content_type]) + version + struct.pack("!H", len(fragment)) + fragment

    def add_client_key_exchange(self, message):
        """Add the complete ClientKeyExchange handshake message."""
        if self.state != "client_key_exchange" or len(message) < 6 or message[0] != 0x10:
            raise TLSProtocolError("unexpected TLS ClientKeyExchange")
        declared = int.from_bytes(message[1:4], "big")
        if declared != len(message) - 4:
            raise TLSProtocolError("malformed TLS ClientKeyExchange")
        ident_len = struct.unpack("!H", message[4:6])[0]
        if ident_len != len(message) - 6:
            raise TLSProtocolError("malformed TLS PSK identity")
        self.transcript.extend(message)
        self.state = "change_cipher_spec"
        identity = bytes(message[6:])
        # A legacy Tuya PSK-only/bootstrap path configures one embedded value
        # as both its key and its clear identity. Trial it only for the exact
        # observed 32-byte alphanumeric shape and only when the caller opted
        # into that Tuya compatibility mode. Matching the shape does not admit
        # a session: finish() must still authenticate the encrypted Finished.
        if (self._tuya_legacy_identity_psk and len(identity) == 32
                and identity.isalnum() and identity not in self._psks):
            self._psks += (identity,)
        return identity

    def change_cipher_spec(self, payload):
        if self.state != "change_cipher_spec" or payload != b"\x01":
            raise TLSProtocolError("unexpected TLS ChangeCipherSpec")
        self.state = "client_finished"

    def _candidate_schedule(self, psk):
        premaster = tls_psk_premaster(psk)
        session_hash = hashlib.sha256(self.transcript).digest()
        master = tls12_prf(premaster, b"extended master secret", session_hash, 48)
        block = tls12_prf(master, b"key expansion",
                          self.server_random + self.client_random, 40)
        return master, block[:16], block[16:32], block[32:36], block[36:40]

    def finish(self, version, fragment):
        """Authenticate client Finished and return server CCS + Finished."""
        if self.state != "client_finished":
            raise TLSProtocolError("unexpected TLS Finished")

        selected = None
        transcript_hash = hashlib.sha256(self.transcript).digest()
        for psk in self._psks:
            master, ckey, skey, civ, siv = self._candidate_schedule(psk)
            try:
                plain = self._decrypt(ckey, civ, 0, 0x16, version, fragment)
            except TLSProtocolError:
                continue
            expected = (b"\x14\x00\x00\x0c"
                        + tls12_prf(master, b"client finished", transcript_hash, 12))
            if hmac.compare_digest(plain, expected):
                selected = (master, ckey, skey, civ, siv, plain)
                break
        # Candidate secrets are no longer useful after this decision.  Do not
        # retain wrong keys (or the selected PSK itself) in the live session.
        self._psks = ()
        self._tuya_legacy_identity_psk = False
        if selected is None:
            raise TLSProtocolError("TLS Finished authentication failed")

        master, self.client_key, self.server_key, self.client_iv, self.server_iv, plain = selected
        self.client_seq = 1
        self.transcript.extend(plain)
        server_verify = tls12_prf(
            master, b"server finished", hashlib.sha256(self.transcript).digest(), 12)
        server_finished = b"\x14\x00\x00\x0c" + server_verify
        encrypted = self._encrypt(self.server_key, self.server_iv, 0, 0x16,
                                  TLS12, server_finished)
        self.server_seq = 1
        self.state = "established"
        return b"\x14\x03\x03\x00\x01\x01" + encrypted

    @property
    def established(self):
        return self.state == "established"

    def clear_secrets(self):
        """Drop every credential/traffic-key reference when a run closes."""
        self._psks = ()
        self._tuya_legacy_identity_psk = False
        self.client_key = self.server_key = None
        self.client_iv = self.server_iv = None
        self.transcript.clear()
        self.state = "closed"

    def decrypt_record(self, content_type, version, fragment):
        if not self.established:
            raise TLSProtocolError("TLS application record before Finished")
        plain = self._decrypt(self.client_key, self.client_iv, self.client_seq,
                              content_type, version, fragment)
        if len(plain) > self.max_plaintext:
            raise TLSProtocolError("TLS plaintext exceeds negotiated fragment limit")
        self.client_seq += 1
        return plain

    def encrypt_record(self, content_type, plaintext, version=TLS12):
        if not self.established:
            raise TLSProtocolError("TLS application record before Finished")
        if len(plaintext) > self.max_plaintext:
            raise TLSProtocolError("TLS plaintext exceeds negotiated fragment limit")
        record = self._encrypt(self.server_key, self.server_iv, self.server_seq,
                               content_type, version, plaintext)
        self.server_seq += 1
        return record

    def encrypt_records(self, content_type, plaintext, version=TLS12):
        """Encrypt plaintext across records respecting max_fragment_length."""
        plaintext = bytes(plaintext)
        if not plaintext:
            return self.encrypt_record(content_type, b"", version)
        out = bytearray()
        for off in range(0, len(plaintext), self.max_plaintext):
            out.extend(self.encrypt_record(
                content_type, plaintext[off:off + self.max_plaintext], version))
        return bytes(out)


def tls_client_hello(data):
    """What a TLS ClientHello says in clear, or None if this is not one.

    Returns the record version, the offered cipher suites, the server name if
    the client sent one, and which of the suites are pre-shared-key ones.
    Nothing here is decryption: a ClientHello is sent before any key exchange,
    so all of it is on the wire in the open.
    """
    try:
        if len(data) < 45 or data[0] != 0x16 or data[5] != 0x01:
            return None
        record_len = struct.unpack("!H", data[3:5])[0]
        if (len(data) < 5 + record_len or record_len < 4
                or record_len > TLS_MAX_PLAINTEXT):
            return None
        handshake_len = int.from_bytes(data[6:9], "big")
        if handshake_len + 4 > record_len:
            return None
        handshake_end = 9 + handshake_len
        ver = struct.unpack("!H", data[9:11])[0]
        random = bytes(data[11:43])
        p = 11 + 32                             # past version and random
        p += 1 + data[p]                        # session id
        if p + 2 > handshake_end:
            return None
        cs_len = struct.unpack("!H", data[p:p + 2])[0]
        if cs_len % 2:
            return None
        p += 2
        if p + cs_len + 1 > handshake_end:
            return None
        suites = [struct.unpack("!H", data[p + i:p + i + 2])[0] for i in range(0, cs_len, 2)]
        p += cs_len
        p += 1 + data[p]                        # compression methods
        if p > handshake_end:
            return None
        exts = {}
        if p + 2 <= handshake_end:
            ext_len = struct.unpack("!H", data[p:p + 2])[0]
            p += 2
            if p + ext_len != handshake_end:
                return None
            end = p + ext_len
            while p + 4 <= end:
                et, el = struct.unpack("!HH", data[p:p + 4])
                if p + 4 + el > end:
                    return None
                if et in exts:
                    return None
                exts[et] = data[p + 4:p + 4 + el]
                p += 4 + el
            if p != end:
                return None
        elif p != handshake_end:
            return None
        return {"version": TLS_VERSIONS.get(ver, "0x%04x" % ver),
                "random": random,
                "handshake": bytes(data[5:handshake_end]),
                "suites": suites,
                "psk": [s for s in suites if s in TLS_PSK_SUITES],
                "extensions": exts,
                "sni": tls_sni(data)}
    except (IndexError, struct.error):
        return None


def tls_psk_identity(data):
    """The identity from a TLS-PSK ClientKeyExchange, or None.

    In a PSK handshake the client names which shared key it is using, and that
    name travels in clear. For a Tuya device it is how the cloud knows which
    device is calling, so it is the one part of the cloud conversation that can
    be read without the secret itself.
    """
    try:
        if len(data) < 11 or data[0] != 0x16 or data[5] != 0x10:
            return None
        n = struct.unpack("!H", data[9:11])[0]
        ident = data[11:11 + n]
        return ident if len(ident) == n else None
    except (IndexError, struct.error):
        return None


def tuya_lan_decode(data):
    """One line describing a Tuya LAN discovery datagram, or None if it is not one.

    For protocol 3.1 and 3.3 that line is the announcement's own JSON, which
    names the device's cloud gateway id and product key. For 3.4/3.5 only the
    framing can be read, so the line says so instead of inventing contents.

    Framing: prefix, sequence, command, length, then the body and a trailing
    CRC32 and suffix. The length counts the body plus those trailing 8 bytes.
    A 4-byte return code precedes the body on some firmware, and the encrypted
    form is AES-ECB with PKCS#7 padding.
    """
    if data.startswith(TUYA_PREFIX_35) and data.endswith(TUYA_SUFFIX_35) and len(data) >= 50:
        # prefix(4) unknown(2) sequence(4) command(4) length(4), then the body
        cmd, length = struct.unpack("!II", data[10:18])
        if 18 + length + 4 != len(data):
            return None
        return ("Tuya LAN protocol 3.4/3.5 announcement, command 0x%02x, %d bytes, encrypted "
                "with this device's own key (not the shared one), so its contents stay sealed"
                % (cmd, length))
    if len(data) < 24 or not data.startswith(TUYA_PREFIX) or not data.endswith(TUYA_SUFFIX):
        return None
    length = struct.unpack("!I", data[12:16])[0]
    if length < 8 or 16 + length != len(data):
        return None
    body = data[16:16 + length - 8]
    if body[:4] == b"\x00\x00\x00\x00" and len(body) > 4:
        body = body[4:]                     # return code, present on some builds
    if body[:1] == b"{":
        try:
            return body.decode("utf-8")
        except UnicodeDecodeError:
            return None
    if len(body) < 16 or len(body) % 16:
        return None
    try:
        from Crypto.Cipher import AES
    except ImportError:
        return None
    try:
        out = AES.new(TUYA_BROADCAST_KEY, AES.MODE_ECB).decrypt(body)
    except Exception:
        return None
    # Tuya pads with PKCS#7, so valid padding is the evidence that this really
    # is a Tuya datagram and the well-known key was the right one. Without it,
    # a wrong key or a damaged packet would yield plausible-looking rubbish.
    pad = out[-1] if out else 0
    if not (1 <= pad <= 16) or out[-pad:] != bytes([pad]) * pad:
        return None
    out = out[:-pad]
    if not out.startswith(b"{"):
        return None
    try:
        return out.decode("utf-8")
    except UnicodeDecodeError:
        return None


class EthPcap:
    """pcap writer for the frames the bridge carried (link type 1, Ethernet).

    The 802.11 capture written by --pcap is a different link type, so the two
    are separate files on purpose: one is the air, this one is the network.
    """

    LINK_ETHERNET = 1

    def __init__(self, path):
        self.f = open(path, "wb") if isinstance(path, str) else path
        self.f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, self.LINK_ETHERNET))
        self.f.flush()
        self.count = 0

    def write(self, frame, us):
        self.f.write(struct.pack("<IIII", us // 1_000_000, us % 1_000_000, len(frame), len(frame)))
        self.f.write(frame)
        self.f.flush()
        self.count += 1

    def close(self):
        try:
            self.f.close()
        except Exception:
            pass


def hexdump(data, width=16, base=0):
    """Classic offset / hex / printable dump, for showing the bytes themselves."""
    out = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hexed = " ".join("%02x" % b for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append("%08x  %-*s  %s" % (base + off, width * 3 - 1, hexed, text))
    return "\n".join(out)


def ipv4_endpoints(frame):
    """Return an Ethernet frame's ``(source, destination)`` IPv4 addresses.

    The addresses are returned as four-byte values, matching the rest of this
    module.  ``None`` means the frame is not a complete, internally plausible
    Ethernet/IPv4 packet.  Keeping this parser separate from the human-readable
    description lets callers compare addresses exactly instead of scraping (or
    substring-matching) the text produced by :func:`describe_frame`.
    """
    try:
        if len(frame) < 14 + 20 or frame[12:14] != struct.pack("!H", ETH_IP):
            return None
        packet = frame[14:]
        if packet[0] >> 4 != 4:
            return None
        ihl = (packet[0] & 0x0F) * 4
        if ihl < 20 or len(packet) < ihl:
            return None
        total = struct.unpack("!H", packet[2:4])[0]
        if total < ihl or total > len(packet):
            return None
        return bytes(packet[12:16]), bytes(packet[16:20])
    except (IndexError, TypeError, struct.error):
        return None


def describe_frame(frame):
    """One line saying what an Ethernet frame is, for a packet list.

    Deliberately shallow: enough to find the interesting frame in a list, with
    the bytes themselves alongside for anything more. Never raises - a short or
    malformed frame is described as what it is rather than hidden.
    """
    if len(frame) < 14:
        return "runt frame, %d bytes" % len(frame)
    etype = struct.unpack("!H", frame[12:14])[0]
    p = frame[14:]
    if etype == ETH_ARP:
        if len(p) < 28:
            return "ARP (truncated)"
        op = struct.unpack("!H", p[6:8])[0]
        sender, target = p[14:18], p[24:28]
        if op == 1:
            return "ARP who has %s, tell %s" % (ip2str(target), ip2str(sender))
        if op == 2:
            return "ARP %s is at %s" % (ip2str(sender), p[8:14].hex(":"))
        return "ARP opcode %d" % op
    if etype != ETH_IP:
        return "ethertype 0x%04x, %d bytes" % (etype, len(p))
    if len(p) < 20:
        return "IPv4 (truncated)"
    ihl = (p[0] & 0x0F) * 4
    proto, src, dst = p[9], p[12:16], p[16:20]
    body = p[ihl:]
    if proto == IP_ICMP and len(body) >= 4:
        kind = {0: "echo reply", 8: "echo request"}.get(body[0], "type %d" % body[0])
        return "ICMP %s %s to %s" % (kind, ip2str(src), ip2str(dst))
    if proto == IP_UDP and len(body) >= 8:
        sp, dp = struct.unpack("!HH", body[:4])
        services = {53: "DNS", 67: "DHCP", 68: "DHCP", 123: "NTP", 1900: "SSDP",
                    5353: "mDNS", 6666: "Tuya LAN", 6667: "Tuya LAN"}
        # A reply has the service on its SOURCE port, so both ends are
        # candidates. A well-known port wins, which keeps a DNS reply to a
        # high port from being named after whatever that port usually means.
        named = [services[p] for p in (dp, sp) if p in services]
        low = [services[p] for p in (dp, sp) if p in services and p < 1024]
        what = (low or named or [None])[0]
        return "UDP %s:%d to %s:%d%s, %d bytes" % (
            ip2str(src), sp, ip2str(dst), dp, (" (%s)" % what) if what else "", len(body) - 8)
    if proto == IP_TCP and len(body) >= 20:
        sp, dp = struct.unpack("!HH", body[:4])
        flags = body[13]
        names = [n for bit, n in ((TCP_SYN, "SYN"), (TCP_ACK, "ACK"), (TCP_PSH, "PSH"),
                                  (TCP_FIN, "FIN"), (TCP_RST, "RST")) if flags & bit]
        payload = len(body) - (body[12] >> 4) * 4
        return "TCP %s:%d to %s:%d [%s]%s" % (
            ip2str(src), sp, ip2str(dst), dp, ",".join(names) or "none",
            (", %d bytes" % payload) if payload > 0 else "")
    return "IPv4 protocol %d, %s to %s" % (proto, ip2str(src), ip2str(dst))


def mqtt_varint(n):
    """MQTT's 1-4 byte remaining-length encoding."""
    out = bytearray()
    while True:
        b = n % 128
        n //= 128
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def mqtt_publish_packet(topic, payload):
    """A QoS 0 PUBLISH, which needs no acknowledgement from the device."""
    body = struct.pack("!H", len(topic)) + topic + payload
    return b"\x30" + mqtt_varint(len(body)) + body


def mqtt_topic_matches(filt, topic):
    """MQTT topic-filter matching, with the + (one level) and # (rest) wildcards."""
    f, t = filt.split("/"), topic.split("/")
    for i, part in enumerate(f):
        if part == "#":
            return True                     # '#' must be last and covers the rest
        if i >= len(t):
            return False
        if part != "+" and part != t[i]:
            return False
    return len(f) == len(t)


def describe_payload(data):
    """One line saying what a captured TCP flow starts with."""
    sni = tls_sni(data)
    if sni:
        return "TLS ClientHello, server name %s" % sni
    if data[:1] == b"\x16":
        return "TLS ClientHello (no server name)"
    head = data.split(b"\r\n", 1)[0]
    if head[:4] in (b"GET ", b"POST", b"PUT ", b"HEAD") or head[:7] == b"OPTIONS":
        line = head.decode("latin-1", "replace")
        host = ""
        for part in data.split(b"\r\n"):
            if part.lower().startswith(b"host:"):
                host = " host " + part[5:].strip().decode("latin-1", "replace")
                break
        return "HTTP %s%s" % (line, host)
    mqtt = mqtt_connect_info(data)
    if mqtt:
        return mqtt
    text = "".join(chr(c) if 32 <= c < 127 else "." for c in data[:48])
    return "%d bytes: %s" % (len(data), text)


# ---------------------------------------------------------------- host side
class HostIO:
    """Helper thread servicing real sockets; everything else stays in device time."""

    def __init__(self):
        self.lock = threading.Lock()
        self.socks = {}                 # sock -> conn
        self.listeners = {}             # sock -> dport
        self.accepted = collections.deque()      # (sock, dport)
        self.dns_results = collections.deque()   # (key, ip_bytes or None)
        self.connect_results = collections.deque()  # (conn, ok)
        self.udp_in = collections.deque()        # (flow, data)
        self.udp_socks = {}             # sock -> flow
        self._stop = False
        # Async DNS/connect workers capture this generation.  A device reboot
        # increments it so a late result from the old TCP/IP instance cannot
        # attach a socket or answer a query in the new one.
        self.generation = 0
        self.thread = threading.Thread(target=self._run, name="netstack-io", daemon=True)
        self.thread.start()

    def listen(self, lport, dport, host="127.0.0.1"):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            # Windows: SO_REUSEADDR there lets a SECOND listener bind the same
            # port silently and steal half the connections - two emulators
            # both "forwarding 127.0.0.1:80". Exclusive use makes the second
            # one fail loudly instead.
            s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        else:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, lport))
        s.listen(8)
        s.setblocking(False)
        with self.lock:
            self.listeners[s] = dport
        return s

    def resolve(self, name, key):
        with self.lock:
            generation = self.generation

        def work():
            try:
                ip = socket.gethostbyname(name)
                res = str2ip(ip)
            except Exception:
                res = None
            with self.lock:
                if generation == self.generation and not self._stop:
                    self.dns_results.append((key, res))
        threading.Thread(target=work, daemon=True).start()

    def connect(self, conn, ip, port):
        with self.lock:
            generation = self.generation

        def work():
            s = None
            try:
                s = socket.create_connection((ip, port), timeout=10)
                s.setblocking(False)
                with self.lock:
                    if self._stop or generation != self.generation:
                        s.close()
                        return
                    conn.sock = s
                    self.socks[s] = conn
                    self.connect_results.append((conn, True))
            except Exception:
                if s is not None:
                    try:
                        s.close()
                    except Exception:
                        pass
                with self.lock:
                    if generation == self.generation and not self._stop:
                        self.connect_results.append((conn, False))
        threading.Thread(target=work, daemon=True).start()

    def attach(self, sock, conn):
        sock.setblocking(False)
        with self.lock:
            self.socks[sock] = conn

    def udp_socket(self, flow):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setblocking(False)
        with self.lock:
            self.udp_socks[s] = flow
        return s

    def _run(self):
        while not self._stop:
            with self.lock:
                rs = list(self.socks) + list(self.listeners) + list(self.udp_socks)
                ws = [s for s, c in self.socks.items()
                      if c.to_host or c.shutdown_pending or c.close_pending]
            if not rs and not ws:
                time.sleep(0.05)
                continue
            try:
                r, w, _ = select.select(rs, ws, [], 0.05)
            except Exception:
                time.sleep(0.05)
                continue
            for s in r:
                with self.lock:
                    conn = self.socks.get(s)
                    dport = self.listeners.get(s)
                    flow = self.udp_socks.get(s)
                if dport is not None:
                    try:
                        c, _ = s.accept()
                        with self.lock:
                            self.accepted.append((c, dport))
                    except Exception:
                        pass
                elif flow is not None:
                    try:
                        data, _ = s.recvfrom(65535)
                        with self.lock:
                            self.udp_in.append((flow, data))
                    except Exception:
                        pass
                elif conn is not None:
                    try:
                        data = s.recv(65536)
                    except BlockingIOError:
                        continue
                    except Exception:
                        data = b""
                    with self.lock:
                        if data:
                            conn.from_host.append(data)
                        else:
                            conn.host_closed = True
                            self.socks.pop(s, None)
            for s in w:
                with self.lock:
                    conn = self.socks.get(s)
                if conn is None:
                    continue
                with self.lock:
                    chunk = conn.to_host.popleft() if conn.to_host else None
                if chunk is None:
                    # Everything queued has gone out: now carry out a close
                    # or half-close the device asked for (see TcpConn).
                    if conn.close_pending:
                        conn.close_pending = False
                        self.close(s)
                    elif conn.shutdown_pending:
                        conn.shutdown_pending = False
                        try:
                            s.shutdown(socket.SHUT_WR)
                        except Exception:
                            pass
                    continue
                try:
                    n = s.send(chunk)
                    if n < len(chunk):
                        with self.lock:
                            conn.to_host.appendleft(chunk[n:])
                except BlockingIOError:
                    with self.lock:
                        conn.to_host.appendleft(chunk)
                except Exception:
                    with self.lock:
                        conn.host_closed = True
                        self.socks.pop(s, None)

    def close(self, sock):
        with self.lock:
            self.socks.pop(sock, None)
            self.udp_socks.pop(sock, None)
        try:
            sock.close()
        except Exception:
            pass

    def reset_connections(self):
        """Close device-side sockets but retain forward listeners and thread."""
        with self.lock:
            self.generation += 1
            sockets = list(self.socks) + list(self.udp_socks)
            sockets += [sock for sock, _ in self.accepted]
            self.socks.clear()
            self.udp_socks.clear()
            self.accepted.clear()
            self.dns_results.clear()
            self.connect_results.clear()
            self.udp_in.clear()
        for sock in sockets:
            try:
                sock.close()
            except Exception:
                pass

    def shutdown(self):
        """Stop the thread and close every host socket, the listeners included.

        A process that runs the emulator more than once (the GUI) needs this:
        a listener left open keeps its port, so the next run's forward cannot
        bind it and the old one goes on accepting connections nobody serves.
        The thread stops first, so select() never sees a closed socket.
        """
        self._stop = True
        if self.thread is not threading.current_thread():
            self.thread.join(1.0)
        with self.lock:
            socks = list(self.listeners) + list(self.socks) + list(self.udp_socks)
            socks += [c for c, _ in self.accepted]
            self.listeners.clear()
            self.socks.clear()
            self.udp_socks.clear()
            self.accepted.clear()
        for s in socks:
            try:
                s.close()
            except Exception:
                pass


# --------------------------------------------------------------------- TCP
class TcpConn:
    """One TCP connection between the device and this stack."""

    def __init__(self, stack, local_ip, local_port, remote_ip, remote_port, kind):
        self.stack = stack
        self.lip, self.lport, self.rip, self.rport = local_ip, local_port, remote_ip, remote_port
        self.kind = kind                # "capture" | "relay" | "forward"
        self.state = "CLOSED"
        self.snd_una = self.snd_nxt = 0x10000000 + (hash((local_port, remote_port)) & 0xFFFFF)
        self.rcv_nxt = 0
        self.peer_window = 4096
        self.unacked = b""              # bytes sent but not yet acknowledged
        self.unacked_seq = 0
        self.send_buf = b""             # bytes waiting to be sent to the device
        self.last_send_us = 0
        self.last_activity_us = 0
        self.captured = b""
        self.described = False
        self.rx_buf = b""               # capture: bytes not yet parsed by a responder
        self.proto = None               # capture: 'http' | 'mqtt' | 'raw' once recognised
        self.answered = False           # capture/http: reply sent
        self.subscribed = []            # capture/mqtt: topic filters the device asked for
        self.tls = None                 # TLS12PSKGCMServer once a supported hello is answered
        self.tls_handshake_buf = b""    # clear handshake messages, without record headers
        self.tls_plain_buf = b""        # decrypted application bytes awaiting MQTT framing
        self.tls_app_proto = None       # application protocol recognised inside TLS
        self.fin_sent = False
        self.fin_rcvd = False
        self.close_after_flush = False
        self.sock = None
        self.to_host = collections.deque()
        self.from_host = collections.deque()
        self.host_closed = False
        self.shutdown_pending = False   # half-close the host socket once to_host is sent
        self.close_pending = False      # close it once to_host is sent
        self.syn_tries = 0
        self.log_prefix = "%s:%d <-> %s:%d" % (ip2str(remote_ip), remote_port, ip2str(local_ip), local_port)

    def send(self, flags, payload=b"", options=b""):
        pkt = tcp_segment(self.lip, self.rip, self.lport, self.rport, self.snd_nxt, self.rcv_nxt,
                          flags, RCV_WINDOW, payload, options)
        self.stack.send_ip(pkt, self.rip)

    def queue(self, data):
        self.send_buf += data

    def pump(self, now_us):
        """Push queued data to the device within its window; retransmit stale data."""
        if self.state == "SYN_SENT":
            # Our SYN can be lost like any frame (no free RX descriptor, a
            # full listen backlog). Without a resend the connection - and the
            # browser waiting on it - hung forever.
            if now_us - self.last_send_us > RETRANSMIT_US:
                if self.syn_tries >= SYN_MAX_TRIES:
                    self.stack.log("[NET] TCP %s: no SYN-ACK after %d tries, giving up"
                                   % (self.log_prefix, self.syn_tries))
                    self.state = "CLOSED"
                    self.close_host()
                    return
                self.syn_tries += 1
                self.snd_nxt = (self.snd_nxt - 1) & 0xFFFFFFFF
                self.send(TCP_SYN, options=b"\x02\x04" + struct.pack("!H", MSS))
                self.snd_nxt = (self.snd_nxt + 1) & 0xFFFFFFFF
                self.last_send_us = now_us
            return
        if self.state != "ESTABLISHED" and self.state != "CLOSE_WAIT":
            return
        if self.unacked and now_us - self.last_send_us > RETRANSMIT_US:
            seq_save = self.snd_nxt
            self.snd_nxt = self.unacked_seq
            for i in range(0, len(self.unacked), MSS):
                self.send(TCP_ACK | TCP_PSH, self.unacked[i:i + MSS])
                self.snd_nxt += len(self.unacked[i:i + MSS])
            self.snd_nxt = seq_save
            self.last_send_us = now_us
        room = min(self.peer_window, 8 * MSS) - len(self.unacked)
        while self.send_buf and room > 0:
            chunk = self.send_buf[:min(MSS, room)]
            self.send_buf = self.send_buf[len(chunk):]
            if not self.unacked:
                self.unacked_seq = self.snd_nxt
            self.send(TCP_ACK | TCP_PSH, chunk)
            self.snd_nxt += len(chunk)
            self.unacked += chunk
            room -= len(chunk)
            self.last_send_us = now_us
        if (self.close_after_flush and not self.send_buf and not self.unacked
                and not self.fin_sent):
            self.send(TCP_FIN | TCP_ACK)
            self.snd_nxt += 1
            self.fin_sent = True
            self.state = "LAST_ACK" if self.fin_rcvd else "FIN_WAIT_1"

    def on_segment(self, seq, ack, flags, window, payload, now_us):
        self.last_activity_us = now_us
        self.peer_window = window or 1
        if flags & TCP_RST:
            self.stack.log("[NET] TCP %s reset by device" % self.log_prefix)
            self.close_host()
            self.state = "CLOSED"
            return
        if flags & TCP_ACK:
            acked = (ack - self.unacked_seq) & 0xFFFFFFFF
            if self.unacked and 0 < acked <= len(self.unacked):
                self.unacked = self.unacked[acked:]
                self.unacked_seq = ack
            if self.state == "SYN_SENT" and flags & TCP_SYN:
                self.rcv_nxt = (seq + 1) & 0xFFFFFFFF
                self.snd_una = ack
                self.state = "ESTABLISHED"
                self.send(TCP_ACK)
                self.stack.log("[NET] TCP %s established (%s)" % (self.log_prefix, self.kind))
                return
            if self.state == "SYN_RECEIVED":
                self.state = "ESTABLISHED"
            if self.state in ("FIN_WAIT_1",) and ack == self.snd_nxt:
                self.state = "FIN_WAIT_2"
            if self.state == "LAST_ACK" and ack == self.snd_nxt:
                self.state = "CLOSED"
                self.close_host()
                return
        if payload:
            if seq == self.rcv_nxt:
                self.rcv_nxt = (self.rcv_nxt + len(payload)) & 0xFFFFFFFF
                self.deliver(payload, now_us)
            # out of order or a retransmission: acknowledge what we have
            self.send(TCP_ACK)
        # A FIN occupies the sequence number after the segment's data, so a
        # last data segment that also carries FIN closes at seq + len(data).
        fin_seq = (seq + len(payload)) & 0xFFFFFFFF
        if flags & TCP_FIN and fin_seq == self.rcv_nxt and not self.fin_rcvd:
            self.fin_rcvd = True
            self.rcv_nxt = (self.rcv_nxt + 1) & 0xFFFFFFFF
            if self.state in ("FIN_WAIT_1", "FIN_WAIT_2"):
                self.send(TCP_ACK)
                self.state = "CLOSED"
                self.close_host()
            else:
                self.state = "CLOSE_WAIT"
                self.send(TCP_ACK)
                if self.kind == "forward" and self.sock is not None:
                    # Half-close towards the browser - but only once the
                    # host thread has sent what the device delivered. A
                    # last data segment that carries the FIN itself would
                    # otherwise be cut off by an immediate shutdown.
                    self.shutdown_pending = True
                self.close_after_flush = True

    def deliver(self, data, now_us):
        if self.kind == "client":
            if len(self.captured) < 65536:
                self.captured += data
            return
        if self.kind == "capture":
            if len(self.captured) < CAPTURE_LIMIT:
                self.captured += data
            if not self.described and len(self.captured) >= 5:
                self.described = True
                self.stack.log("[NET] TCP %s sends: %s" % (self.log_prefix, describe_payload(self.captured)))
            self.rx_buf += data
            if self.proto is None and len(self.rx_buf) >= 5:
                if mqtt_connect_info(self.rx_buf):
                    self.proto = "mqtt"
                elif self.rx_buf.split(b" ", 1)[0] in HTTP_METHODS:
                    self.proto = "http"
                # A TLS record header arrives before the whole ClientHello in
                # perfectly ordinary TCP segmentation.  Classify from that
                # header and let _tls_serve wait for its declared length;
                # requiring a complete hello here would permanently label a
                # split handshake as opaque raw bytes.
                elif (self.rx_buf[0] == 0x16 and self.rx_buf[1] == 0x03
                      and self.rx_buf[2] in (0x01, 0x02, 0x03)):
                    self.proto = "tls"
                else:
                    self.proto = "raw"          # anything else: capture only
            if self.proto == "mqtt":
                self._mqtt_serve()
            elif self.proto == "http":
                self._http_serve()
            elif self.proto == "tls":
                self._tls_serve()
        else:
            with self.stack.io.lock:
                self.to_host.append(data)

    # -- offline responders ------------------------------------------------
    # A capture that only listens stops most firmware flows at their first
    # packet: an HTTP client waits for a status line, an MQTT client only
    # publishes once the broker has accepted it. These answer just enough of
    # each protocol for the firmware to carry on, so what it sends AFTER the
    # handshake is caught too. TLS-PSK can be answered through ServerHello and
    # ServerHelloDone, far enough for a device to reveal its pre-shared-key
    # identity; completing the encrypted session still requires its secret.

    def _http_serve(self):
        """Answer one plain-HTTP request with a short 200 and close."""
        if self.answered:
            return
        head, sep, body = self.rx_buf.partition(b"\r\n\r\n")
        if not sep:
            return                              # header not complete yet
        length = 0
        for line in head.split(b"\r\n")[1:]:
            if line.lower().startswith(b"content-length:"):
                try:
                    length = int(line.split(b":", 1)[1])
                except ValueError:
                    pass
        if len(body) < length:
            return                              # wait for the whole body
        self.answered = True
        request = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        reply = ("BekenSimulator offline network: %s\n" % request).encode("latin-1", "replace")
        self.queue(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n"
                   b"Connection: close\r\n\r\n%s" % (len(reply), reply))
        self.close_after_flush = True
        self.stack.log("[NET] HTTP %s answered 200 (offline)" % request)

    def _mqtt_send(self, payload, over_tls=False):
        """Queue one broker packet, encrypting it for an established TLS peer."""
        if over_tls:
            if self.tls is None or not self.tls.established:
                raise TLSProtocolError("MQTT reply before TLS Finished")
            payload = self.tls.encrypt_records(0x17, payload)
        self.queue(payload)

    def _mqtt_serve(self, over_tls=False):
        """A broker that accepts everything: CONNACK, SUBACK, PUBACK, PINGRESP.

        Every PUBLISH is logged as topic = payload. MQTT 3.1/3.1.1 framing:
        one type/flags byte, a 1-4 byte remaining length, the body.
        """
        while True:
            buf = self.tls_plain_buf if over_tls else self.rx_buf
            if len(buf) < 2:
                return
            n, mult, p = 0, 1, 1
            while True:
                if p >= len(buf) or p > 4:
                    return                      # length field incomplete
                b = buf[p]
                n += (b & 0x7F) * mult
                mult *= 128
                p += 1
                if not b & 0x80:
                    break
            if len(buf) < p + n:
                return                          # packet incomplete
            ptype, flags, body = buf[0] >> 4, buf[0] & 0x0F, buf[p:p + n]
            if over_tls:
                self.tls_plain_buf = buf[p + n:]
            else:
                self.rx_buf = buf[p + n:]
            if ptype == 1:                      # CONNECT
                self._mqtt_send(b"\x20\x02\x00\x00", over_tls)
                self.stack.log("[NET] MQTT %s connected to the offline broker" % self.log_prefix)
            elif ptype == 3:                    # PUBLISH
                qos = (flags >> 1) & 3
                tlen = int.from_bytes(body[:2], "big")
                topic = body[2:2 + tlen].decode("utf-8", "replace")
                q = 2 + tlen
                pid = body[q:q + 2] if qos else b""
                payload = body[q + (2 if qos else 0):]
                text = payload.decode("utf-8", "replace")
                if len(text) > 120:
                    text = text[:120] + " ..."
                self.stack.log("[NET] MQTT PUBLISH %s = %s" % (topic, text))
                self.stack.mqtt_publishes.append((topic, payload))
                if qos == 1:
                    self._mqtt_send(b"\x40\x02" + pid, over_tls)
                elif qos == 2:
                    self._mqtt_send(b"\x50\x02" + pid, over_tls)
            elif ptype == 6:                    # PUBREL (QoS 2)
                self._mqtt_send(b"\x70\x02" + body[:2], over_tls)
            elif ptype == 8:                    # SUBSCRIBE
                pid, q, granted, topics = body[:2], 2, b"", []
                while q + 2 <= len(body):
                    tlen = int.from_bytes(body[q:q + 2], "big")
                    topics.append(body[q + 2:q + 2 + tlen].decode("utf-8", "replace"))
                    granted += bytes([min(body[q + 2 + tlen] if q + 2 + tlen < len(body) else 0, 1)])
                    q += 3 + tlen
                self._mqtt_send(bytes([0x90, 2 + len(granted)]) + pid + granted, over_tls)
                self.stack.log("[NET] MQTT SUBSCRIBE %s" % ", ".join(topics))
                self.subscribed.extend(topics)
                self._mqtt_deliver(over_tls)
            elif ptype == 10:                   # UNSUBSCRIBE
                self._mqtt_send(b"\xb0\x02" + body[:2], over_tls)
            elif ptype == 12:                   # PINGREQ
                self._mqtt_send(b"\xd0\x00", over_tls)
            elif ptype == 14:                   # DISCONNECT
                self.close_after_flush = True
                return

    def _tls_serve(self):
        """Serve TLS-PSK, completing the supported GCM+EMS flow when keyed.

        Without a configured candidate PSK this retains the useful inspection
        behaviour: answer through ServerHelloDone, record the clear PSK
        identity, and stop at ChangeCipherSpec.  With candidates, no key is
        selected merely because the identity looks plausible.  The encrypted
        client Finished must authenticate and contain the right transcript
        verify_data first; only then is the server Finished sent and decrypted
        application data handed to the offline MQTT broker.
        """
        while True:
            buf = self.rx_buf
            if len(buf) < 5:
                return
            if buf[0] not in (0x16, 0x14, 0x15, 0x17):
                self.proto = "raw"              # not TLS after all
                return
            n = struct.unpack("!H", buf[3:5])[0]
            encrypted_epoch = (self.tls is not None
                               and self.tls.state in ("client_finished", "established"))
            limit = TLS_MAX_CIPHERTEXT if encrypted_epoch else TLS_MAX_PLAINTEXT
            if n > limit:
                self._tls_fail("record exceeds the TLS length limit")
                return
            if len(buf) < 5 + n:
                return                          # record incomplete
            rec, self.rx_buf = buf[:5 + n], buf[5 + n:]
            content_type, version, fragment = rec[0], rec[1:3], rec[5:]

            # Once CCS has installed the client write keys, a type-0x16 record
            # is ciphertext, not another clear handshake message.
            if self.tls is not None and self.tls.state == "client_finished":
                if content_type != 0x16:
                    self._tls_fail("expected the encrypted client Finished")
                    return
                try:
                    server_flight = self.tls.finish(version, fragment)
                except TLSProtocolError:
                    self._tls_fail("client Finished authentication failed")
                    return
                self.queue(server_flight)
                self.stack.log("[NET] TLS %s handshake authenticated; serving encrypted MQTT "
                               "offline" % self.log_prefix)
                continue

            if self.tls is not None and self.tls.established:
                try:
                    plain = self.tls.decrypt_record(content_type, version, fragment)
                except TLSProtocolError:
                    self._tls_fail("encrypted record authentication failed")
                    return
                if content_type == 0x17:
                    self.tls_plain_buf += plain
                    if self.tls_app_proto is None:
                        if mqtt_connect_info(self.tls_plain_buf) is not None:
                            self.tls_app_proto = "mqtt"
                        elif len(self.tls_plain_buf) >= 12:
                            self.tls_app_proto = "raw"
                            self.stack.log("[NET] TLS %s decrypted non-MQTT application data"
                                           % self.log_prefix)
                    if self.tls_app_proto == "mqtt":
                        self._mqtt_serve(over_tls=True)
                elif content_type == 0x15:
                    self.stack.log("[NET] TLS %s received an authenticated alert"
                                   % self.log_prefix)
                    self.close_after_flush = True
                # Post-handshake type 0x16 is authenticated but there is no
                # renegotiation/session-ticket machinery in this small server.
                continue

            if content_type == 0x16:
                self.tls_handshake_buf += fragment
                while len(self.tls_handshake_buf) >= 4:
                    msg_len = int.from_bytes(self.tls_handshake_buf[1:4], "big")
                    if msg_len > 0x10000:
                        self._tls_fail("oversized clear handshake message")
                        return
                    if len(self.tls_handshake_buf) < 4 + msg_len:
                        break
                    msg = self.tls_handshake_buf[:4 + msg_len]
                    self.tls_handshake_buf = self.tls_handshake_buf[4 + msg_len:]
                    if msg[0] == 0x01 and not self.answered:
                        hello_rec = b"\x16" + version + struct.pack("!H", len(msg)) + msg
                        info = tls_client_hello(hello_rec)
                        if info is None:
                            self._tls_fail("malformed ClientHello")
                            return
                        self.answered = True
                        named = ", ".join(TLS_PSK_SUITES.get(s, "0x%04x" % s)
                                          for s in info["suites"])
                        self.stack.log(
                            "[NET] TLS %s client hello: version %s, %d cipher suites (%s)%s"
                            % (self.log_prefix, info["version"], len(info["suites"]), named,
                               ", server name %s" % info["sni"] if info["sni"] else
                               ", no server name"))
                        if not info["psk"]:
                            self.stack.log("[NET] TLS %s offers no pre-shared-key suite, so "
                                           "nothing further can be read" % self.log_prefix)
                            return
                        ems = info["extensions"].get(TLS_EXT_EXTENDED_MASTER_SECRET)
                        mfl_data = info["extensions"].get(0x0001)
                        mfl = (TLS_MAX_FRAGMENT_LENGTHS.get(mfl_data[0])
                               if mfl_data is not None and len(mfl_data) == 1
                               else None)
                        can_complete = (bool(self.stack.tls_psks)
                                        and info["version"] == "1.2"
                                        and TLS_PSK_AES_128_GCM_SHA256 in info["psk"]
                                        and ems == b"")
                        suite = (TLS_PSK_AES_128_GCM_SHA256 if can_complete
                                 else info["psk"][0])
                        reply = self._tls_server_hello(suite, info["extensions"])
                        if can_complete:
                            try:
                                self.tls = TLS12PSKGCMServer(
                                    self.stack.tls_psks, info["random"], reply[11:43],
                                    info["handshake"], reply[5:],
                                    max_plaintext=mfl or TLS_MAX_PLAINTEXT,
                                    tuya_legacy_identity_psk=(
                                        self.stack.tuya_legacy_identity_psk))
                            except (TLSProtocolError, TypeError):
                                self._tls_fail("TLS credential setup failed")
                                return
                        self.queue(reply)
                        self.stack.log("[NET] TLS %s answered with %s, waiting for the key "
                                       "identity" % (self.log_prefix, TLS_PSK_SUITES[suite]))
                    elif msg[0] == 0x10:
                        try:
                            if self.tls is not None:
                                ident = self.tls.add_client_key_exchange(msg)
                            else:
                                synthetic = (b"\x16" + version
                                             + struct.pack("!H", len(msg)) + msg)
                                ident = tls_psk_identity(synthetic)
                                if ident is None:
                                    raise TLSProtocolError("malformed TLS PSK identity")
                        except TLSProtocolError:
                            self._tls_fail("malformed ClientKeyExchange")
                            return
                        self._tls_note_identity(ident)
                    elif self.tls is not None:
                        self._tls_fail("unexpected clear handshake message")
                        return
                continue

            if content_type == 0x14:
                if self.tls is not None:
                    try:
                        self.tls.change_cipher_spec(fragment)
                    except TLSProtocolError:
                        self._tls_fail("unexpected ChangeCipherSpec")
                        return
                    self.stack.log("[NET] TLS %s switched to encryption (ChangeCipherSpec); "
                                   "authenticating the client Finished" % self.log_prefix)
                    continue
                # Inspection-only mode has no traffic keys and deliberately
                # stops before interpreting the encrypted Finished.
                self.proto = "raw"
                self.stack.log("[NET] TLS %s switched to encryption (ChangeCipherSpec); "
                               "everything after this needs the device's own secret to read"
                               % self.log_prefix)
                return
            if content_type == 0x15:
                self.proto = "raw"
                self.stack.log("[NET] TLS %s alert, the device gave up on the handshake"
                               % self.log_prefix)
                return
            if content_type == 0x17:
                self.proto = "raw"
                self.stack.log("[NET] TLS %s is encrypted from here on (%d bytes), which needs "
                               "the device's own secret to read" % (self.log_prefix, len(fragment)))
                return

    def _tls_note_identity(self, ident):
        # The identity is credential-adjacent and can itself carry private
        # account/device material.  Retain it for internal inspection, but
        # expose only its shape in logs.
        self.stack.log("[NET] TLS %s pre-shared key identity: %d bytes"
                       % (self.log_prefix, len(ident)))
        self.stack.tls_identities.append((self.log_prefix, ident))

    def _tls_fail(self, reason):
        """Stop TLS parsing with a key-agnostic diagnostic."""
        self.proto = "raw"
        self.stack.log("[NET] TLS %s %s" % (self.log_prefix, reason))

    # Extensions echoed back when the client offers them.  In particular,
    # 0x0017 commits both peers to the Extended Master Secret derivation used
    # by TLS12PSKGCMServer.
    TLS_ECHO_EXTENSIONS = (0x0001,      # max_fragment_length, echoed with its value
                           0x0016,      # encrypt_then_mac
                           0x0017)      # extended_master_secret

    def _tls_server_hello(self, suite, client_exts=()):
        """ServerHello picking `suite`, then ServerHelloDone, in one record.

        The random is derived from the connection rather than taken from the
        system, so a run stays reproducible like everything else here.
        """
        seed = ("%s|%d" % (self.log_prefix, suite)).encode()
        rnd = (hashlib.sha256(seed).digest() + hashlib.sha256(seed[::-1]).digest())[:32]
        ext = b""
        for et in self.TLS_ECHO_EXTENSIONS:
            if et in client_exts:
                val = client_exts[et] if et == 0x0001 else b""
                if et == 0x0001 and (len(val) != 1
                                     or val[0] not in TLS_MAX_FRAGMENT_LENGTHS):
                    continue
                if et in (0x0016, 0x0017) and client_exts[et] != b"":
                    continue
                ext += struct.pack("!HH", et, len(val)) + val
        body = struct.pack("!H", 0x0303) + rnd + b"\x00" + struct.pack("!H", suite) + b"\x00"
        if ext:
            body += struct.pack("!H", len(ext)) + ext
        hello = b"\x02" + struct.pack("!I", len(body))[1:] + body
        done = b"\x0e\x00\x00\x00"
        payload = hello + done
        return b"\x16\x03\x03" + struct.pack("!H", len(payload)) + payload

    def _mqtt_deliver(self, over_tls=False):
        """Send the device any --mqtt-publish message it has now subscribed to.

        A real broker only forwards what a client asked for, so each message
        waits for a matching SUBSCRIBE. That is also what makes this a test of
        the device: the firmware chose those topic filters itself.
        """
        for item in list(self.stack.mqtt_pubs):
            topic, payload = item
            if not any(mqtt_topic_matches(f, topic) for f in self.subscribed):
                continue
            self.stack.mqtt_pubs.remove(item)
            self._mqtt_send(mqtt_publish_packet(topic.encode("utf-8"), payload), over_tls)
            self.stack.log("[NET] MQTT -> device PUBLISH %s = %s"
                           % (topic, payload.decode("utf-8", "replace")))

    def close_host(self):
        if self.sock is not None:
            with self.stack.io.lock:
                unsent = bool(self.to_host)
            if unsent:
                self.close_pending = True       # the host thread closes it once flushed
            else:
                self.stack.io.close(self.sock)
            self.sock = None

    def service(self, now_us):
        """Called every tick: move host bytes toward the device, time out captures."""
        if self.kind in ("relay", "forward"):
            with self.stack.io.lock:
                chunks = list(self.from_host)
                self.from_host.clear()
                host_closed = self.host_closed
            for c in chunks:
                self.queue(c)
            if host_closed and not self.close_after_flush:
                self.close_after_flush = True
        elif self.kind == "capture":
            # An MQTT session stays open as long as the firmware keeps it:
            # it goes quiet between keep-alives, which is not the end of it.
            mqtt_session = (self.proto == "mqtt"
                            or (self.proto == "tls" and self.tls is not None
                                and self.tls.established and self.tls_app_proto == "mqtt"))
            if (self.state in ("ESTABLISHED", "CLOSE_WAIT") and not self.close_after_flush
                    and not mqtt_session
                    and now_us - self.last_activity_us > CAPTURE_IDLE_US):
                if self.captured and not self.described:
                    self.described = True
                    self.stack.log("[NET] TCP %s sends: %s" % (self.log_prefix, describe_payload(self.captured)))
                self.close_after_flush = True
        elif self.kind == "client":
            # Our own request (--net-http-get): report the reply once the
            # device closes, or once it has gone quiet after answering.
            idle = now_us - self.last_activity_us > CAPTURE_IDLE_US
            if not self.described and (self.fin_rcvd or (self.captured and idle)):
                self.described = True
                self.stack.report_http(self, self.captured)
                self.close_after_flush = True
            elif not self.described and idle and now_us - self.opened_us > 30_000_000:
                self.described = True
                self.stack.log("[NET] HTTP GET %s: no reply from the device" % self.request_path)
                self.close_after_flush = True
        self.pump(now_us)


# ------------------------------------------------------------------ the stack
class NetStack:
    def __init__(self, mac, log=None, gateway=True, ip=None, netmask=b"\xff\xff\xff\x00",
                 net_out=False, forwards=(), device_ip=None, http_gets=(), mqtt_pubs=(),
                 tls_psks=(), tuya_legacy_identity_psk=False):
        self.mac = mac
        self.log = log or (lambda *a: None)
        self.gateway = gateway          # True: we are the router/DHCP server; False: DHCP client
        self.ip = ip or (str2ip("192.168.1.1") if gateway else None)
        self.netmask = netmask
        self.net_out = net_out
        self.output = None              # callback(eth_frame)
        # Optional callback(direction, frame_bytes, now_us) for a front end
        # that shows the traffic itself; see _trace().
        self.on_frame = None
        self.io = HostIO()
        self.now_us = 0
        self.arp = {}                   # ip bytes -> mac bytes
        self.device_ip = device_ip      # learned from DHCP / ARP / IP source
        self.device_mac = None
        self.leases = {}                # mac -> ip (gateway mode)
        self.pool_next = 100
        self.conns = {}                 # (lip, lport, rip, rport) -> TcpConn
        self.next_port = 40000
        self.dns_cache = {}             # name -> ip bytes
        self.dns_pending = {}           # key -> (query packet info)
        self.sinkhole = {}              # name -> ip bytes
        self.sinkhole_rev = {}
        self.sink_next = 1
        self.udp_flows = {}             # (dev_port, dst_ip, dst_port) -> [sock, last_us]
        self.forwards = list(forwards)  # [(lport, dport)]
        self.listeners = []
        for lport, dport in self.forwards:
            try:
                self.listeners.append(self.io.listen(lport, dport))
                self.log("[NET] forwarding 127.0.0.1:%d -> device:%d" % (lport, dport))
            except Exception as e:
                self.log("[NET] cannot listen on 127.0.0.1:%d: %s" % (lport, e))
        # DHCP client state (device-is-AP mode)
        self.dhcp_state = "INIT"
        self.dhcp_xid = 0x5A17C0DE
        self.dhcp_next_us = 0
        self.dhcp_server = None
        self.offered = None
        self.link = False
        self.link_up_us = None
        self._next_probe_us = 0
        self.probe_sent = False
        self.ping_seq = 0
        self.ping_replies = 0
        self.pending_forward_wait = []  # accepted host sockets waiting for the device IP
        self.ident = 1
        self.http_gets = list(http_gets)  # paths to GET from the device's port 80
        self.http_replies = []
        self.mqtt_publishes = []        # (topic, payload) seen by the offline broker
        self.tls_identities = []        # (connection, identity bytes) from TLS-PSK handshakes
        if isinstance(tls_psks, (bytes, bytearray, memoryview)):
            tls_psks = (tls_psks,)
        candidates = []
        for psk in tls_psks:
            if not isinstance(psk, (bytes, bytearray, memoryview)):
                raise TypeError("TLS PSK candidates must be byte strings")
            candidates.append(bytes(psk))
        # Kept at stack scope so a firmware cloud reconnect can authenticate
        # too.  Each TLS12PSKGCMServer receives a private copy and discards its
        # candidate tuple immediately after Finished succeeds or fails.
        self.tls_psks = tuple(candidates)
        self.tuya_legacy_identity_psk = bool(tuya_legacy_identity_psk)
        # (topic, payload) the offline broker should push TO the device, each
        # sent once the device subscribes to a filter that matches it.
        self.mqtt_pubs = list(mqtt_pubs)
        self._http_next_us = 0
        if self.net_out:
            self.log("[NET] REAL INTERNET enabled: device DNS/TCP/UDP can leave this machine")

    def close(self):
        """Release host resources and forget all TLS credential material."""
        self.io.shutdown()
        self.tls_psks = ()
        self.tuya_legacy_identity_psk = False
        self.tls_identities.clear()
        for conn in tuple(self.conns.values()):
            if conn.tls is not None:
                conn.tls.clear_secrets()
                conn.tls = None
            # These capture the clear ClientKeyExchange (including its
            # identity) and decrypted application records while a run is live.
            conn.captured = b""
            conn.rx_buf = b""
            conn.tls_handshake_buf = b""
            conn.tls_plain_buf = b""
        self.conns.clear()
        self.output = None
        self.on_frame = None

    @staticmethod
    def _forget_connection(conn):
        """Remove retained payload/key material from one abandoned session."""
        if conn.tls is not None:
            conn.tls.clear_secrets()
            conn.tls = None
        conn.captured = b""
        conn.rx_buf = b""
        conn.tls_handshake_buf = b""
        conn.tls_plain_buf = b""

    def device_reset(self, now_us):
        """Drop state owned by the rebooted device, keeping the outside LAN.

        The router/AP, capture writer and listening port forwards are external
        hardware and remain alive.  Associations call link_up() again after
        reboot; every old transport flow and host socket is invalid then.
        """
        self.now_us = now_us
        self.io.reset_connections()
        for conn in tuple(self.conns.values()):
            self._forget_connection(conn)
        self.conns.clear()
        self.udp_flows.clear()
        self.dns_pending.clear()

        # Accepted forward sockets which had not yet learned the device IP are
        # not registered with HostIO, so close those explicitly.
        waiting, self.pending_forward_wait = self.pending_forward_wait, []
        for sock, _dport, _accepted_at in waiting:
            try:
                sock.close()
            except Exception:
                pass

        self.link = False
        self.link_up_us = None
        self.device_mac = None
        self.device_ip = None
        self.probe_sent = False
        self._next_probe_us = now_us
        self._http_next_us = now_us
        self.dhcp_state = "INIT"
        self.dhcp_next_us = now_us
        self.dhcp_server = None
        self.offered = None
        # In station mode this stack itself obtained an address from the
        # device's AP, so that lease goes with the lost link.  In gateway mode
        # our router address and lease table belong to the external LAN.
        if not self.gateway:
            self.ip = None

    # --------------------------------------------------------------- output
    def send_eth(self, dst_mac, ethertype, payload):
        if self.output is not None:
            frame = eth_frame(dst_mac, self.mac, ethertype, payload)
            self._trace("to device", frame)
            self.output(frame)

    def _trace(self, direction, frame):
        """Hand a front end every byte that crossed the bridge, as it crossed.

        Both edges of the stack funnel through here, so this is the whole
        record: not a summary of what was understood, but the frames
        themselves, including ones nothing here knew what to do with.
        """
        if self.on_frame is None:
            return
        try:
            self.on_frame(direction, bytes(frame), self.now_us)
        except Exception:
            pass                            # a front end must never break the run

    def mac_for(self, ip):
        m = self.arp.get(ip)
        if m:
            return m
        if self.device_mac and (ip == self.device_ip or not self.gateway):
            return self.device_mac
        return BCAST_MAC

    def send_ip(self, pkt, dst_ip):
        self.send_eth(self.mac_for(dst_ip), ETH_IP, pkt)

    def send_arp_request(self, target_ip):
        if not self.ip:
            return
        req = struct.pack("!HHBBH", 1, ETH_IP, 6, 4, 1) + self.mac + self.ip + bytes(6) + target_ip
        self.send_eth(BCAST_MAC, ETH_ARP, req)

    def send_ping(self, target_ip):
        if not self.ip:
            return
        self.ping_seq += 1
        icmp = struct.pack("!BBHHH", 8, 0, 0, 0xBEEF, self.ping_seq) + b"BekenSimulator ping"
        icmp = icmp[:2] + struct.pack("!H", checksum(icmp)) + icmp[4:]
        self.send_ip(ipv4_packet(self.ip, target_ip, IP_ICMP, icmp, ident=self.ident), target_ip)
        self.ident = (self.ident + 1) & 0xFFFF

    # ---------------------------------------------------------------- input
    def link_up(self, device_mac=None):
        if device_mac:
            self.device_mac = device_mac
        self.link = True
        self.link_up_us = self.now_us
        if not self.gateway and self.ip is None:
            self.dhcp_state = "INIT"
            self.dhcp_next_us = self.now_us

    def input(self, frame):
        if len(frame) < 14:
            return
        dst, src, etype = frame[:6], frame[6:12], struct.unpack("!H", frame[12:14])[0]
        if src != self.mac:
            # Traced before anything is decided about it, so a frame this
            # stack ignores is still on the record.
            self._trace("from device", frame)
        if src == self.mac:
            # Our own broadcast, relayed back to the BSS by the device's AP
            # (an AP forwards a station's group frames to all stations).
            return
        if self.device_mac is None or (self.gateway and src != self.device_mac):
            self.device_mac = src
        if etype == ETH_ARP:
            self._arp(frame[14:], src)
        elif etype == ETH_IP:
            self._ipv4(frame[14:], src)

    def _arp(self, p, src_mac):
        if len(p) < 28:
            return
        htype, ptype, hlen, plen, op = struct.unpack("!HHBBH", p[:8])
        sha, spa, tha, tpa = p[8:14], p[14:18], p[18:24], p[24:28]
        if spa != b"\x00\x00\x00\x00":
            self.arp[spa] = sha
            if sha == self.device_mac:
                self.device_ip = spa
        if op == 2 and sha == self.device_mac:
            self.log("[NET] ARP: device %s is at %s" % (ip2str(spa), mac2str(sha)))
        if op == 1 and self.ip and tpa == self.ip:
            reply = struct.pack("!HHBBH", 1, ETH_IP, 6, 4, 2) + self.mac + self.ip + sha + spa
            self.send_eth(sha, ETH_ARP, reply)
        elif op == 1 and self.gateway and tpa != spa and not self._local(tpa):
            # the device asks for an address outside its subnet: we are the way out
            reply = struct.pack("!HHBBH", 1, ETH_IP, 6, 4, 2) + self.mac + tpa + sha + spa
            self.send_eth(sha, ETH_ARP, reply)

    def _local(self, ip):
        if not self.ip:
            return False
        return bytes(a & m for a, m in zip(ip, self.netmask)) == bytes(a & m for a, m in zip(self.ip, self.netmask))

    def _ipv4(self, p, src_mac):
        if len(p) < 20 or p[0] >> 4 != 4:
            return
        ihl = (p[0] & 0xF) * 4
        total = struct.unpack("!H", p[2:4])[0]
        proto = p[9]
        src, dst = p[12:16], p[16:20]
        payload = p[ihl:total] if total >= ihl else p[ihl:]
        if src != b"\x00\x00\x00\x00" and src_mac == self.device_mac:
            self.device_ip = src
            self.arp[src] = src_mac
        if proto == IP_UDP:
            self._udp(src, dst, payload)
        elif proto == IP_TCP:
            self._tcp(src, dst, payload)
        elif proto == IP_ICMP:
            self._icmp(src, dst, payload)

    # ---------------------------------------------------------------- ICMP
    def _icmp(self, src, dst, p):
        if len(p) >= 8 and p[0] == 0 and p[4:6] == b"\xbe\xef":
            self.ping_replies += 1
            self.log("[NET] ping reply from %s (seq %d)" % (ip2str(src), struct.unpack("!H", p[6:8])[0]))
            return
        if len(p) < 8 or p[0] != 8:
            return
        if dst != self.ip and not self.gateway:
            return
        reply = b"\x00\x00\x00\x00" + p[4:]
        reply = reply[:2] + struct.pack("!H", checksum(reply)) + reply[4:]
        self.send_ip(ipv4_packet(dst, src, IP_ICMP, reply), src)
        self.log("[NET] ping %s -> %s answered" % (ip2str(src), ip2str(dst)))

    # ----------------------------------------------------------------- UDP
    def _udp(self, src, dst, p):
        if len(p) < 8:
            return
        sport, dport, ulen = struct.unpack("!HHH", p[:6])
        data = p[8:ulen] if ulen >= 8 else p[8:]
        if dport == 67 and self.gateway:
            self._dhcp_server(src, sport, data)
            return
        if dport == 68 and not self.gateway:
            self._dhcp_client_rx(data)
            return
        if dport == 53:
            self._dns(src, sport, dst, data)
            return
        if dport == 123:
            self._ntp(src, sport, dst, data)
            return
        if dst[0] >= 224 or dst == b"\xff\xff\xff\xff" or dst[3] == 255:
            if dport in TUYA_LAN_PORTS:
                info = tuya_lan_decode(data)
                if info:
                    self.log("[NET] Tuya LAN broadcast from %s:%d: %s" % (ip2str(src), sport, info))
                    return
            text = "".join(chr(c) if 32 <= c < 127 else "." for c in data[:60])
            self.log("[NET] UDP broadcast %s:%d -> %s:%d %d bytes: %s"
                     % (ip2str(src), sport, ip2str(dst), dport, len(data), text))
            return
        if self.gateway and self.net_out:
            key = (sport, dst, dport)
            ent = self.udp_flows.get(key)
            if ent is None:
                try:
                    s = self.io.udp_socket(key)
                except Exception:
                    return
                ent = [s, self.now_us]
                self.udp_flows[key] = ent
                self.log("[NET] UDP %s:%d -> %s:%d relayed" % (ip2str(src), sport, ip2str(dst), dport))
            ent[1] = self.now_us
            try:
                ent[0].sendto(data, (ip2str(dst), dport))
            except Exception:
                pass
            return
        self.log("[NET] UDP %s:%d -> %s:%d %d bytes (offline, dropped)"
                 % (ip2str(src), sport, self._name(dst), dport, len(data)))

    def _name(self, ip):
        n = self.sinkhole_rev.get(ip)
        return "%s(%s)" % (ip2str(ip), n) if n else ip2str(ip)

    def _ntp(self, src, sport, dst, data):
        if len(data) < 48:
            return
        NTP_DELTA = 2208988800
        t = time.time() + NTP_DELTA
        secs = int(t)
        frac = int((t - secs) * (1 << 32))
        reply = bytearray(48)
        reply[0] = (0 << 6) | (4 << 3) | 4        # LI=0, VN=4, mode=server
        reply[1] = 2                              # stratum
        reply[2] = data[2] if data[2] else 6
        reply[3] = 0xEC
        reply[12:16] = b"LOCL"
        ts = struct.pack("!II", secs, frac)
        reply[16:24] = ts                         # reference
        reply[24:32] = data[40:48]                # originate = client transmit
        reply[32:40] = ts                         # receive
        reply[40:48] = ts                         # transmit
        self.send_ip(udp_packet(dst if dst != b"\xff\xff\xff\xff" else self.ip, src, 123, sport, bytes(reply)), src)
        self.log("[NET] NTP %s -> %s answered with the host clock" % (ip2str(src), self._name(dst)))

    # ----------------------------------------------------------------- DNS
    def _dns(self, src, sport, dst, data):
        if len(data) < 12:
            return
        txid, flags, qd = struct.unpack("!HHH", data[:6])
        if qd < 1:
            return
        name, off = dns_name(data, 12)
        if off + 4 > len(data):
            return
        qtype, qclass = struct.unpack("!HH", data[off:off + 4])
        question = data[12:off + 4]
        key = (src, sport, txid, name, qtype, dst)
        if qtype not in (1, 28):
            self._dns_reply(key, question, None)
            return
        if qtype == 28:                           # AAAA: no IPv6 here
            self._dns_reply(key, question, None)
            return
        if not self.net_out:
            ip = self.sinkhole.get(name)
            if ip is None:
                ip = bytes([10, 200, (self.sink_next >> 8) & 0xFF, self.sink_next & 0xFF])
                self.sink_next += 1
                self.sinkhole[name] = ip
                self.sinkhole_rev[ip] = name
            self.log("[NET] DNS %s -> %s (offline sinkhole)" % (name, ip2str(ip)))
            self._dns_reply(key, question, ip)
            return
        if name in self.dns_cache:
            self._dns_reply(key, question, self.dns_cache[name])
            return
        self.dns_pending[key] = question
        self.io.resolve(name, key)

    def _dns_reply(self, key, question, ip):
        src, sport, txid, name, qtype, dst = key
        if ip:
            flags = 0x8180
            answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + ip
            an = 1
        else:
            flags = 0x8183 if qtype == 1 else 0x8180   # NXDOMAIN for A, empty for AAAA/other
            answer = b""
            an = 0
        pkt = struct.pack("!HHHHHH", txid, flags, 1, an, 0, 0) + question + answer
        reply_src = dst if dst != b"\xff\xff\xff\xff" else self.ip
        self.send_ip(udp_packet(reply_src, src, 53, sport, pkt), src)

    # ---------------------------------------------------------------- DHCP
    def _dhcp_opts(self, data):
        opts = {}
        if len(data) < 240 or data[236:240] != b"\x63\x82\x53\x63":
            return opts
        p = 240
        while p < len(data):
            t = data[p]
            if t == 255:
                break
            if t == 0:
                p += 1
                continue
            l = data[p + 1]
            opts[t] = data[p + 2:p + 2 + l]
            p += 2 + l
        return opts

    def _dhcp_server(self, src, sport, data):
        opts = self._dhcp_opts(data)
        if len(data) < 240 or 53 not in opts:
            return
        mtype = opts[53][0]
        xid = data[4:8]
        chaddr = data[28:34]
        lease_ip = self.leases.get(chaddr)
        if lease_ip is None:
            lease_ip = self.ip[:3] + bytes([self.pool_next])
            self.pool_next += 1
            self.leases[chaddr] = lease_ip
        if mtype == 1:
            reply_type = 2
        elif mtype == 3:
            reply_type = 5
        else:
            return
        resp = bytearray(240)
        resp[0:4] = b"\x02\x01\x06\x00"
        resp[4:8] = xid
        resp[10:12] = data[10:12]                 # flags (broadcast bit)
        resp[16:20] = lease_ip
        resp[20:24] = self.ip
        resp[28:34] = chaddr
        resp[236:240] = b"\x63\x82\x53\x63"
        o = b"\x35\x01" + bytes([reply_type])
        o += b"\x36\x04" + self.ip                 # server id
        o += b"\x33\x04" + struct.pack("!I", 86400)
        o += b"\x01\x04" + self.netmask
        o += b"\x03\x04" + self.ip                 # router
        o += b"\x06\x04" + self.ip                 # dns
        o += b"\xff"
        pkt = udp_packet(self.ip, b"\xff\xff\xff\xff", 67, 68, bytes(resp) + o)
        self.send_eth(BCAST_MAC, ETH_IP, pkt)
        if reply_type == 5:
            self.device_ip = lease_ip
            self.device_mac = chaddr
            self.arp[lease_ip] = chaddr
            self.log("[NET] DHCP: device %s got %s (gateway/DNS %s)"
                     % (mac2str(chaddr), ip2str(lease_ip), ip2str(self.ip)))
        else:
            self.log("[NET] DHCP: offering %s to %s" % (ip2str(lease_ip), mac2str(chaddr)))

    def _dhcp_client_send(self, mtype):
        msg = bytearray(240)
        msg[0:4] = b"\x01\x01\x06\x00"
        msg[4:8] = struct.pack("!I", self.dhcp_xid)
        msg[10:12] = b"\x80\x00"                 # broadcast replies
        msg[28:34] = self.mac
        msg[236:240] = b"\x63\x82\x53\x63"
        o = b"\x35\x01" + bytes([mtype])
        o += b"\x3d\x07\x01" + self.mac
        if mtype == 3 and self.offered:
            o += b"\x32\x04" + self.offered
            if self.dhcp_server:
                o += b"\x36\x04" + self.dhcp_server
        o += b"\x37\x03\x01\x03\x06\xff"
        pkt = udp_packet(b"\x00\x00\x00\x00", b"\xff\xff\xff\xff", 68, 67, bytes(msg) + o)
        self.send_eth(BCAST_MAC, ETH_IP, pkt)

    def _dhcp_client_rx(self, data):
        opts = self._dhcp_opts(data)
        if len(data) < 240 or 53 not in opts or data[4:8] != struct.pack("!I", self.dhcp_xid):
            return
        mtype = opts[53][0]
        if mtype == 2 and self.dhcp_state == "DISCOVER":
            self.offered = data[16:20]
            self.dhcp_server = opts.get(54, data[20:24])
            self.dhcp_state = "REQUEST"
            self._dhcp_client_send(3)
            self.dhcp_next_us = self.now_us + 3_000_000
        elif mtype == 5 and self.dhcp_state == "REQUEST":
            self.ip = data[16:20]
            self.netmask = opts.get(1, self.netmask)
            router = opts.get(3)
            self.dhcp_state = "BOUND"
            self.log("[NET] DHCP: we got %s/%s from the device (router %s)"
                     % (ip2str(self.ip), ip2str(self.netmask), ip2str(router) if router else "-"))
            if router:
                self.device_ip = router
        elif mtype == 6:
            self.dhcp_state = "INIT"
            self.dhcp_next_us = self.now_us + 2_000_000

    def _arp_probe_tick(self):
        """Station side, no address known for the device: ask the usual suspects.

        The device announces itself with a gratuitous ARP when its interface
        comes up - typically before anything has joined it - so a late joiner
        may never hear it. An ARP probe (sender 0.0.0.0) for the common
        soft-AP gateway addresses gets an answer from LwIP for whichever one
        is the device's, without needing an address of our own first.
        """
        if self.device_ip or self.link_up_us is None:
            return
        if self.now_us - self.link_up_us < 4_000_000 or self.now_us < self._next_probe_us:
            return
        self._next_probe_us = self.now_us + 2_000_000
        for cand in SOFTAP_GUESSES:
            req = struct.pack("!HHBBH", 1, ETH_IP, 6, 4, 1) + self.mac + bytes(4) + bytes(6) + cand
            self.send_eth(BCAST_MAC, ETH_ARP, req)

    def _dhcp_client_tick(self):
        if self.gateway or not self.link:
            return
        self._arp_probe_tick()
        if self.dhcp_state in ("BOUND", "STATIC"):
            return
        # No lease after a few tries: take an address next to the device's own
        # (learned from its gratuitous ARP), so the rest of the path - ARP,
        # ping, port forwards - can be exercised and the DHCP failure stays a
        # finding rather than a dead end.
        if (self.ip is None and self.device_ip and self.link_up_us is not None
                and self.now_us - self.link_up_us > STATIC_FALLBACK_US):
            self.ip = self.device_ip[:3] + bytes([(self.device_ip[3] % 250) + 2])
            self.dhcp_state = "STATIC"
            self.log("[NET] no DHCP lease from the device after %d s: using static %s/%s"
                     % (STATIC_FALLBACK_US // 1_000_000, ip2str(self.ip), ip2str(self.netmask)))
            return
        if self.now_us < self.dhcp_next_us:
            return
        if self.dhcp_state in ("INIT", "DISCOVER"):
            self.dhcp_state = "DISCOVER"
            self._dhcp_client_send(1)
            self.dhcp_next_us = self.now_us + 3_000_000
        elif self.dhcp_state == "REQUEST":
            self._dhcp_client_send(3)
            self.dhcp_next_us = self.now_us + 3_000_000

    # ----------------------------------------------------------------- TCP
    def _tcp(self, src, dst, p):
        if len(p) < 20:
            return
        sport, dport, seq, ack, doff_flags, window = struct.unpack("!HHIIHH", p[:16])
        doff = (doff_flags >> 12) * 4
        flags = doff_flags & 0x3F
        payload = p[doff:]
        key = (dst, dport, src, sport)
        conn = self.conns.get(key)
        if conn is None:
            if flags & TCP_SYN and not (flags & TCP_ACK):
                self._tcp_new(src, sport, dst, dport, seq, window)
            elif not (flags & TCP_RST):
                # unknown connection: reset it so the firmware does not wait
                pkt = tcp_segment(dst, src, dport, sport, ack, (seq + len(payload)) & 0xFFFFFFFF,
                                  TCP_RST | TCP_ACK, 0)
                self.send_ip(pkt, src)
            return
        conn.on_segment(seq, ack, flags, window, payload, self.now_us)
        if conn.state == "CLOSED":
            self.conns.pop(key, None)

    def _tcp_new(self, src, sport, dst, dport, seq, window):
        """The device opens a connection to dst:dport."""
        target = self._name(dst)
        if dst == self.ip or (self.gateway and not self.net_out) or not self.gateway:
            kind = "capture"
        else:
            kind = "relay"
        conn = TcpConn(self, dst, dport, src, sport, kind)
        conn.rcv_nxt = (seq + 1) & 0xFFFFFFFF
        conn.peer_window = window
        conn.last_activity_us = self.now_us
        self.conns[(dst, dport, src, sport)] = conn
        if kind == "capture":
            self.log("[NET] TCP connect %s:%d -> %s:%d (accepted for capture)"
                     % (ip2str(src), sport, target, dport))
            conn.state = "SYN_RECEIVED"
            conn.send(TCP_SYN | TCP_ACK, options=b"\x02\x04" + struct.pack("!H", MSS))
            conn.snd_nxt += 1
        else:
            self.log("[NET] TCP connect %s:%d -> %s:%d (relaying)" % (ip2str(src), sport, target, dport))
            conn.state = "CONNECTING"
            self.io.connect(conn, ip2str(dst), dport)

    def _http_client_tick(self):
        """Issue the queued --net-http-get requests to the device, one at a time."""
        if not self.http_gets or not self.ip or not self.device_ip:
            return
        if self.now_us < self._http_next_us:
            return
        if any(c.kind == "client" and not c.described for c in self.conns.values()):
            return
        path = self.http_gets.pop(0)
        self._http_next_us = self.now_us + 500_000
        lport = self.next_port
        self.next_port = 40000 + ((self.next_port - 40000 + 1) % 20000)
        conn = TcpConn(self, self.ip, lport, self.device_ip, 80, "client")
        conn.request_path = path
        conn.opened_us = self.now_us
        conn.last_activity_us = self.now_us
        conn.queue(("GET %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: BekenSimulator\r\n"
                    "Connection: close\r\n\r\n" % (path, ip2str(self.device_ip))).encode("latin-1"))
        self.conns[(self.ip, lport, self.device_ip, 80)] = conn
        conn.state = "SYN_SENT"
        conn.last_send_us = self.now_us
        conn.send(TCP_SYN, options=b"\x02\x04" + struct.pack("!H", MSS))
        conn.snd_nxt += 1
        self.log("[NET] HTTP GET http://%s%s" % (ip2str(self.device_ip), path))

    def report_http(self, conn, data):
        head, sep, body = data.partition(b"\r\n\r\n")
        if not sep:
            head, _, body = data.partition(b"\n\n")
        # OpenBeken ends its status line with a bare LF, so split on LF and
        # drop any CR rather than assuming CRLF throughout.
        status = (head.split(b"\n", 1)[0].strip().decode("latin-1", "replace")
                  if head else "(empty reply)")
        text = body.decode("utf-8", "replace")
        one_line = " ".join(text.split())
        if len(one_line) > 300:
            one_line = one_line[:300] + " ..."
        self.log("[NET] HTTP GET %s -> %s, %d byte body: %s"
                 % (conn.request_path, status, len(body), one_line))
        self.http_replies.append((conn.request_path, status, body))

    def _forward_open(self, sock, dport):
        if not self.device_ip or not self.ip:
            self.pending_forward_wait.append((sock, dport, self.now_us))
            return
        lport = self.next_port
        self.next_port = 40000 + ((self.next_port - 40000 + 1) % 20000)
        conn = TcpConn(self, self.ip, lport, self.device_ip, dport, "forward")
        conn.sock = sock
        self.io.attach(sock, conn)
        self.conns[(self.ip, lport, self.device_ip, dport)] = conn
        conn.state = "SYN_SENT"
        conn.last_send_us = self.now_us
        conn.last_activity_us = self.now_us
        conn.send(TCP_SYN, options=b"\x02\x04" + struct.pack("!H", MSS))
        conn.snd_nxt += 1
        self.log("[NET] TCP forward: %s:%d -> device %s:%d" % (ip2str(self.ip), lport, ip2str(self.device_ip), dport))

    # ---------------------------------------------------------------- tick
    def tick(self, now_us):
        self.now_us = now_us
        self._dhcp_client_tick()
        if (not self.gateway and self.link and self.ip and self.device_ip and not self.probe_sent):
            # First thing on a usable station link: ARP for the device and ping
            # it, which proves the data path independently of any service above.
            self.probe_sent = True
            self.send_arp_request(self.device_ip)
            self.send_ping(self.device_ip)
        self._http_client_tick()
        io = self.io
        with io.lock:
            accepted = list(io.accepted); io.accepted.clear()
            dns = list(io.dns_results); io.dns_results.clear()
            connects = list(io.connect_results); io.connect_results.clear()
            udp_in = list(io.udp_in); io.udp_in.clear()
        for sock, dport in accepted:
            self._forward_open(sock, dport)
        if self.pending_forward_wait and self.device_ip and self.ip:
            waiting, self.pending_forward_wait = self.pending_forward_wait, []
            for sock, dport, _ in waiting:
                self._forward_open(sock, dport)
        for key, ip in dns:
            q = self.dns_pending.pop(key, None)
            if q is None:
                continue
            name = key[3]
            if ip:
                self.dns_cache[name] = ip
            self.log("[NET] DNS %s -> %s" % (name, ip2str(ip) if ip else "NXDOMAIN"))
            self._dns_reply(key, q, ip)
        for conn, ok in connects:
            if conn.state != "CONNECTING":
                continue
            if ok:
                conn.state = "SYN_RECEIVED"
                conn.send(TCP_SYN | TCP_ACK, options=b"\x02\x04" + struct.pack("!H", MSS))
                conn.snd_nxt += 1
            else:
                self.log("[NET] TCP %s: remote refused/unreachable" % conn.log_prefix)
                pkt = tcp_segment(conn.lip, conn.rip, conn.lport, conn.rport, 0, conn.rcv_nxt, TCP_RST | TCP_ACK, 0)
                self.send_ip(pkt, conn.rip)
                conn.state = "CLOSED"
        for flow, data in udp_in:
            dev_port, dst_ip, dst_port = flow
            if self.device_ip:
                self.send_ip(udp_packet(dst_ip, self.device_ip, dst_port, dev_port, data), self.device_ip)
        for key, conn in list(self.conns.items()):
            conn.service(now_us)
            if conn.state == "CLOSED":
                conn.close_host()
                self.conns.pop(key, None)

    def summary(self):
        return {"device_ip": ip2str(self.device_ip) if self.device_ip else None,
                "our_ip": ip2str(self.ip) if self.ip else None,
                "conns": len(self.conns), "dns": list(self.sinkhole) + list(self.dns_cache)}


# ---------------------------------------------------------------------------
# Self-tests: a fake device (just the frames) against the stack. Run: python src/netstack.py
# ---------------------------------------------------------------------------
def _run_selftests():
    n = 0

    def check(cond, msg):
        nonlocal n
        assert cond, "FAIL: " + msg
        n += 1
        print("  [PASS]", msg)

    logs = []
    out = []
    st = NetStack(bytes.fromhex("020000000001"), log=logs.append, gateway=True)
    st.output = out.append
    dev_mac = bytes.fromhex("c8478c000001")

    print("== ARP ==")
    req = struct.pack("!HHBBH", 1, ETH_IP, 6, 4, 1) + dev_mac + str2ip("192.168.1.100") + bytes(6) + st.ip
    st.input(eth_frame(BCAST_MAC, dev_mac, ETH_ARP, req))
    check(out and out[-1][12:14] == b"\x08\x06" and out[-1][14 + 8:14 + 14] == st.mac, "ARP request for our IP answered with our MAC")

    print("== DHCP server ==")
    disc = bytearray(240); disc[0:4] = b"\x01\x01\x06\x00"; disc[4:8] = b"\x12\x34\x56\x78"; disc[28:34] = dev_mac; disc[236:240] = b"\x63\x82\x53\x63"
    st.input(eth_frame(BCAST_MAC, dev_mac, ETH_IP, udp_packet(b"\0\0\0\0", b"\xff\xff\xff\xff", 68, 67, bytes(disc) + b"\x35\x01\x01\xff")))
    offer = out[-1][14:]
    yiaddr = offer[20 + 8 + 16:20 + 8 + 20]
    check(yiaddr == str2ip("192.168.1.100"), "DISCOVER -> OFFER of the first pool address")
    st.input(eth_frame(BCAST_MAC, dev_mac, ETH_IP, udp_packet(b"\0\0\0\0", b"\xff\xff\xff\xff", 68, 67, bytes(disc) + b"\x35\x01\x03\x32\x04" + yiaddr + b"\xff")))
    check(st.device_ip == yiaddr and any("got 192.168.1.100" in l for l in logs), "REQUEST -> ACK, device address learned")

    print("== DNS sinkhole + TCP capture ==")
    q = struct.pack("!HHHHHH", 0xBEEF, 0x0100, 1, 0, 0, 0) + b"\x03api\x04tuya\x03com\x00" + struct.pack("!HH", 1, 1)
    st.input(eth_frame(st.mac, dev_mac, ETH_IP, udp_packet(yiaddr, st.ip, 5000, 53, q)))
    resp = out[-1][14 + 20 + 8:]
    check(resp[:2] == b"\xbe\xef" and resp[-4:-2] == b"\x0a\xc8", "A query answered from the 10.200/16 sinkhole")
    sink = resp[-4:]
    check(st.sinkhole_rev[sink] == "api.tuya.com", "name remembered for that address")
    syn = tcp_segment(yiaddr, sink, 6000, 443, 1000, 0, TCP_SYN, 8192)
    st.input(eth_frame(st.mac, dev_mac, ETH_IP, syn))
    sa = out[-1][14 + 20:]
    check(sa[13] & TCP_SYN and sa[13] & TCP_ACK and struct.unpack("!I", sa[8:12])[0] == 1001, "SYN to a sinkhole address gets SYN-ACK")
    conn = st.conns[(sink, 443, yiaddr, 6000)]
    isn = conn.snd_nxt
    ext = b"\x00\x00" + struct.pack("!H", 2 + 3 + 12) + struct.pack("!H", 3 + 12) + b"\x00" + struct.pack("!H", 12) + b"a1.tuyaeu.com"[:12]
    body = b"\x03\x03" + bytes(32) + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00" + struct.pack("!H", len(ext)) + ext
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    rec = b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs
    st.input(eth_frame(st.mac, dev_mac, ETH_IP, tcp_segment(yiaddr, sink, 6000, 443, 1001, isn, TCP_ACK | TCP_PSH, 8192, rec)))
    check(any("server name a1.tuyaeu.co" in l for l in logs), "captured ClientHello decoded to its server name")
    st.tick(10_000_000)
    check(conn.fin_sent, "idle capture is closed with FIN")
    mq = b"\x00\x04MQTT\x04\xc2\x00\x3c\x00\x0bobk8C000000\x00\x04user\x00\x04pass"
    check(describe_payload(b"\x10" + bytes([len(mq)]) + mq)
          == "MQTT CONNECT (v3.1.1, client id 'obk8C000000', keepalive 60s, with username/password)",
          "MQTT CONNECT decoded: protocol level, client id, keepalive, credential flags")
    check(describe_payload(b"\x10\x90\x01" + mq + bytes(144 - len(mq))).startswith("MQTT CONNECT (v3.1.1"),
          "...also behind a two-byte remaining-length field")

    print("== NTP ==")
    ntp = bytes([0x23]) + bytes(47)
    st.input(eth_frame(st.mac, dev_mac, ETH_IP, udp_packet(yiaddr, str2ip("10.200.0.9"), 123, 123, ntp)))
    r = out[-1][14 + 20 + 8:]
    check(len(r) == 48 and (r[0] & 7) == 4 and struct.unpack("!I", r[40:44])[0] > 3_900_000_000, "NTP answered with a server-mode packet carrying the host clock")

    print("== ping ==")
    icmp = b"\x08\x00\x00\x00\x00\x01\x00\x01" + b"abc"
    icmp = icmp[:2] + struct.pack("!H", checksum(icmp)) + icmp[4:]
    st.input(eth_frame(st.mac, dev_mac, ETH_IP, ipv4_packet(yiaddr, st.ip, IP_ICMP, icmp)))
    check(out[-1][14 + 20] == 0 and out[-1][14 + 20 + 8:] == b"abc", "echo request answered")

    print("== forward: our side opens TCP into the device ==")
    class FakeSock:
        def __init__(self): self.sent = b""; self.closed = False
        def setblocking(self, b): pass
        def send(self, d): self.sent += d; return len(d)
        def recv(self, n): raise BlockingIOError
        def shutdown(self, how): pass
        def close(self): self.closed = True
        def fileno(self): return -1
    fs = FakeSock()
    st._forward_open(fs, 80)
    syn = out[-1][14 + 20:]
    check(syn[13] == TCP_SYN and struct.unpack("!H", syn[2:4])[0] == 80, "SYN sent to device port 80")
    fconn = [c for c in st.conns.values() if c.kind == "forward"][0]
    synack = tcp_segment(st.device_ip, st.ip, 80, fconn.lport, 5000, fconn.snd_nxt, TCP_SYN | TCP_ACK, 2048)
    st.input(eth_frame(st.mac, dev_mac, ETH_IP, synack))
    check(fconn.state == "ESTABLISHED" and out[-1][14 + 20 + 13] == TCP_ACK, "SYN-ACK -> ACK, established")
    with st.io.lock:
        fconn.from_host.append(b"GET / HTTP/1.0\r\n\r\n")
    st.tick(11_000_000)
    seg = out[-1][14 + 20:]
    check(seg[20:] == b"GET / HTTP/1.0\r\n\r\n", "host bytes pushed to the device")
    st.input(eth_frame(st.mac, dev_mac, ETH_IP, tcp_segment(st.device_ip, st.ip, 80, fconn.lport, 5001, fconn.snd_nxt, TCP_ACK | TCP_PSH, 2048, b"HTTP/1.0 200 OK\r\n")))
    check(fconn.to_host and fconn.to_host[0] == b"HTTP/1.0 200 OK\r\n", "device bytes queued for the host socket")
    check(not fconn.unacked, "our data acknowledged")

    print("== station side: DHCP fallback, ARP/ping probe ==")
    logs2, out2 = [], []
    cl = NetStack(bytes.fromhex("020000000001"), log=logs2.append, gateway=False)
    cl.output = out2.append
    garp = struct.pack("!HHBBH", 1, ETH_IP, 6, 4, 1) + dev_mac + str2ip("192.168.4.1") + bytes(6) + str2ip("192.168.4.1")
    cl.input(eth_frame(BCAST_MAC, dev_mac, ETH_ARP, garp))
    check(cl.device_ip == str2ip("192.168.4.1") and cl.device_mac == dev_mac, "device address learned from its gratuitous ARP")
    cl.tick(1_000_000); cl.link_up(dev_mac); cl.tick(1_000_001)
    check(out2 and out2[-1][14 + 20 + 8 + 240:][:3] == b"\x35\x01\x01", "DHCP DISCOVER sent once the link is up")
    cl.tick(1_000_000 + STATIC_FALLBACK_US + 1)
    check(cl.ip == str2ip("192.168.4.3") and cl.dhcp_state == "STATIC", "static fallback next to the device's address")
    kinds = [(f[12:14], f[14 + 20 + 0] if f[12:14] == b"\x08\x00" else None) for f in out2[-2:]]
    check(any(k[0] == b"\x08\x06" for k in kinds) and any(k == (b"\x08\x00", 8) for k in kinds), "ARP request and ping sent to the device")
    echo = b"\x00\x00\x00\x00\xbe\xef\x00\x01" + b"BekenSimulator ping"
    echo = echo[:2] + struct.pack("!H", checksum(echo)) + echo[4:]
    cl.input(eth_frame(cl.mac, dev_mac, ETH_IP, ipv4_packet(str2ip("192.168.4.1"), cl.ip, IP_ICMP, echo)))
    check(cl.ping_replies == 1 and any("ping reply from 192.168.4.1" in l for l in logs2), "ping reply recognised")

    print("== --net-http-get: our own request to the device ==")
    logs3, out3 = [], []
    hc = NetStack(bytes.fromhex("020000000001"), log=logs3.append, gateway=False, http_gets=["/cm?cmnd=echo%20hi"])
    hc.output = out3.append
    hc.ip, hc.device_ip, hc.device_mac = str2ip("192.168.4.100"), str2ip("192.168.4.1"), dev_mac
    hc.link, hc.probe_sent, hc.dhcp_state = True, True, "BOUND"
    hc.tick(1_000_000)
    syn = out3[-1][14 + 20:]
    check(syn[13] == TCP_SYN and struct.unpack("!H", syn[2:4])[0] == 80, "queued GET opens a connection to the device's port 80")
    cc = [x for x in hc.conns.values() if x.kind == "client"][0]
    hc.input(eth_frame(hc.mac, dev_mac, ETH_IP, tcp_segment(hc.device_ip, hc.ip, 80, cc.lport, 7000, cc.snd_nxt, TCP_SYN | TCP_ACK, 4096)))
    hc.tick(1_100_000)
    check(out3[-1][14 + 40:].startswith(b"GET /cm?cmnd=echo%20hi HTTP/1.0\r\n"), "request sent once established")
    reply = b"HTTP/1.1 200 OK\r\nContent-type: application/json\r\n\r\nhi"
    hc.input(eth_frame(hc.mac, dev_mac, ETH_IP, tcp_segment(hc.device_ip, hc.ip, 80, cc.lport, 7001, cc.snd_nxt,
                                                         TCP_ACK | TCP_PSH | TCP_FIN, 4096, reply)))
    hc.tick(1_200_000)
    check(hc.http_replies == [("/cm?cmnd=echo%20hi", "HTTP/1.1 200 OK", b"hi")],
          "reply whose last segment also carries FIN is complete (FIN at seq + data length)")
    check(any("-> HTTP/1.1 200 OK, 2 byte body: hi" in l for l in logs3), "status and body logged")

    def segs(frames, dport=None):
        """TCP segments we sent: [(seq, ack, flags, payload, sport, dport)]."""
        res = []
        for f in frames:
            if f[12:14] == b"\x08\x00" and f[14 + 9] == IP_TCP:
                t = f[14 + 20:]
                sp, dp, sq, ak = struct.unpack("!HHII", t[:12])
                if dport is None or dp == dport:
                    res.append((sq, ak, t[13], t[(t[12] >> 4) * 4:], sp, dp))
        return res

    def open_capture(stack, out, dst, dport, sport, isn=5000):
        """Device SYN to dst:dport; returns (conn, next device seq)."""
        stack.input(eth_frame(stack.mac, dev_mac, ETH_IP, tcp_segment(stack.device_ip, dst, sport, dport, isn, 0, TCP_SYN, 8192)))
        c = stack.conns[(dst, dport, stack.device_ip, sport)]
        stack.input(eth_frame(stack.mac, dev_mac, ETH_IP, tcp_segment(stack.device_ip, dst, sport, dport, isn + 1, c.snd_nxt, TCP_ACK, 8192)))
        return c, isn + 1

    def dev_send(stack, c, dst, dport, sport, seq, payload, flags=TCP_ACK | TCP_PSH, window=8192):
        stack.input(eth_frame(stack.mac, dev_mac, ETH_IP, tcp_segment(stack.device_ip, dst, sport, dport, seq,
                                                                     c.snd_nxt, flags, window, payload)))
        return seq + len(payload)

    print("== offline HTTP responder: the device's HTTP client gets an answer ==")
    logs7, out7 = [], []
    hs = NetStack(bytes.fromhex("020000000001"), log=logs7.append, gateway=True)
    hs.output = out7.append
    hs.device_ip, hs.device_mac = str2ip("192.168.1.100"), dev_mac
    hs.arp[hs.device_ip] = dev_mac
    sink2 = str2ip("10.200.0.7")
    hc2, sq = open_capture(hs, out7, sink2, 80, 6100)
    sq = dev_send(hs, hc2, sink2, 80, 6100, sq, b"GET /hello?dev=obk HTTP/1.1\r\nHost: api.bekensim.test\r\n\r\n")
    hs.tick(1_000_000)
    rep = b"".join(p for _, _, _, p, sp, _ in segs(out7) if sp == 80)
    check(rep.startswith(b"HTTP/1.1 200 OK\r\n") and b"GET /hello?dev=obk" in rep,
          "GET to a sinkhole address answered 200, the reply names the request")
    check(any("HTTP GET /hello?dev=obk HTTP/1.1 answered 200 (offline)" in l for l in logs7), "answer logged")
    hs.input(eth_frame(hs.mac, dev_mac, ETH_IP, tcp_segment(hs.device_ip, sink2, 6100, 80, sq, hc2.snd_nxt, TCP_ACK, 8192)))
    hs.tick(1_100_000)
    check(segs(out7)[-1][2] & TCP_FIN, "connection closed after the reply is acknowledged (Connection: close)")
    pc_, sq = open_capture(hs, out7, sink2, 80, 6101, isn=7000)
    n_before = len(segs(out7))
    sq = dev_send(hs, pc_, sink2, 80, 6101, sq, b"POST /api HTTP/1.1\r\nContent-Length: 10\r\n\r\n12345")
    hs.tick(1_200_000)
    check(not any(p.startswith(b"HTTP/1.1") for _, _, _, p, _, _ in segs(out7)[n_before:]),
          "POST with half its body: no answer yet")
    sq = dev_send(hs, pc_, sink2, 80, 6101, sq, b"67890")
    hs.tick(1_300_000)
    check(any(p.startswith(b"HTTP/1.1 200 OK") for _, _, _, p, _, _ in segs(out7)[n_before:]),
          "...answered once Content-Length bytes have arrived")

    print("== offline MQTT broker: CONNACK, SUBACK, PUBACK, PINGRESP, PUBLISH logged ==")
    mc, sq = open_capture(hs, out7, sink2, 1883, 6200, isn=9000)
    connect = b"\x00\x04MQTT\x04\x02\x00\x3c\x00\x06obkSim"
    sq = dev_send(hs, mc, sink2, 1883, 6200, sq, b"\x10" + bytes([len(connect)]) + connect)
    hs.tick(2_000_000)
    check(segs(out7, 6200)[-1][3] == b"\x20\x02\x00\x00", "CONNECT -> CONNACK (accepted)")
    sub = b"\x00\x01" + b"\x00\x0cobkSim/+/set" + b"\x01"
    sq = dev_send(hs, mc, sink2, 1883, 6200, sq, b"\x82" + bytes([len(sub)]) + sub)
    hs.tick(2_100_000)
    check(segs(out7, 6200)[-1][3] == b"\x90\x03\x00\x01\x01", "SUBSCRIBE -> SUBACK with the packet id and granted QoS")
    pub0 = b"\x00\x10obkSim/connected" + b"online"
    pub1 = b"\x00\x0cobkSim/1/get" + b"\x00\x05" + b"1"
    sq = dev_send(hs, mc, sink2, 1883, 6200, sq, b"\x30" + bytes([len(pub0)]) + pub0 + b"\x32" + bytes([len(pub1)]) + pub1)
    hs.tick(2_200_000)
    check(("obkSim/connected", b"online") in hs.mqtt_publishes and ("obkSim/1/get", b"1") in hs.mqtt_publishes,
          "two PUBLISHes in one segment both decoded (topic, payload)")
    check(any("MQTT PUBLISH obkSim/connected = online" in l for l in logs7), "publish logged as topic = payload")
    check(segs(out7, 6200)[-1][3] == b"\x40\x02\x00\x05", "QoS 1 PUBLISH -> PUBACK with its packet id")
    sq = dev_send(hs, mc, sink2, 1883, 6200, sq, b"\xc0\x00")
    hs.tick(2_300_000)
    check(segs(out7, 6200)[-1][3] == b"\xd0\x00", "PINGREQ -> PINGRESP")
    hs.input(eth_frame(hs.mac, dev_mac, ETH_IP, tcp_segment(hs.device_ip, sink2, 6200, 1883, sq, mc.snd_nxt, TCP_ACK, 8192)))
    hs.tick(30_000_000)
    check(not mc.fin_sent and mc.state == "ESTABLISHED", "an idle MQTT session is kept open (keep-alive, not end of flow)")

    print("== offline MQTT broker: QoS 2, UNSUBSCRIBE, split packets, DISCONNECT ==")
    m2, sq = open_capture(hs, out7, sink2, 1883, 6400, isn=13000)
    sq = dev_send(hs, m2, sink2, 1883, 6400, sq, b"\x10" + bytes([len(connect)]) + connect)
    hs.tick(31_000_000)
    pub2 = b"\x00\x08obkSim/q" + b"\x00\x07" + b"two"
    sq = dev_send(hs, m2, sink2, 1883, 6400, sq, b"\x34" + bytes([len(pub2)]) + pub2)
    hs.tick(31_100_000)
    check(segs(out7, 6400)[-1][3] == b"\x50\x02\x00\x07", "QoS 2 PUBLISH -> PUBREC with its packet id")
    sq = dev_send(hs, m2, sink2, 1883, 6400, sq, b"\x62\x02\x00\x07")
    hs.tick(31_200_000)
    check(segs(out7, 6400)[-1][3] == b"\x70\x02\x00\x07", "PUBREL -> PUBCOMP, the QoS 2 exchange completes")
    uns = b"\x00\x09" + b"\x00\x0cobkSim/+/set"
    sq = dev_send(hs, m2, sink2, 1883, 6400, sq, b"\xa2" + bytes([len(uns)]) + uns)
    hs.tick(31_300_000)
    check(segs(out7, 6400)[-1][3] == b"\xb0\x02\x00\x09", "UNSUBSCRIBE -> UNSUBACK with its packet id")
    big = b"\x00\x0cobkSim/state" + b"x" * 300
    pkt = b"\x30" + bytes([(len(big) & 0x7F) | 0x80, len(big) >> 7]) + big
    sq = dev_send(hs, m2, sink2, 1883, 6400, sq, pkt[:2])           # ends inside the length field
    sq = dev_send(hs, m2, sink2, 1883, 6400, sq, pkt[2:100])
    hs.tick(31_400_000)
    check(not any(t == "obkSim/state" for t, _ in hs.mqtt_publishes),
          "a PUBLISH split across segments (even inside its length field) waits for the rest")
    sq = dev_send(hs, m2, sink2, 1883, 6400, sq, pkt[100:])
    hs.tick(31_500_000)
    check(("obkSim/state", b"x" * 300) in hs.mqtt_publishes,
          "...and is decoded whole once it arrives (two-byte remaining length)")
    sq = dev_send(hs, m2, sink2, 1883, 6400, sq, b"\xe0\x00")
    hs.tick(31_600_000)
    check(segs(out7, 6400)[-1][2] & TCP_FIN, "DISCONNECT -> the broker closes the connection")

    print("== offline MQTT broker: pushing a message TO the device ==")
    check(mqtt_varint(5) == b"\x05" and mqtt_varint(300) == b"\xac\x02",
          "remaining length encodes as one byte, and as two past 127")
    pkt = mqtt_publish_packet(b"cmnd/obkSim/POWER", b"ON")
    check(pkt == b"\x30\x15\x00\x11cmnd/obkSim/POWERON", "a QoS 0 PUBLISH is built topic-length, topic, payload")
    check(mqtt_topic_matches("cmnd/obkSim/+", "cmnd/obkSim/POWER")
          and mqtt_topic_matches("obkSim/#", "obkSim/1/set")
          and mqtt_topic_matches("a/b", "a/b"),
          "topic filters match: + for one level, # for the rest, and plain equality")
    check(not mqtt_topic_matches("cmnd/obkSim/+", "cmnd/obkSim/1/POWER")
          and not mqtt_topic_matches("cmnd/obkSim/+", "cmnd/other/POWER")
          and not mqtt_topic_matches("a/b/c", "a/b"),
          "+ does not span a level, a different level does not match, and a longer filter does not match")
    logsP, outP = [], []
    ps = NetStack(bytes.fromhex("020000000001"), log=logsP.append, gateway=True,
                  mqtt_pubs=[("cmnd/obkSim/POWER", b"ON"), ("nobody/listens", b"x")])
    ps.output = outP.append
    ps.device_ip, ps.device_mac = str2ip("192.168.1.100"), dev_mac
    ps.arp[ps.device_ip] = dev_mac
    sinkP = str2ip("10.200.0.3")
    pc, sq = open_capture(ps, outP, sinkP, 1883, 6500, isn=21000)
    sq = dev_send(ps, pc, sinkP, 1883, 6500, sq, b"\x10" + bytes([len(connect)]) + connect)
    ps.tick(1_000_000)
    check(not any(b"cmnd/obkSim/POWER" in p for _, _, _, p, _, _ in segs(outP, 6500)),
          "nothing is pushed to a device that has only connected")
    sub2 = b"\x00\x01" + b"\x00\x0dcmnd/obkSim/+" + b"\x00"
    sq = dev_send(ps, pc, sinkP, 1883, 6500, sq, b"\x82" + bytes([len(sub2)]) + sub2)
    ps.tick(1_100_000)
    pushed = b"".join(p for _, _, _, p, sp, _ in segs(outP, 6500) if sp == 1883)
    check(mqtt_publish_packet(b"cmnd/obkSim/POWER", b"ON") in pushed,
          "...and it is pushed once the device subscribes to a filter that matches it")
    check(any("[NET] MQTT -> device PUBLISH cmnd/obkSim/POWER = ON" in l for l in logsP), "the push is logged")
    check(ps.mqtt_pubs == [("nobody/listens", b"x")],
          "a message nobody subscribed to is still waiting, not sent to the wrong topic")
    n_before = len(segs(outP, 6500))
    sq = dev_send(ps, pc, sinkP, 1883, 6500, sq, b"\x82" + bytes([len(sub2)]) + sub2)
    ps.tick(1_200_000)
    check(not any(b"cmnd/obkSim/POWER" in p for _, _, _, p, _, _ in segs(outP, 6500)[n_before:]),
          "subscribing again does not send the same message twice")

    print("== offline UDP: broadcasts logged, other datagrams dropped ==")
    n_out = len(out7)
    hs.input(eth_frame(BCAST_MAC, dev_mac, ETH_IP, udp_packet(hs.device_ip, b"\xff\xff\xff\xff", 6666, 6667,
                                                             b"\x00\x00\x55\xaa{\"gwId\":\"sim\"}")))
    check(len(out7) == n_out and any("UDP broadcast 192.168.1.100:6666 -> 255.255.255.255:6667" in l
                                     and "gwId" in l for l in logs7),
          "a LAN broadcast (Tuya's discovery port 6667) is logged with its text, nothing answered")
    hs.input(eth_frame(hs.mac, dev_mac, ETH_IP, udp_packet(hs.device_ip, sink2, 7000, 9999, b"data")))
    check(len(out7) == n_out and any("UDP 192.168.1.100:7000 -> 10.200.0.7:9999 4 bytes (offline, dropped)" in l
                                     for l in logs7),
          "a datagram to any other port is logged and dropped while offline")

    print("== frame trace: every byte that crossed the bridge ==")
    seen = []
    logsF, outF = [], []
    fs = NetStack(bytes.fromhex("020000000001"), log=logsF.append, gateway=True)
    fs.output = outF.append
    fs.on_frame = lambda d, f, us: seen.append((d, f, us))
    fs.device_ip, fs.device_mac = str2ip("192.168.1.100"), dev_mac
    fs.arp[fs.device_ip] = dev_mac
    fs.now_us = 1234
    ping = b"\x08\x00\x00\x00\x00\x01\x00\x07" + b"hello"
    ping = ping[:2] + struct.pack("!H", checksum(ping)) + ping[4:]
    inframe = eth_frame(fs.mac, dev_mac, ETH_IP, ipv4_packet(fs.device_ip, fs.ip, IP_ICMP, ping))
    fs.input(inframe)
    check(len(seen) == 2, "one frame in, one frame out, both on the record")
    check(seen[0][0] == "from device" and seen[0][1] == inframe and seen[0][2] == 1234,
          "the device's frame is recorded whole, byte for byte, with the time it arrived")
    check(seen[1][0] == "to device" and seen[1][1] == outF[-1],
          "and so is the reply, exactly as it went out")
    # A frame nothing here understands must still be recorded: the point is to
    # show what crossed, not what this stack happened to parse.
    odd = eth_frame(fs.mac, dev_mac, 0x88CC, b"\x01\x02\x03")
    fs.input(odd)
    check(seen[-1] == ("from device", odd, 1234), "a frame the stack ignores is recorded too")
    n_before = len(seen)
    fs.input(eth_frame(fs.mac, fs.mac, ETH_IP, bytes(20)))
    check(len(seen) == n_before, "our own frame echoed back by the device's AP is not double-counted")
    fs.on_frame = lambda d, f, us: (_ for _ in ()).throw(RuntimeError("front end bug"))
    fs.input(inframe)
    check(True, "a front end that raises cannot break the run")

    print("== frame summaries for a packet list ==")
    def summ(pkt, src=None, dst=None):
        return describe_frame(eth_frame(dst or BCAST_MAC, src or dev_mac, ETH_IP, pkt))
    ip = fs.device_ip
    check(describe_frame(inframe) == "ICMP echo request 192.168.1.100 to 192.168.1.1",
          "an echo request is named with both addresses")
    check(ipv4_endpoints(inframe) == (str2ip("192.168.1.100"), str2ip("192.168.1.1")),
          "raw IPv4 endpoints are extracted exactly for packet-list filtering")
    malformed_ip = bytearray(ipv4_packet(ip, fs.ip, IP_ICMP, ping))
    malformed_ip[2:4] = struct.pack("!H", len(malformed_ip) + 1)
    check(ipv4_endpoints(eth_frame(fs.mac, dev_mac, ETH_ARP, bytes(malformed_ip))) is None
          and ipv4_endpoints(eth_frame(fs.mac, dev_mac, ETH_IP, bytes(malformed_ip))) is None
          and ipv4_endpoints(b"short") is None,
          "endpoint extraction rejects non-IPv4, truncated and inconsistent frames safely")
    syn = tcp_segment(ip, str2ip("10.200.0.1"), 40127, 1883, 1, 0, TCP_SYN, 8192)
    check(summ(syn) == "TCP 192.168.1.100:40127 to 10.200.0.1:1883 [SYN]", "a SYN names its ports and flag")
    data = tcp_segment(ip, str2ip("10.200.0.1"), 40127, 1883, 2, 1, TCP_ACK | TCP_PSH, 8192, b"hello there")
    check(summ(data) == "TCP 192.168.1.100:40127 to 10.200.0.1:1883 [ACK,PSH], 11 bytes",
          "a data segment says how many bytes it carried")
    dns = udp_packet(ip, str2ip("192.168.1.1"), 5353, 53, b"q" * 20)
    check(summ(dns) == "UDP 192.168.1.100:5353 to 192.168.1.1:53 (DNS), 20 bytes",
          "a datagram is named by the service on its port")
    tuya = udp_packet(ip, b"\xff\xff\xff\xff", 63035, 6667, b"x" * 40)
    check("(Tuya LAN)" in summ(tuya), "...including Tuya's own discovery port")
    reply = udp_packet(str2ip("192.168.1.1"), ip, 53, 5353, b"a" * 22)
    check("(DNS)" in summ(reply),
          "a reply is named for the service it came FROM, not whatever its destination port means")
    arp = struct.pack("!HHBBH", 1, ETH_IP, 6, 4, 1) + dev_mac + ip + bytes(6) + str2ip("192.168.1.1")
    check(describe_frame(eth_frame(BCAST_MAC, dev_mac, ETH_ARP, arp))
          == "ARP who has 192.168.1.1, tell 192.168.1.100", "an ARP request reads as a question")
    check(describe_frame(b"\x00" * 8) == "runt frame, 8 bytes"
          and "truncated" in describe_frame(eth_frame(BCAST_MAC, dev_mac, ETH_IP, b"\x45")),
          "a short or malformed frame is described as such, not hidden or raised over")

    print("== writing the captured frames as an Ethernet pcap ==")
    import tempfile as _tf
    fd, cap_path = _tf.mkstemp(suffix=".pcap")
    os.close(fd)
    try:
        cap = EthPcap(cap_path)
        cap.write(inframe, 1_500_000)
        cap.write(outF[0], 2_250_500)
        cap.close()
        blob = open(cap_path, "rb").read()
    finally:
        os.remove(cap_path)
    magic, vmaj, vmin, _z, _z2, snap, link = struct.unpack("<IHHiIII", blob[:24])
    check((magic, vmaj, vmin, link) == (0xA1B2C3D4, 2, 4, EthPcap.LINK_ETHERNET),
          "the header says pcap 2.4, link type 1, which is what Wireshark reads as Ethernet")
    off, recs = 24, []
    while off + 16 <= len(blob):
        sec, usec, incl, orig = struct.unpack("<IIII", blob[off:off + 16])
        recs.append((sec * 1_000_000 + usec, incl, orig, blob[off + 16:off + 16 + incl]))
        off += 16 + incl
    check(off == len(blob) and [r[3] for r in recs] == [inframe, outF[0]],
          "both frames are written whole, in order, with nothing added between them")
    check(recs[0][0] == 1_500_000 and recs[1][0] == 2_250_500,
          "each keeps the device time it crossed, seconds and microseconds apart")
    check(all(r[1] == r[2] == len(r[3]) for r in recs), "and is recorded at its full length")

    print("== hex dump ==")
    dump = hexdump(bytes(range(8)) + b"Hi!\x7f")
    check(dump.startswith("00000000  00 01 02 03 04 05 06 07 48 69 21 7f"), "offset then the bytes")
    check(dump.endswith("  ........Hi!."), "then the printable ones, with the rest as dots")
    check(hexdump(b"") == "", "an empty buffer dumps to nothing")
    two = hexdump(bytes(20))
    check(two.count("\n") == 1 and two.splitlines()[1].startswith("00000010  00 00 00 00  "),
          "a second row starts at the right offset and is padded so the text column lines up")

    print("== TLS 1.2 PSK/GCM/EMS crypto engine ==")
    # Published TLS 1.2 SHA-256 PRF vector (100-byte vector, first 32 bytes).
    prf_vector = tls12_prf(
        bytes.fromhex("9bbe436ba940f017b17652849a71db35"), b"test label",
        bytes.fromhex("a0ba9f936cda311827a6f796ffd5198c"), 32)
    check(prf_vector.hex() ==
          "e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a",
          "TLS 1.2 P_SHA256 matches its published deterministic vector")
    check(tls_psk_premaster(b"abc") == b"\x00\x03\x00\x00\x00\x00\x03abc",
          "plain PSK premaster encodes an equal-length all-zero other_secret")

    # A fixed synthetic transcript pins EMS, Finished, GCM nonce/AAD/tag and
    # both traffic directions without carrying any real device credential.
    fx_ch = bytes.fromhex(
        "0100002f0303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        "00000200a80100000400170000")
    fx_server = bytes.fromhex(
        "0200002c0303202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        "0000a8000004001700000e000000")
    fx_cke = bytes.fromhex("10000010000e666978747572652d636c69656e74")
    fx_client_finished = bytes.fromhex(
        "16030300280000000000000000dd86ff0778b91eebcf1068a28cbe65d34ce39485bdb25ac6c5f9"
        "41df023e7520")
    fx_server_flight = bytes.fromhex(
        "14030300010116030300280000000000000000c2ab5020ab616191d1e89dbb55870f79df90619e99"
        "d92d9dd97cc43a81ac7557")
    fx_app_record = bytes.fromhex(
        "170303002c0000000000000001dc9548dca48a3d054700292fe30be85d011960ff23ca3d85f04835"
        "6eaa524b568806b8f4")
    fx_app = bytes.fromhex("101200044d5154540402003c0006636c69656e74")
    fx = TLS12PSKGCMServer(
        (b"incorrect synthetic candidate", b"synthetic tls psk fixture"),
        bytes(range(32)), bytes(range(32, 64)), fx_ch, fx_server)
    check(hashlib.sha256(fx.transcript + fx_cke).hexdigest() ==
          "9b53d23c0caa1f9f1ccf93274bfe8ec7f22a6193c5ad83e81ef93ad0fe147836",
          "ClientHello, ServerHello/Done and ClientKeyExchange form the EMS transcript")
    check(fx.add_client_key_exchange(fx_cke) == b"fixture-client",
          "ClientKeyExchange contributes its identity and complete handshake framing")
    fx.change_cipher_spec(b"\x01")
    check(fx.finish(TLS12, fx_client_finished[5:]) == fx_server_flight,
          "authenticated client Finished selects the right candidate and yields CCS + server Finished")
    check(fx.established and fx.client_seq == 1 and fx.server_seq == 1,
          "record epochs start at sequence zero for Finished, then advance independently")
    check(fx.decrypt_record(0x17, TLS12, fx_app_record[5:]) == fx_app,
          "AES-GCM application record decrypts with explicit nonce, sequence AAD and tag")
    check(fx.encrypt_record(0x17, b"\x20\x02\x00\x00").hex() ==
          "170303001c0000000000000001cafd534ff055bbc5fd23d7c9e74fbf9103d90558",
          "server application record uses its own sequence, nonce, AAD and authentication tag")
    try:
        fx.decrypt_record(0x17, TLS12, fx_app_record[5:])
        replay_rejected = False
    except TLSProtocolError:
        replay_rejected = True
    check(replay_rejected, "replaying a valid GCM record at the next sequence number is rejected")

    # TuyaOS 3.3's legacy bootstrap mode passes one embedded 32-byte token to
    # mbedTLS as both the public identity and the PSK.  Use a wholly synthetic
    # token to pin that compatibility path, including the Finished proof that
    # prevents an arbitrary identity from being accepted on shape alone.
    legacy_identity = b"legacyIdentityActsAsPskValue0001"
    legacy_body = struct.pack("!H", len(legacy_identity)) + legacy_identity
    legacy_cke = b"\x10" + len(legacy_body).to_bytes(3, "big") + legacy_body
    legacy = TLS12PSKGCMServer(
        (b"wrong stored legacy candidate",), bytes(range(32)), bytes(range(32, 64)),
        fx_ch, fx_server, tuya_legacy_identity_psk=True)
    check(legacy.add_client_key_exchange(legacy_cke) == legacy_identity
          and legacy._psks[-1] == legacy_identity,
          "enabled Tuya legacy mode trials an exact 32-byte alphanumeric identity as PSK")
    legacy.change_cipher_spec(b"\x01")
    legacy_hash = hashlib.sha256(legacy.transcript).digest()
    legacy_master = tls12_prf(
        tls_psk_premaster(legacy_identity), b"extended master secret", legacy_hash, 48)
    legacy_block = tls12_prf(
        legacy_master, b"key expansion", bytes(range(32, 64)) + bytes(range(32)), 40)
    legacy_finished_plain = (b"\x14\x00\x00\x0c"
                             + tls12_prf(legacy_master, b"client finished",
                                         legacy_hash, 12))
    legacy_finished = TLS12PSKGCMServer._encrypt(
        legacy_block[:16], legacy_block[32:36], 0, 0x16, TLS12,
        legacy_finished_plain)
    legacy.finish(TLS12, legacy_finished[5:])
    check(legacy.established and legacy._psks == (),
          "the identity key is admitted only after its encrypted Finished authenticates")

    legacy_off = TLS12PSKGCMServer(
        (b"wrong stored legacy candidate",), bytes(range(32)), bytes(range(32, 64)),
        fx_ch, fx_server, tuya_legacy_identity_psk=False)
    legacy_off.add_client_key_exchange(legacy_cke)
    legacy_off.change_cipher_spec(b"\x01")
    try:
        legacy_off.finish(TLS12, legacy_finished[5:])
        legacy_disabled_rejected = False
    except TLSProtocolError:
        legacy_disabled_rejected = True
    malformed_identity = b"not-a-32-byte-alphanumeric-token"
    malformed_body = struct.pack("!H", len(malformed_identity)) + malformed_identity
    malformed_cke = b"\x10" + len(malformed_body).to_bytes(3, "big") + malformed_body
    legacy_shaped = TLS12PSKGCMServer(
        (b"wrong stored legacy candidate",), bytes(range(32)), bytes(range(32, 64)),
        fx_ch, fx_server, tuya_legacy_identity_psk=True)
    legacy_shaped.add_client_key_exchange(malformed_cke)
    check(legacy_disabled_rejected
          and legacy_shaped._psks == (b"wrong stored legacy candidate",),
          "disabled mode and a non-matching identity shape never become PSK candidates")

    print("== TLS-PSK: reading who is calling the cloud ==")
    # The exact ClientHello a BK7231N 3-phase meter dump sent to its Tuya cloud
    # in this emulator: TLS 1.2, four suites, three of them pre-shared-key, no
    # server name. Tuya's devices authenticate to their cloud with a shared
    # secret rather than a certificate, which is why it looks like this.
    real_hello = bytes.fromhex(
        "16030300460100004203032aec34e9f5ba50499bcdd89e1070246f6db6ee0ef786727acdbfa08a4a07fd0a"
        "000008008d00ae008c00ff010000110001000102001600000017000000230000")
    info = tls_client_hello(real_hello)
    check(info is not None and info["version"] == "1.2", "the hello is read, and names TLS 1.2")
    check(info["suites"] == [0x008D, 0x00AE, 0x008C, 0x00FF],
          "all four offered cipher suites are listed, in the order offered")
    check(info["psk"] == [0x008D, 0x00AE, 0x008C] and
          TLS_PSK_SUITES[info["psk"][0]] == "TLS_PSK_WITH_AES_256_CBC_SHA",
          "the pre-shared-key suites are picked out by name")
    check(info["sni"] is None, "and it carries no server name, as a PSK client need not")
    check(tls_client_hello(b"GET / HTTP/1.1\r\n\r\n") is None
          and tls_client_hello(real_hello[:20]) is None,
          "something that is not a complete hello is not read as one")
    hello_base = fx_ch[4:-6]  # body before extensions_length + the one EMS extension

    def hello_with_extensions(ext_blob):
        body = hello_base + struct.pack("!H", len(ext_blob)) + ext_blob
        msg = b"\x01" + len(body).to_bytes(3, "big") + body
        return b"\x16\x03\x03" + struct.pack("!H", len(msg)) + msg

    duplicate_ems = hello_with_extensions(b"\x00\x17\x00\x00\x00\x17\x00\x00")
    trailing_ext_byte = hello_with_extensions(b"\x00\x17\x00\x00\xff")
    check(tls_client_hello(duplicate_ems) is None
          and tls_client_hello(trailing_ext_byte) is None,
          "duplicate extensions and trailing bytes in the extension block reject a ClientHello")

    logsT2, outT2 = [], []
    ts3 = NetStack(bytes.fromhex("020000000001"), log=logsT2.append, gateway=True)
    ts3.output = outT2.append
    ts3.device_ip, ts3.device_mac = str2ip("192.168.1.100"), dev_mac
    ts3.arp[ts3.device_ip] = dev_mac
    cloud = str2ip("10.200.0.5")
    tc, sq = open_capture(ts3, outT2, cloud, 8886, 6700, isn=31000)
    sq = dev_send(ts3, tc, cloud, 8886, 6700, sq, real_hello)
    ts3.tick(1_000_000)
    check(any("client hello: version 1.2, 4 cipher suites" in l and "TLS_PSK_WITH_AES_256_CBC_SHA" in l
              for l in logsT2), "a device's hello to the cloud is reported with what it offered")
    reply = b"".join(p for _, _, _, p, sp, _ in segs(outT2, 6700) if sp == 8886)
    check(reply[:3] == b"\x16\x03\x03" and reply[5] == 0x02,
          "the stack answers with a ServerHello of its own")
    chosen = struct.unpack("!H", reply[5 + 4 + 2 + 32 + 1:5 + 4 + 2 + 32 + 3])[0]
    check(chosen == 0x008D and reply[-4:] == b"\x0e\x00\x00\x00",
          "...picking one of the PSK suites the device offered, then ServerHelloDone")
    check(any("answered with TLS_PSK_WITH_AES_256_CBC_SHA" in l for l in logsT2), "which is logged")
    # Now the device names the key it means to use. That identity is in clear.
    ident = b"bf0e0f689d000d56656gmp"
    cke_body = struct.pack("!H", len(ident)) + ident
    cke = b"\x10" + struct.pack("!I", len(cke_body))[1:] + cke_body
    sq = dev_send(ts3, tc, cloud, 8886, 6700, sq,
                  b"\x16\x03\x03" + struct.pack("!H", len(cke)) + cke)
    ts3.tick(1_100_000)
    check(any("pre-shared key identity: %d bytes" % len(ident) in l for l in logsT2)
          and not any(ident.decode() in l for l in logsT2),
          "the identity is retained without exposing its bytes in the log")
    check(ts3.tls_identities and ts3.tls_identities[-1][1] == ident,
          "and kept, so a front end can show which device called")
    n_logs = len(logsT2)
    sq = dev_send(ts3, tc, cloud, 8886, 6700, sq, b"\x17\x03\x03\x00\x20" + bytes(32))
    ts3.tick(1_200_000)
    check(any("encrypted from here on" in l for l in logsT2[n_logs:]),
          "once it switches to encryption, the stack says so rather than pretending to read it")

    # After the device changes to encryption, its Finished is itself a type
    # 0x16 record - the same type as the ClientKeyExchange - so if its ciphertext
    # happened to look like one, it must still NOT be read as a second identity.
    ce, sqc = open_capture(ts3, outT2, cloud, 8886, 6900, isn=41000)
    sqc = dev_send(ts3, ce, cloud, 8886, 6900, sqc, real_hello)
    ts3.tick(2_000_000)
    before = len(ts3.tls_identities)
    cke_rec = b"\x16\x03\x03" + struct.pack("!H", len(cke)) + cke
    ccs_rec = b"\x14\x03\x03\x00\x01\x01"
    # The real key exchange, the ChangeCipherSpec, then a record shaped exactly
    # like another identity - standing in for an encrypted Finished that happens
    # to collide with the ClientKeyExchange shape. All in one flight.
    dev_send(ts3, ce, cloud, 8886, 6900, sqc, cke_rec + ccs_rec + cke_rec)
    ts3.tick(2_100_000)
    check(len(ts3.tls_identities) == before + 1,
          "the identity is read once from the real key exchange; a matching record after "
          "the ChangeCipherSpec is not read as a second one")
    check(any("switched to encryption (ChangeCipherSpec)" in l for l in logsT2),
          "the switch to encryption is reported instead of parsing past it")

    # A client offering only certificate suites gets no ServerHello: there is
    # nothing to learn, and answering would be inventing a certificate.
    logsT3, outT3 = [], []
    ts4 = NetStack(bytes.fromhex("020000000001"), log=logsT3.append, gateway=True)
    ts4.output = outT3.append
    ts4.device_ip, ts4.device_mac = str2ip("192.168.1.100"), dev_mac
    ts4.arp[ts4.device_ip] = dev_mac
    rsa_hello = (b"\x16\x03\x03" + struct.pack("!H", 4 + 2 + 32 + 1 + 2 + 4 + 2)
                 + b"\x01" + struct.pack("!I", 2 + 32 + 1 + 2 + 4 + 2)[1:]
                 + b"\x03\x03" + bytes(32) + b"\x00" + struct.pack("!H", 4)
                 + b"\x00\x2f\x00\x35" + b"\x01\x00" + b"\x00\x00")
    rc2, sq2 = open_capture(ts4, outT3, cloud, 443, 6701, isn=33000)
    sq2 = dev_send(ts4, rc2, cloud, 443, 6701, sq2, rsa_hello)
    ts4.tick(1_000_000)
    check(any("offers no pre-shared-key suite" in l for l in logsT3),
          "a certificate-based hello is reported and left alone")
    check(not [p for _, _, _, p, sp, _ in segs(outT3, 6701) if sp == 443 and p],
          "...with no ServerHello sent back, because there is nothing honest to send")

    print("== TLS keyed-mode admission and record limits ==")
    logsG, outG = [], []
    gated = NetStack(bytes.fromhex("020000000001"), log=logsG.append, gateway=True,
                     tls_psks=(b"synthetic gate key",))
    gated.output = outG.append
    gated.device_ip, gated.device_mac = str2ip("192.168.1.100"), dev_mac
    gated.arp[gated.device_ip] = dev_mac
    # EMS is an empty extension by definition.  A non-empty encoding may be
    # inspected, but must never activate credential-backed completion.
    nonempty_ems = hello_with_extensions(b"\x00\x17\x00\x01\x00")
    gc1, gs1 = open_capture(gated, outG, cloud, 8883, 6702, isn=33500)
    dev_send(gated, gc1, cloud, 8883, 6702, gs1, nonempty_ems)
    gated.tick(1_000_000)
    # Likewise, suite 0x00A8 does not turn a TLS 1.1 ClientHello into a TLS 1.2
    # exchange merely because the record-layer version looks familiar.
    tls11_hello = bytearray(hello_with_extensions(b"\x00\x17\x00\x00"))
    tls11_hello[9:11] = b"\x03\x02"
    gc2, gs2 = open_capture(gated, outG, cloud, 8883, 6703, isn=34000)
    dev_send(gated, gc2, cloud, 8883, 6703, gs2, bytes(tls11_hello))
    gated.tick(1_100_000)
    check(gc1.tls is None and gc2.tls is None,
          "keyed completion requires TLS 1.2 and an exactly empty EMS extension")
    gc3, gs3 = open_capture(gated, outG, cloud, 8883, 6704, isn=34500)
    oversize_header = (b"\x16\x03\x03"
                       + struct.pack("!H", TLS_MAX_PLAINTEXT + 1))
    dev_send(gated, gc3, cloud, 8883, 6704, gs3, oversize_header)
    check(gc3.proto == "raw" and any("record exceeds the TLS length limit" in line
                                      for line in logsG),
          "an oversized clear TLS record is rejected from its header without buffering its body")

    print("== keyed TLS-PSK record flow reaches the offline MQTT broker ==")
    tls_secret = b"synthetic integration psk, never a device key"
    large_push = b"x" * 2300
    logsK, outK = [], []
    keyed = NetStack(bytes.fromhex("020000000001"), log=logsK.append, gateway=True,
                     tls_psks=(b"wrong synthetic candidate", tls_secret),
                     mqtt_pubs=(("cmnd/large", large_push),))
    keyed.output = outK.append
    keyed.device_ip, keyed.device_mac = str2ip("192.168.1.100"), dev_mac
    keyed.arp[keyed.device_ip] = dev_mac
    kc, kseq = open_capture(keyed, outK, cloud, 8883, 6710, isn=35000)

    # Split the ClientHello after its TLS header.  Protocol recognition and
    # record buffering must not depend on how TCP happened to segment it.
    keyed_hello_record = hello_with_extensions(
        b"\x00\x01\x00\x01\x02"       # max_fragment_length = 1024
        b"\x00\x17\x00\x00")          # extended_master_secret
    keyed_ch = keyed_hello_record[5:]
    client_hello_record = keyed_hello_record
    kseq = dev_send(keyed, kc, cloud, 8883, 6710, kseq, client_hello_record[:7])
    check(kc.proto == "tls" and not kc.answered,
          "a split TLS record is recognised from its header and waits for the complete ClientHello")
    hello_out_from = len(outK)
    kseq = dev_send(keyed, kc, cloud, 8883, 6710, kseq, client_hello_record[7:])
    keyed.tick(1_000_000)
    hello_reply = b"".join(p for _, _, _, p, sp, _ in segs(outK[hello_out_from:])
                           if sp == 8883 and p)
    check(hello_reply.startswith(b"\x16\x03\x03") and hello_reply[5] == 0x02
          and b"\x00\x01\x00\x01\x02" in hello_reply
          and hello_reply[-4:] == b"\x0e\x00\x00\x00",
          "keyed ServerHello selects AES-128-GCM, EMS and the offered 1024-byte fragment limit")

    server_random = hello_reply[11:43]
    transcript = keyed_ch + hello_reply[5:] + fx_cke
    master = tls12_prf(tls_psk_premaster(tls_secret), b"extended master secret",
                       hashlib.sha256(transcript).digest(), 48)
    key_block = tls12_prf(master, b"key expansion", server_random + bytes(range(32)), 40)
    client_key, server_key = key_block[:16], key_block[16:32]
    client_iv, server_iv = key_block[32:36], key_block[36:40]
    client_finished_plain = (b"\x14\x00\x00\x0c"
                             + tls12_prf(master, b"client finished",
                                         hashlib.sha256(transcript).digest(), 12))
    client_finished_record = TLS12PSKGCMServer._encrypt(
        client_key, client_iv, 0, 0x16, TLS12, client_finished_plain)
    cke_record = b"\x16\x03\x03" + struct.pack("!H", len(fx_cke)) + fx_cke
    client_handshake_flight = (cke_record + b"\x14\x03\x03\x00\x01\x01"
                               + client_finished_record)
    finished_out_from = len(outK)
    kseq = dev_send(keyed, kc, cloud, 8883, 6710, kseq, client_handshake_flight)
    keyed.tick(1_100_000)
    server_finished_flight = b"".join(
        p for _, _, _, p, sp, _ in segs(outK[finished_out_from:]) if sp == 8883 and p)
    check(server_finished_flight.startswith(b"\x14\x03\x03\x00\x01\x01\x16\x03\x03"),
          "verified client Finished produces server ChangeCipherSpec and encrypted Finished")
    check(kc.tls is not None and kc.tls.max_plaintext == 1024 and kc.tls._psks == (),
          "the session installs the negotiated fragment limit and discards its PSK candidates")
    server_finished_record = server_finished_flight[6:]
    server_finished_plain = TLS12PSKGCMServer._decrypt(
        server_key, server_iv, 0, 0x16, TLS12, server_finished_record[5:])
    expected_server_finished = (b"\x14\x00\x00\x0c"
                                + tls12_prf(master, b"server finished",
                                            hashlib.sha256(transcript
                                                           + client_finished_plain).digest(), 12))
    check(hmac.compare_digest(server_finished_plain, expected_server_finished),
          "server Finished authenticates the transcript including the client's Finished")

    connect = fx_app
    sub_body = b"\x12\x34" + struct.pack("!H", len(b"cmnd/#")) + b"cmnd/#\x00"
    subscribe = b"\x82" + mqtt_varint(len(sub_body)) + sub_body
    pub_body = struct.pack("!H", len(b"dev/state")) + b"dev/state" + b"online"
    publish = b"\x30" + mqtt_varint(len(pub_body)) + pub_body
    mqtt_flight = connect + subscribe + publish
    client_app_record = TLS12PSKGCMServer._encrypt(
        client_key, client_iv, 1, 0x17, TLS12, mqtt_flight)
    app_out_from = len(outK)
    # Split the protected application record too; neither GCM nor MQTT sees a
    # partial unit until the complete TLS record has arrived.
    cut = len(client_app_record) // 2
    kseq = dev_send(keyed, kc, cloud, 8883, 6710, kseq, client_app_record[:cut])
    check(not keyed.mqtt_publishes, "a partial encrypted application record is not decrypted early")
    kseq = dev_send(keyed, kc, cloud, 8883, 6710, kseq, client_app_record[cut:])
    keyed.tick(1_200_000)
    mqtt_reply_stream = b"".join(
        p for _, _, _, p, sp, _ in segs(outK[app_out_from:]) if sp == 8883 and p)

    def tls_records(stream):
        records = []
        while stream:
            if len(stream) < 5:
                return []
            length = struct.unpack("!H", stream[3:5])[0]
            if len(stream) < 5 + length:
                return []
            records.append(stream[:5 + length])
            stream = stream[5 + length:]
        return records

    mqtt_reply_records = tls_records(mqtt_reply_stream)
    mqtt_replies = [TLS12PSKGCMServer._decrypt(
        server_key, server_iv, seq, rec[0], rec[1:3], rec[5:])
        for seq, rec in enumerate(mqtt_reply_records, 1)]
    check(mqtt_replies[:2] == [b"\x20\x02\x00\x00", b"\x90\x03\x12\x34\x00"],
          "decrypted CONNECT and SUBSCRIBE reach the existing broker and return encrypted CONNACK/SUBACK")
    expected_push = mqtt_publish_packet(b"cmnd/large", large_push)
    push_chunks = mqtt_replies[2:]
    check(len(push_chunks) == 3 and all(len(chunk) <= 1024 for chunk in push_chunks)
          and b"".join(push_chunks) == expected_push,
          "a large broker PUBLISH is split into sequenced TLS records at max_fragment_length")
    check(keyed.mqtt_publishes == [("dev/state", b"online")]
          and any("MQTT PUBLISH dev/state = online" in line for line in logsK),
          "a decrypted application PUBLISH reaches the existing MQTT capture path")

    ping_record = TLS12PSKGCMServer._encrypt(
        client_key, client_iv, 2, 0x17, TLS12, b"\xc0\x00")
    ping_out_from = len(outK)
    kseq = dev_send(keyed, kc, cloud, 8883, 6710, kseq, ping_record)
    keyed.tick(1_300_000)
    ping_reply = b"".join(
        p for _, _, _, p, sp, _ in segs(outK[ping_out_from:]) if sp == 8883 and p)
    ping_records = tls_records(ping_reply)
    next_server_seq = 1 + len(mqtt_reply_records)
    check(len(ping_records) == 1 and TLS12PSKGCMServer._decrypt(
        server_key, server_iv, next_server_seq, 0x17, TLS12,
        ping_records[0][5:]) == b"\xd0\x00",
          "later encrypted PINGREQ/PINGRESP records advance each direction's sequence correctly")
    keyed.tick(5_000_000)
    check(kc.state == "ESTABLISHED" and not kc.close_after_flush,
          "an authenticated MQTT-over-TLS connection stays open between keep-alives")
    check(tls_secret.decode() not in "\n".join(logsK)
          and "wrong synthetic candidate" not in "\n".join(logsK)
          and "fixture-client" not in "\n".join(logsK),
          "TLS diagnostics log neither candidate key nor PSK identity bytes")
    keyed.on_frame = lambda *_args: None
    check(bool(keyed.tls_psks) and bool(keyed.tls_identities)
          and kc.tls is not None and kc.tls.client_key is not None,
          "the live stack retains only the credentials and traffic keys needed for reconnects")
    keyed.close()
    check(keyed.tls_psks == () and keyed.tls_identities == []
          and keyed.tuya_legacy_identity_psk is False
          and not keyed.conns and keyed.output is None and keyed.on_frame is None
          and kc.tls is None and kc.captured == b"" and kc.rx_buf == b""
          and kc.tls_handshake_buf == b"" and kc.tls_plain_buf == b"",
          "close drops PSKs, identities, TLS sessions, buffers and callback references")

    print("== Tuya LAN discovery broadcast decoded ==")
    def tuya_packet(payload, cmd=0x13, retcode=True):
        body = (b"\x00\x00\x00\x00" if retcode else b"") + payload
        return (TUYA_PREFIX + struct.pack("!III", 0, cmd, len(body) + 8)
                + body + b"\x24\x2d\x2c\x95" + TUYA_SUFFIX)

    # The real announcement a BK7231N 3-phase meter dump broadcast in this
    # emulator once it joined the virtual AP, re-encrypted here from its
    # decoded JSON so the test carries no captured bytes of unknown origin.
    real = ('{"ip":"192.168.1.100","gwId":"bf0e0f689d000d56656gmp","active":2,"ablilty":0,'
            '"encrypt":true,"productKey":"gqmmtjclqb7reg5p","version":"3.3"}')
    # Pin the key itself. Without this the checks below would pass under ANY
    # key, since they encrypt with the same constant they decrypt with.
    check(TUYA_BROADCAST_KEY.hex() == "6c1ec8e2bb9bb59ab50b0daf649b410a",
          "the shared broadcast key is the md5 every Tuya device uses")
    try:
        from Crypto.Cipher import AES
        raw = real.encode()
        pad = 16 - len(raw) % 16
        enc = AES.new(TUYA_BROADCAST_KEY, AES.MODE_ECB).encrypt(raw + bytes([pad]) * pad)
        check(tuya_lan_decode(tuya_packet(enc)) == real,
              "an encrypted 3.3 announcement decodes to its JSON (gateway id, product key)")
        check(tuya_lan_decode(tuya_packet(enc)[:-1]) is None, "a truncated one is not decoded")
        check(tuya_lan_decode(tuya_packet(enc[:-16])) is None, "nor is one whose ciphertext was cut short")
        bad = AES.new(hashlib.md5(b"wrongkey").digest(), AES.MODE_ECB).encrypt(raw + bytes([pad]) * pad)
        check(tuya_lan_decode(tuya_packet(bad)) is None, "nor one encrypted with a different key")
    except ImportError:
        print("  [SKIP] no pycryptodome, encrypted form not checked")
    plain = '{"ip":"192.168.1.50","gwId":"abc","version":"3.1"}'
    check(tuya_lan_decode(tuya_packet(plain.encode(), retcode=False)) == plain,
          "a 3.1 announcement is read straight out, it is not encrypted")
    check(tuya_lan_decode(b"hello") is None and tuya_lan_decode(TUYA_PREFIX + b"\x00" * 30) is None,
          "ordinary datagrams are not mistaken for Tuya ones")
    good = tuya_packet(plain.encode(), retcode=False)
    check(tuya_lan_decode(good[:-4] + b"\x00\x00\x00\x00") is None,
          "a datagram of the right length but without the Tuya end marker is rejected")
    check(tuya_lan_decode(good[:12] + struct.pack("!I", len(good)) + good[16:]) is None,
          "so is one whose declared length disagrees with how many bytes arrived")
    # A length SHORTER than what arrived is the dangerous direction: unchecked,
    # the body is cut mid-JSON and still looks decodable, so half a message
    # would be reported as the device's identity.
    check(tuya_lan_decode(good[:12] + struct.pack("!I", 18) + good[16:]) is None,
          "...including one that declares less than arrived, which would otherwise read as half a message")
    # Protocol 3.4/3.5, as a BK7238 RGB controller dump broadcasts from its own
    # pairing access point: same announcement, reframed, and sealed with a key
    # only that device has. The shape is checked; the contents are not claimed.
    sealed = (TUYA_PREFIX_35 + b"\x00\x00" + struct.pack("!III", 0, 0x11, 259)
              + bytes(259) + TUYA_SUFFIX_35)
    desc = tuya_lan_decode(sealed)
    check(desc and "3.4/3.5" in desc and "command 0x11" in desc and "sealed" in desc,
          "a 3.4/3.5 announcement is named by its framing, and its contents are not guessed at")
    check(tuya_lan_decode(sealed[:-1]) is None
          and tuya_lan_decode(sealed[:-5] + TUYA_SUFFIX_35) is None,
          "...and a frame whose declared length does not match what arrived is rejected")
    logsT, outT = [], []
    ts2 = NetStack(bytes.fromhex("020000000001"), log=logsT.append, gateway=True)
    ts2.output = outT.append
    ts2.device_ip, ts2.device_mac = str2ip("192.168.1.100"), dev_mac
    ts2.input(eth_frame(BCAST_MAC, dev_mac, ETH_IP,
                        udp_packet(ts2.device_ip, b"\xff\xff\xff\xff", 63035, 6667,
                                   tuya_packet(plain.encode(), retcode=False))))
    check(any('[NET] Tuya LAN broadcast from 192.168.1.100:63035' in l and '"gwId":"abc"' in l
              for l in logsT) and not outT,
          "a device's announcement is reported with its identity, and nothing is sent back")

    print("== offline DNS: stable sinkhole names, AAAA without records ==")
    def dns_ask(stack, name, qtype=1, txid=0x4242, sport=5353):
        labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
        q = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + labels + struct.pack("!HH", qtype, 1)
        stack.input(eth_frame(stack.mac, dev_mac, ETH_IP, udp_packet(stack.device_ip, stack.ip, sport, 53, q)))

    def udp_out(frames, sport=None, dport=None):
        """UDP datagrams we sent: [(src ip, sport, dport, payload)]."""
        res = []
        for f in frames:
            if f[12:14] == b"\x08\x00" and f[14 + 9] == IP_UDP:
                u = f[14 + (f[14] & 0x0F) * 4:]
                sp, dp = struct.unpack("!HH", u[:4])
                if (sport is None or sp == sport) and (dport is None or dp == dport):
                    res.append((f[14 + 12:14 + 16], sp, dp, u[8:]))
        return res

    dns_ask(hs, "api.bekensim.test", txid=0x4141)
    r1 = udp_out(out7, sport=53)[-1][3]
    dns_ask(hs, "api.bekensim.test", txid=0x4343)
    r2 = udp_out(out7, sport=53)[-1][3]
    dns_ask(hs, "mqtt.bekensim.test", txid=0x4444)
    r3 = udp_out(out7, sport=53)[-1][3]
    check(r1[-4:] == r2[-4:] and r1[:2] == b"\x41\x41" and r2[:2] == b"\x43\x43",
          "a name keeps its sinkhole address across lookups; each reply carries its query's id")
    check(r3[-4:] != r1[-4:] and r3[-4:-2] == b"\x0a\xc8", "another name gets its own 10.200/16 address")
    dns_ask(hs, "api.bekensim.test", qtype=28, txid=0x4545)
    r4 = udp_out(out7, sport=53)[-1][3]
    check(r4[:2] == b"\x45\x45" and struct.unpack("!HH", r4[2:4] + r4[6:8]) == (0x8180, 0),
          "AAAA answered with no records (no IPv6 here), not NXDOMAIN, so the A lookup still counts")

    print("== TCP: the device closes (FIN) or resets (RST) a captured connection ==")
    fc, sq = open_capture(hs, out7, sink2, 8883, 6300, isn=11000)
    sq = dev_send(hs, fc, sink2, 8883, 6300, sq, b"\x16\x03\x01\x00\x05hello")
    hs.input(eth_frame(hs.mac, dev_mac, ETH_IP, tcp_segment(hs.device_ip, sink2, 6300, 8883, sq, fc.snd_nxt,
                                                         TCP_FIN | TCP_ACK, 8192)))
    hs.tick(32_000_000)
    last = segs(out7, 6300)[-1]
    check(last[1] == sq + 1 and last[2] & TCP_FIN, "device FIN acknowledged and answered with our own FIN")
    hs.input(eth_frame(hs.mac, dev_mac, ETH_IP, tcp_segment(hs.device_ip, sink2, 6300, 8883, sq + 1, fc.snd_nxt,
                                                         TCP_ACK, 8192)))
    hs.tick(32_100_000)
    check((sink2, 8883, hs.device_ip, 6300) not in hs.conns,
          "...and the connection is gone once the device acknowledges that FIN")
    rc_, sq = open_capture(hs, out7, sink2, 8883, 6301, isn=12000)
    hs.input(eth_frame(hs.mac, dev_mac, ETH_IP, tcp_segment(hs.device_ip, sink2, 6301, 8883, sq, rc_.snd_nxt,
                                                         TCP_RST | TCP_ACK, 0)))
    n_before = len(segs(out7, 6301))
    hs.tick(32_200_000)
    check(rc_.state == "CLOSED" and (sink2, 8883, hs.device_ip, 6301) not in hs.conns
          and len(segs(out7, 6301)) == n_before and any("reset by device" in l for l in logs7),
          "device RST drops the connection at once and nothing more is sent on it")
    hs.input(eth_frame(hs.mac, dev_mac, ETH_IP, tcp_segment(hs.device_ip, sink2, 6301, 8883, sq, 777,
                                                         TCP_ACK | TCP_PSH, 8192, b"late")))
    late = segs(out7, 6301)[-1]
    check(late[2] == (TCP_RST | TCP_ACK) and late[0] == 777 and late[1] == sq + 4,
          "a segment for a connection we no longer know is answered with RST, so the firmware does not hang")

    print("== TCP: window, segmentation, retransmission, duplicates ==")
    logs8, out8 = [], []
    ts = NetStack(bytes.fromhex("020000000001"), log=logs8.append, gateway=False)
    ts.output = out8.append
    ts.ip, ts.device_ip, ts.device_mac = str2ip("192.168.4.100"), str2ip("192.168.4.1"), dev_mac
    tc = TcpConn(ts, ts.ip, 41000, ts.device_ip, 80, "forward")
    ts.conns[(ts.ip, 41000, ts.device_ip, 80)] = tc
    tc.state, tc.rcv_nxt, tc.peer_window = "ESTABLISHED", 100, 3000
    tc.unacked_seq = tc.snd_nxt
    blob = bytes(i & 0xFF for i in range(10000))
    tc.queue(blob)
    tc.pump(0)
    first = [s for s in segs(out8) if s[3]]
    check(sum(len(s[3]) for s in first) <= 3000 and all(len(s[3]) <= MSS for s in first),
          "10000 bytes queued: no more than the device's 3000-byte window in flight, segments <= MSS")
    resend_from = len(segs(out8))
    tc.pump(RETRANSMIT_US + 1)
    again = [s for s in segs(out8)[resend_from:] if s[3]]
    check(again and again[0][0] == first[0][0] and again[0][3] == first[0][3],
          "no ACK within the retransmit time: the unacknowledged data is sent again from the same seq")
    got, t = b"", RETRANSMIT_US + 2
    while len(got) < len(blob) and t < 50_000_000:
        sent = [s for s in segs(out8) if s[3]]
        # the device acknowledges everything it has seen so far, in order
        stream = {}
        for sq_, _, _, p, _, _ in sent:
            stream[sq_] = p
        seq0 = first[0][0]
        got = b""
        while seq0 + len(got) in stream:
            got += stream[seq0 + len(got)]
        tc.on_segment(100, (seq0 + len(got)) & 0xFFFFFFFF, TCP_ACK, 3000, b"", t)
        tc.pump(t)
        t += 1000
    check(got == blob, "all 10000 bytes arrive in order once the device keeps acknowledging")
    n_cap = len(tc.to_host)
    tc.on_segment(100, tc.snd_nxt, TCP_ACK | TCP_PSH, 3000, b"abc", t)
    tc.on_segment(100, tc.snd_nxt, TCP_ACK | TCP_PSH, 3000, b"abc", t)
    check(len(tc.to_host) == n_cap + 1 and tc.rcv_nxt == 103,
          "a retransmitted (duplicate) segment from the device is delivered once")
    tc.on_segment(200, tc.snd_nxt, TCP_ACK | TCP_PSH, 3000, b"later", t)
    check(len(tc.to_host) == n_cap + 1 and tc.rcv_nxt == 103,
          "an out-of-order segment is not delivered ahead of the gap")
    check(segs(out8)[-1][1] == 103, "...and is answered with an ACK for what was actually received")

    print("== SYN retransmission ==")
    logs9, out9 = [], []
    ss = NetStack(bytes.fromhex("020000000001"), log=logs9.append, gateway=False, http_gets=["/x"])
    ss.output = out9.append
    ss.ip, ss.device_ip, ss.device_mac = str2ip("192.168.4.100"), str2ip("192.168.4.1"), dev_mac
    ss.link, ss.probe_sent, ss.dhcp_state = True, True, "BOUND"
    ss.tick(1_000_000)
    syns = [s for s in segs(out9) if s[2] == TCP_SYN]
    check(len(syns) == 1, "first SYN sent")
    ss.tick(1_000_000 + RETRANSMIT_US + 1)
    syns2 = [s for s in segs(out9) if s[2] == TCP_SYN]
    check(len(syns2) == 2 and syns2[1][0] == syns2[0][0], "no SYN-ACK: the SYN is resent with the same sequence number")
    t = 1_000_000 + RETRANSMIT_US + 1
    for _ in range(SYN_MAX_TRIES + 2):
        t += RETRANSMIT_US + 1
        ss.tick(t)
    check(any("no SYN-ACK after" in l for l in logs9) and not any(c.kind == "client" and c.state == "SYN_SENT"
                                                                for c in ss.conns.values()),
          "after %d resends the attempt is abandoned instead of hanging" % SYN_MAX_TRIES)

    print("== --net-forward: a real listener on 127.0.0.1 into the device ==")
    tmp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tmp.bind(("127.0.0.1", 0))
    fport = tmp.getsockname()[1]
    tmp.close()
    logs5, out5 = [], []
    fw = NetStack(bytes.fromhex("020000000001"), log=logs5.append, gateway=False, forwards=[(fport, 80)])
    fw.output = out5.append
    fw.ip, fw.device_ip, fw.device_mac = str2ip("192.168.4.100"), str2ip("192.168.4.1"), dev_mac
    fw.link, fw.probe_sent, fw.dhcp_state = True, True, "BOUND"
    check(any("forwarding 127.0.0.1:%d -> device:80" % fport in l for l in logs5),
          "listening on 127.0.0.1:%d" % fport)
    logs6 = []
    NetStack(bytes.fromhex("020000000002"), log=logs6.append, gateway=False, forwards=[(fport, 80)])
    check(any("cannot listen on 127.0.0.1:%d" % fport in l for l in logs6),
          "a second instance on the same port is refused, not silently sharing it")
    browser = socket.create_connection(("127.0.0.1", fport), timeout=5)

    def tcp_out(frames):
        # [(sport, dport, flags, payload)] of the TCP segments sent towards the device
        res = []
        for f in frames:
            if f[12:14] == b"\x08\x00" and f[14 + 9] == IP_TCP:
                t = f[14 + 20:]
                res.append((struct.unpack("!H", t[0:2])[0], struct.unpack("!H", t[2:4])[0],
                            t[13], t[(t[12] >> 4) * 4:]))
        return res

    deadline = time.time() + 5
    while time.time() < deadline and not any(fl == TCP_SYN and dp == 80 for _, dp, fl, _ in tcp_out(out5)):
        fw.tick(20_000_000); time.sleep(0.02)
    check(any(fl == TCP_SYN and dp == 80 for _, dp, fl, _ in tcp_out(out5)),
          "browser connect accepted -> SYN to the device's port 80")
    fc = [c for c in fw.conns.values() if c.kind == "forward"][0]
    fw.input(eth_frame(fw.mac, dev_mac, ETH_IP, tcp_segment(fw.device_ip, fw.ip, 80, fc.lport, 9000, fc.snd_nxt,
                                                         TCP_SYN | TCP_ACK, 4096)))
    request = b"GET /index HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
    browser.sendall(request)
    deadline = time.time() + 5
    while time.time() < deadline and not any(p == request for _, _, _, p in tcp_out(out5)):
        fw.tick(21_000_000); time.sleep(0.02)
    check(any(p == request for _, _, _, p in tcp_out(out5)), "the browser's request reaches the device")
    page = b"HTTP/1.1 200 OK\r\nContent-type: text/html\r\n\r\n<html>OBK panel</html>"
    # The device's last segment carries the FIN too: the page must still arrive whole.
    fw.input(eth_frame(fw.mac, dev_mac, ETH_IP, tcp_segment(fw.device_ip, fw.ip, 80, fc.lport, 9001, fc.snd_nxt,
                                                         TCP_ACK | TCP_PSH | TCP_FIN, 4096, page)))
    browser.settimeout(5)
    got = b""
    try:
        while True:
            fw.tick(22_000_000)
            chunk = browser.recv(65536)
            if not chunk:
                break
            got += chunk
    except socket.timeout:
        pass
    check(got == page, "the whole page reaches the browser even though data and FIN came in one segment")
    check(got == page and not browser.recv(1), "then the browser sees the connection closed")
    browser.close()
    # A process that runs more than once (the GUI) must get its port back.
    fw.close()
    check(not fw.io.thread.is_alive(), "close() stops the stack's host thread")
    logs7 = []
    again = NetStack(bytes.fromhex("020000000003"), log=logs7.append, gateway=False, forwards=[(fport, 80)])
    check(any("forwarding 127.0.0.1:%d -> device:80" % fport in l for l in logs7),
          "after close() the same port can be forwarded again by the next run")
    again.close()

    print("== --net-out: device TCP relayed through a host socket (to 127.0.0.1 only) ==")
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0)); srv.listen(1)
    port = srv.getsockname()[1]
    logs4, out4 = [], []
    gw = NetStack(bytes.fromhex("020000000001"), log=logs4.append, gateway=True, net_out=True)
    gw.output = out4.append
    gw.device_ip, gw.device_mac = str2ip("192.168.1.100"), dev_mac
    gw.arp[gw.device_ip] = dev_mac
    lo = str2ip("127.0.0.1")
    gw.input(eth_frame(gw.mac, dev_mac, ETH_IP, tcp_segment(gw.device_ip, lo, 5555, port, 100, 0, TCP_SYN, 8192)))
    srv.settimeout(5)
    peer_sock, _ = srv.accept()
    deadline = time.time() + 5
    while time.time() < deadline and not (out4 and out4[-1][14 + 20 + 13] & TCP_SYN):
        gw.tick(1); time.sleep(0.02)
    sa = out4[-1][14 + 20:]
    check(sa[13] == (TCP_SYN | TCP_ACK), "device SYN -> real host connect -> SYN-ACK back to the device")
    rc = gw.conns[(lo, port, gw.device_ip, 5555)]
    gw.input(eth_frame(gw.mac, dev_mac, ETH_IP, tcp_segment(gw.device_ip, lo, 5555, port, 101, rc.snd_nxt,
                                                         TCP_ACK | TCP_PSH, 8192, b"hello host")))
    peer_sock.settimeout(5)
    check(peer_sock.recv(100) == b"hello host", "device bytes arrive at the real host socket")
    peer_sock.sendall(b"hello device")
    deadline = time.time() + 5
    got = b""
    while time.time() < deadline and not got:
        gw.tick(2_000_000)
        for f in out4:
            if f[12:14] == b"\x08\x00" and f[14 + 9] == IP_TCP and f[14 + 40:] == b"hello device":
                got = f[14 + 40:]
        time.sleep(0.02)
    check(got == b"hello device", "host reply relayed back to the device")
    peer_sock.close(); srv.close()

    print("== --net-out: DNS through the host resolver, UDP relayed both ways ==")
    t_us = 3_000_000
    n4 = len(out4)
    dns_ask(gw, "localhost", txid=0x5151)
    check(not udp_out(out4[n4:], sport=53), "an online lookup is not answered from the sinkhole")
    deadline = time.time() + 10
    while time.time() < deadline and not udp_out(out4[n4:], sport=53):
        t_us += 10_000; gw.tick(t_us); time.sleep(0.02)
    rr = udp_out(out4[n4:], sport=53)
    check(rr and rr[0][3][:2] == b"\x51\x51" and rr[0][3][-4:] == lo,
          "the name is resolved by the host (localhost -> 127.0.0.1) and the answer reaches the device")
    check(any("[NET] DNS localhost -> 127.0.0.1" in l for l in logs4), "the lookup is logged")
    n4 = len(out4)
    dns_ask(gw, "localhost", txid=0x5252)
    rr = udp_out(out4[n4:], sport=53)
    check(rr and rr[0][3][:2] == b"\x52\x52" and rr[0][3][-4:] == lo, "a repeat lookup is answered at once from the cache")
    us = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    us.bind(("127.0.0.1", 0)); us.settimeout(5)
    uport = us.getsockname()[1]
    gw.input(eth_frame(gw.mac, dev_mac, ETH_IP, udp_packet(gw.device_ip, lo, 5600, uport, b"ping udp")))
    data, addr = us.recvfrom(100)
    check(data == b"ping udp", "a device datagram leaves through a host UDP socket")
    gw.input(eth_frame(gw.mac, dev_mac, ETH_IP, udp_packet(gw.device_ip, lo, 5600, uport, b"again")))
    data2, addr2 = us.recvfrom(100)
    check(data2 == b"again" and addr2 == addr and sum("relayed" in l and ":5600 ->" in l for l in logs4) == 1,
          "the flow keeps its host socket: same source port, logged once")
    n4 = len(out4)
    us.sendto(b"pong udp", addr)
    deadline = time.time() + 5
    while time.time() < deadline and not udp_out(out4[n4:], dport=5600):
        t_us += 10_000; gw.tick(t_us); time.sleep(0.02)
    rr = udp_out(out4[n4:], dport=5600)
    check(rr and rr[0][0] == lo and rr[0][1] == uport and rr[0][3] == b"pong udp",
          "the host's reply comes back to the device from the address it wrote to")
    us.close()

    print("\nAll %d netstack self-tests passed." % n)
    return n


if __name__ == "__main__":
    _run_selftests()
