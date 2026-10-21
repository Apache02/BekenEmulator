"""WPA2-PSK (RSN): what an access point needs to let an encrypted station on.

The emulator's virtual access point could only ever offer an OPEN network, so
a paired device that stored a protected network could see it in a scan and
never join it. This module is the missing half: the RSN advertisement, the key
derivation, and the four-way handshake an authenticator runs.

None of this is a weakening of anything. Both sides already share the
passphrase - the emulator is told it on the command line, and the device has it
in its own flash - and the handshake is the standard proof that each holds it.

Layout of an EAPOL-Key frame (802.1X-2004 header, then the 802.11i key
descriptor), which is what all four messages are:

    0   version (2)              1   type (3 = EAPOL-Key)
    2   body length (2 bytes, big endian: everything from offset 4)
    4   descriptor type (2 = RSN)
    5   key information (2)      7   key length (2)
    9   replay counter (8)      17   key nonce (32)
    49  key IV (16)             65   key RSC (8)
    73  reserved (8)            81   key MIC (16)
    97  key data length (2)     99   key data

The key-information bits say which message it is; see the M1..M4 constants.
"""
import hashlib
import hmac
import os
import struct

ETH_EAPOL = 0x888E                  # ethertype carrying these frames
EAPOL_VERSION = 2
EAPOL_TYPE_KEY = 3
DESC_TYPE_RSN = 2
KEY_HDR = 99                        # bytes before the key data
MIC_OFF, MIC_LEN = 81, 16

# Key-information bits.
KI_DESC_VER_CCMP = 0x0002           # HMAC-SHA1 MIC + AES key wrap
KI_PAIRWISE = 0x0008
KI_INSTALL = 0x0040
KI_ACK = 0x0080
KI_MIC = 0x0100
KI_SECURE = 0x0200
KI_ENCRYPTED = 0x1000

M1 = KI_DESC_VER_CCMP | KI_PAIRWISE | KI_ACK
M2 = KI_DESC_VER_CCMP | KI_PAIRWISE | KI_MIC
M3 = (KI_DESC_VER_CCMP | KI_PAIRWISE | KI_INSTALL | KI_ACK | KI_MIC | KI_SECURE
      | KI_ENCRYPTED)
M4 = KI_DESC_VER_CCMP | KI_PAIRWISE | KI_MIC | KI_SECURE

# The RSN information element for WPA2-PSK with CCMP, as an access point
# advertises it: version 1, CCMP for both group and pairwise, PSK authentication.
OUI_RSN = b"\x00\x0f\xac"
CIPHER_CCMP, AKM_PSK = 4, 2
RSN_IE_BODY = (struct.pack("<H", 1)
               + OUI_RSN + bytes([CIPHER_CCMP])
               + struct.pack("<H", 1) + OUI_RSN + bytes([CIPHER_CCMP])
               + struct.pack("<H", 1) + OUI_RSN + bytes([AKM_PSK])
               + struct.pack("<H", 0))
IE_RSN = 48
# The same advertisement as an element, ready to drop into a frame. Message 3
# must repeat it verbatim: the station compares it against what it saw in the
# beacon, and a mismatch is a downgrade attempt as far as it is concerned. A
# station that finds one says so with deauthentication reason 17.
RSN_IE = bytes([IE_RSN, len(RSN_IE_BODY)]) + RSN_IE_BODY
CAP_PRIVACY = 0x0010                # the capability bit that says "protected"
# What a receiving MAC reports once it has decrypted a frame (hal_desc.h's
# statinfo decrStatus field; the same value as wifimac.RX_HD_DECR_CCMPSUCCESS).
# Frames handed to a device on a protected link carry this, because real
# hardware decrypts before the firmware sees anything.
DECR_CCMP_SUCCESS = 0x1C


def pmk(passphrase, ssid):
    """The pairwise master key: the passphrase stretched with the network name.

    This is the one slow step by design (4096 iterations), and it is why the
    network name is part of the key - the same passphrase on a differently
    named network gives a different master key.
    """
    if isinstance(passphrase, str):
        passphrase = passphrase.encode("utf-8")
    if isinstance(ssid, str):
        ssid = ssid.encode("utf-8")
    return hashlib.pbkdf2_hmac("sha1", passphrase, ssid, 4096, 32)


def prf(key, label, data, nbytes):
    """IEEE 802.11 pseudo-random function: HMAC-SHA1 run with a counter."""
    if isinstance(label, str):
        label = label.encode("ascii")
    out, i = b"", 0
    while len(out) < nbytes:
        out += hmac.new(key, label + b"\x00" + data + bytes([i]), hashlib.sha1).digest()
        i += 1
    return out[:nbytes]


def ptk(master, aa, spa, anonce, snonce):
    """Derive the session keys. Returns (kck, kek, tk).

    Both ends sort the two addresses and the two nonces the same way, so each
    derives the identical key without either sending it.
    """
    data = (min(aa, spa) + max(aa, spa) + min(anonce, snonce) + max(anonce, snonce))
    full = prf(master, "Pairwise key expansion", data, 48)
    return full[0:16], full[16:32], full[32:48]


def key_mic(kck, frame):
    """The MIC over a whole EAPOL frame, computed with the MIC field zeroed."""
    blank = bytearray(frame)
    blank[MIC_OFF:MIC_OFF + MIC_LEN] = bytes(MIC_LEN)
    return hmac.new(kck, bytes(blank), hashlib.sha1).digest()[:MIC_LEN]


def _aes_ecb(key):
    try:
        from Crypto.Cipher import AES
    except ImportError:
        from Cryptodome.Cipher import AES
    return AES.new(key, AES.MODE_ECB)


def aes_key_wrap(kek, plain):
    """RFC 3394 key wrap, which is how the group key travels inside message 3."""
    if len(plain) % 8:
        raise ValueError("key wrap needs a multiple of 8 bytes, got %d" % len(plain))
    n = len(plain) // 8
    a = 0xA6A6A6A6A6A6A6A6
    r = [plain[i * 8:(i + 1) * 8] for i in range(n)]
    enc = _aes_ecb(kek)
    for j in range(6):
        for i in range(1, n + 1):
            b = enc.encrypt(struct.pack(">Q", a) + r[i - 1])
            a = struct.unpack(">Q", b[:8])[0] ^ (n * j + i)
            r[i - 1] = b[8:]
    return struct.pack(">Q", a) + b"".join(r)


def aes_key_unwrap(kek, wrapped):
    """The inverse; raises ValueError if the integrity check fails."""
    if len(wrapped) % 8 or len(wrapped) < 16:
        raise ValueError("bad wrapped length %d" % len(wrapped))
    n = len(wrapped) // 8 - 1
    a = struct.unpack(">Q", wrapped[:8])[0]
    r = [wrapped[8 * (i + 1):8 * (i + 2)] for i in range(n)]
    dec = _aes_ecb(kek)
    for j in range(5, -1, -1):
        for i in range(n, 0, -1):
            b = dec.decrypt(struct.pack(">Q", a ^ (n * j + i)) + r[i - 1])
            a = struct.unpack(">Q", b[:8])[0]
            r[i - 1] = b[8:]
    if a != 0xA6A6A6A6A6A6A6A6:
        raise ValueError("key unwrap integrity check failed")
    return b"".join(r)


def gtk_kde(gtk, key_id=1):
    """The group key, wrapped in the attribute that carries it in message 3."""
    body = OUI_RSN + b"\x01" + bytes([key_id & 3, 0]) + gtk
    return b"\xdd" + bytes([len(body)]) + body


def pad_key_data(data):
    """Key data is wrapped in 8-byte blocks, so it is padded first."""
    if len(data) % 8 == 0:
        return data
    data += b"\xdd"
    while len(data) % 8:
        data += b"\x00"
    return data


def build_eapol_key(key_info, replay, nonce=b"", key_data=b"", kck=None, key_len=16,
                    rsc=b""):
    """Assemble one EAPOL-Key message, adding the MIC when a KCK is given."""
    nonce = (nonce or b"")[:32].ljust(32, b"\x00")
    rsc = (rsc or b"")[:8].ljust(8, b"\x00")
    body = (bytes([DESC_TYPE_RSN])
            + struct.pack(">HH", key_info, key_len)
            + struct.pack(">Q", replay)
            + nonce + bytes(16) + rsc + bytes(8) + bytes(MIC_LEN)
            + struct.pack(">H", len(key_data)) + key_data)
    frame = bytes([EAPOL_VERSION, EAPOL_TYPE_KEY]) + struct.pack(">H", len(body)) + body
    if kck is not None:
        mic = key_mic(kck, frame)
        frame = frame[:MIC_OFF] + mic + frame[MIC_OFF + MIC_LEN:]
    return frame


def parse_eapol_key(data):
    """Read an EAPOL-Key message, or None if this is not one."""
    if len(data) < KEY_HDR or data[1] != EAPOL_TYPE_KEY:
        return None
    if data[4] != DESC_TYPE_RSN:
        return None
    key_info, key_len = struct.unpack(">HH", data[5:9])
    kd_len = struct.unpack(">H", data[97:99])[0]
    return {"key_info": key_info, "key_len": key_len,
            "replay": struct.unpack(">Q", data[9:17])[0],
            "nonce": data[17:49], "mic": data[MIC_OFF:MIC_OFF + MIC_LEN],
            "key_data": data[KEY_HDR:KEY_HDR + kd_len],
            "frame": bytes(data),
            "pairwise": bool(key_info & KI_PAIRWISE),
            "has_mic": bool(key_info & KI_MIC),
            "ack": bool(key_info & KI_ACK),
            "secure": bool(key_info & KI_SECURE),
            "install": bool(key_info & KI_INSTALL)}


class Authenticator:
    """The access point's side of the four-way handshake, one per station.

    Drive it with start() and then feed it whatever the station sends. It
    answers with the next message, or None when there is nothing to say. When
    .done is set the station has proved it holds the passphrase and .tk is the
    key the hardware would use for the traffic that follows.
    """

    def __init__(self, passphrase, ssid, ap_mac, sta_mac, anonce=None, gtk=None,
                 log=None):
        self.master = pmk(passphrase, ssid)
        self.aa, self.spa = ap_mac, sta_mac
        self.anonce = anonce or os.urandom(32)
        self.gtk = gtk or os.urandom(16)
        self.log = log or (lambda *a: None)
        self.replay = 0
        self.snonce = None
        self.kck = self.kek = self.tk = None
        self.done = False
        self.state = "INIT"

    def start(self):
        """Message 1: the access point's nonce, unprotected because no key exists yet."""
        self.replay += 1
        self.state = "M1"
        return build_eapol_key(M1, self.replay, nonce=self.anonce)

    def on_message(self, data):
        """Handle a message from the station; returns the reply, or None."""
        msg = parse_eapol_key(data)
        if msg is None or not msg["pairwise"]:
            return None
        # Message 2 carries the station's nonce, and the first proof it holds
        # the passphrase: a MIC we can only check once we derive the keys.
        if self.state == "M1" and msg["has_mic"] and not msg["secure"]:
            if msg["replay"] != self.replay:
                return None                 # not the counter we sent in message 1
            self.snonce = msg["nonce"]
            # Derive into locals and check the MIC BEFORE storing the keys, so a
            # failed handshake never leaves self.tk holding a bogus key: .tk set
            # means the station proved itself, nothing less.
            kck, kek, tk = ptk(self.master, self.aa, self.spa, self.anonce, self.snonce)
            if key_mic(kck, msg["frame"]) != msg["mic"]:
                self.state = "FAILED"
                self.log("[WIFI] four-way handshake: the station's key does not match "
                         "the passphrase this network was given")
                return None
            self.kck, self.kek, self.tk = kck, kek, tk
            self.replay += 1
            self.state = "M3"
            # The advertisement first, then the group key: the station checks
            # the former matches the beacon before it accepts the latter.
            wrapped = aes_key_wrap(self.kek, pad_key_data(RSN_IE + gtk_kde(self.gtk)))
            return build_eapol_key(M3, self.replay, nonce=self.anonce,
                                   key_data=wrapped, kck=self.kck)
        # Message 4 only confirms; by here both sides already hold the key.
        if self.state == "M3" and msg["has_mic"] and msg["secure"]:
            if msg["replay"] != self.replay:
                return None                 # not the counter we sent in message 3
            if key_mic(self.kck, msg["frame"]) != msg["mic"]:
                self.state = "FAILED"
                return None
            self.state = "DONE"
            self.done = True
            return None
        return None


# ---------------------------------------------------------------------------
# Self-tests. Run: python src/wpa2.py
# ---------------------------------------------------------------------------
def _run_selftests():
    n = 0

    def check(cond, msg):
        nonlocal n
        assert cond, "FAIL: " + msg
        n += 1
        print("  [PASS]", msg)

    print("== master key, against the published IEEE 802.11i vectors ==")
    check(pmk("password", "IEEE").hex() ==
          "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e",
          "passphrase 'password' on network 'IEEE' gives the documented key")
    check(pmk("ThisIsAPassword", "ThisIsASSID").hex() ==
          "0dc0d6eb90555ed6419756b9a15ec3e3209b63df707dd508d14581f8982721af",
          "...and so does the second published vector")
    check(pmk("password", "IEEE") != pmk("password", "OTHER"),
          "the network name is part of the key, so the same passphrase elsewhere differs")

    print("== session keys ==")
    aa, spa = bytes.fromhex("020000000001"), bytes.fromhex("c8478c000000")
    an, sn = bytes(range(32)), bytes(range(32, 64))
    m = pmk("secret123", "BekenSim")
    kck, kek, tk = ptk(m, aa, spa, an, sn)
    check(len(kck) == 16 and len(kek) == 16 and len(tk) == 16,
          "the derivation yields three 16-byte keys")
    check((kck, kek, tk) == ptk(m, spa, aa, sn, an),
          "both ends derive the same keys although they see the addresses and nonces "
          "in the opposite order")
    check(ptk(m, aa, spa, an, sn) != ptk(m, aa, spa, an, bytes(32)),
          "a different station nonce gives different session keys")
    check(len(set(prf(m, "Pairwise key expansion", b"x", k) for k in (16, 32, 48))) == 3,
          "the function stretches to whatever length is asked for")

    print("== key wrap (RFC 3394) ==")
    # The RFC's own first test vector: 128-bit key, 128-bit data.
    kek_v = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
    plain_v = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
    check(aes_key_wrap(kek_v, plain_v).hex().upper() ==
          "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5",
          "wrapping the RFC's test data gives the RFC's answer")
    check(aes_key_unwrap(kek_v, aes_key_wrap(kek_v, plain_v)) == plain_v,
          "and unwrapping returns the original")
    bad = bytearray(aes_key_wrap(kek_v, plain_v))
    bad[3] ^= 1
    try:
        aes_key_unwrap(kek_v, bytes(bad))
        ok = False
    except ValueError:
        ok = True
    check(ok, "a tampered wrap is rejected rather than returning rubbish")

    print("== message framing ==")
    f = build_eapol_key(M1, 1, nonce=an)
    check(f[0] == EAPOL_VERSION and f[1] == EAPOL_TYPE_KEY,
          "a message is an EAPOL frame of type key")
    check(struct.unpack(">H", f[2:4])[0] == len(f) - 4,
          "its length field counts everything after the header")
    p = parse_eapol_key(f)
    check(p["nonce"] == an and p["replay"] == 1 and p["ack"] and not p["has_mic"],
          "message 1 is read back: nonce, counter, asking for a reply, no MIC yet")
    check(parse_eapol_key(b"\x02\x00\x00\x05hello") is None
          and parse_eapol_key(b"") is None,
          "something that is not one of these messages is not read as one")
    signed = build_eapol_key(M2, 1, nonce=sn, kck=kck)
    check(key_mic(kck, signed) == parse_eapol_key(signed)["mic"],
          "a signed message carries a MIC computed over itself with the field blanked")
    check(key_mic(kck, signed) != key_mic(bytes(16), signed),
          "and that MIC depends on the key, which is what makes it proof")

    print("== the four-way handshake ==")
    def station(passphrase, ssid, aa_, spa_, msg1, msg3=None, state={}):
        """The station's half, enough to drive the authenticator honestly."""
        p = parse_eapol_key(msg1)
        if msg3 is None:
            state["snonce"] = sn
            m_ = pmk(passphrase, ssid)
            state["keys"] = ptk(m_, aa_, spa_, p["nonce"], sn)
            return build_eapol_key(M2, p["replay"], nonce=sn, kck=state["keys"][0])
        return build_eapol_key(M4, parse_eapol_key(msg3)["replay"], kck=state["keys"][0])

    logs = []
    auth = Authenticator("secret123", "BekenSim", aa, spa, anonce=an, gtk=bytes(range(16)),
                         log=logs.append)
    one = auth.start()
    check(parse_eapol_key(one)["nonce"] == an and not auth.done,
          "it opens with its own nonce and is not yet satisfied")
    st = {}
    two = station("secret123", "BekenSim", aa, spa, one, state=st)
    three = auth.on_message(two)
    check(three is not None and parse_eapol_key(three)["install"],
          "a station that holds the passphrase gets message 3, telling it to install the key")
    kd = aes_key_unwrap(auth.kek, parse_eapol_key(three)["key_data"])
    check(kd.startswith(RSN_IE),
          "...which repeats the advertisement the station saw in the beacon, so it can "
          "satisfy itself nobody downgraded the network underneath it")
    gtk_part = kd[len(RSN_IE):]
    check(gtk_part.startswith(b"\xdd\x16\x00\x0f\xac\x01"),
          "and then the group key, wrapped so only that station can read it")
    # dd, length, 3-byte OUI, type, then two flag bytes, then the key itself.
    check(gtk_part[8:24] == bytes(range(16)),
          "which is the group key the access point chose")
    check(parse_eapol_key(three)["replay"] > parse_eapol_key(one)["replay"],
          "each message carries a higher counter, so an old one cannot be replayed")
    four = station("secret123", "BekenSim", aa, spa, one, msg3=three, state=st)
    auth.on_message(four)
    check(auth.done and auth.tk == st["keys"][2],
          "after message 4 both sides hold the identical traffic key")

    print("== a station with the wrong passphrase ==")
    logs2 = []
    auth2 = Authenticator("secret123", "BekenSim", aa, spa, anonce=an, log=logs2.append)
    one2 = auth2.start()
    wrong = station("not-the-password", "BekenSim", aa, spa, one2, state={})
    check(auth2.on_message(wrong) is None and not auth2.done,
          "it gets no message 3 and the handshake does not complete")
    check(auth2.state == "FAILED" and any("does not match the passphrase" in l for l in logs2),
          "and the mismatch is reported rather than passing silently")
    check(auth2.tk is None,
          "a failed handshake leaves no traffic key behind, so .tk set always means success")

    print("== a message with the wrong replay counter is ignored ==")
    auth3 = Authenticator("secret123", "BekenSim", aa, spa, anonce=an)
    one3 = auth3.start()
    stale = parse_eapol_key(station("secret123", "BekenSim", aa, spa, one3, state={}))
    forged = build_eapol_key(M2, 999, nonce=stale["nonce"],
                             kck=ptk(pmk("secret123", "BekenSim"), aa, spa, an, stale["nonce"])[0])
    check(auth3.on_message(forged) is None and auth3.state == "M1" and not auth3.done,
          "a message 2 that does not echo the counter we sent is dropped, even with a valid MIC, "
          "and the handshake stays where it was")

    print("== what the access point advertises ==")
    check(RSN_IE_BODY.hex() == "0100000fac04" + "0100000fac04" + "0100000fac02" + "0000",
          "the advertisement offers CCMP for both cipher types and passphrase authentication")
    check(len(RSN_IE_BODY) == 20, "which is 20 bytes, the usual length for this element")

    print("\nAll %d WPA2 self-tests passed." % n)
    return n


if __name__ == "__main__":
    _run_selftests()
