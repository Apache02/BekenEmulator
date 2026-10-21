"""Recover Tuya's on-flash configuration from a BK7231 dump.

Implements the same scheme BK7231GUIFlashTool and bk7231tools use, rather than
scraping plaintext (which only works on a handful of older images):

  1. Find the key block - a 4K block whose first AES-ECB decryption under the
     fixed master key starts with MAGIC_KEY. Its header is
     `<I magic, I crc, 16s inner_key>`, and that inner key is exactly what the
     firmware prints as "get key:" during boot.
  2. Build the data key from two fixed strings plus that inner key, byte-wise:
        data_key[i] = (KEY_PART_1[i & 3] + KEY_PART_2[i] + inner_key[i]) % 256
  3. AES-ECB decrypt the storage area with it. Out come the stored records:
     the network block, the datapoint schema, the pin/`user_param_key` map.

Older firmware keeps `user_param_key` in the clear, so a plaintext scan is kept
as a fallback for those.
"""
import json
import re
import struct

try:
    from Crypto.Cipher import AES
except ImportError:
    try:
        from Cryptodome.Cipher import AES
    except ImportError:                 # extraction is optional; tests never depend on it
        AES = None

KEY_MASTER = b"qwertyuiopasdfgh"
KEY_PART_1 = b"8710_2M"
KEY_PART_2 = b"HHRRQbyemofrtytf"
MAGIC_KEY = 0x13579753

STORAGE_FROM = 0x1C0000       # storage/user area sits above the application
BLOCK = 0x1000


def _data_aes(inner_key):
    key = bytearray(16)
    for i in range(16):
        key[i] = (KEY_PART_1[i & 0b11] + KEY_PART_2[i] + inner_key[i]) % 256
    return AES.new(bytes(key), AES.MODE_ECB)


def find_key_block(data):
    """Locate the key block and return (offset, inner_key), or (None, None)."""
    if AES is None:
        return None, None
    master = AES.new(KEY_MASTER, AES.MODE_ECB)
    for off in range(STORAGE_FROM, len(data) - 32, BLOCK):
        head = master.decrypt(data[off:off + 32])
        magic, _crc = struct.unpack("<II", head[:8])
        if magic == MAGIC_KEY:
            return off, head[8:24]
    return None, None


def decrypt_storage(data, inner_key):
    """Decrypt the whole storage area with the derived data key."""
    seg = data[STORAGE_FROM:]
    seg = seg[:len(seg) // 16 * 16]
    return _data_aes(inner_key).decrypt(seg)


# --- record recovery ---------------------------------------------------------

def _json_objects(buf, limit=4000):
    """Yield balanced {...} spans of printable text.

    A plain regex cannot do this: the datapoint records nest
    ({"mode":"rw","property":{...},"id":103}), so a non-greedy match stops at
    the inner closing brace and yields something json.loads rejects.
    """
    n = len(buf)
    i = buf.find(b"{")
    while 0 <= i < n:
        depth = 0
        for j in range(i, min(i + limit, n)):
            c = buf[j]
            if not (32 <= c <= 126 or c in (9, 10, 13)):
                break                       # ran into binary - not a record
            if c == 0x7B:
                depth += 1
            elif c == 0x7D:
                depth -= 1
                if depth == 0:
                    yield i, buf[i:j + 1]
                    i = buf.find(b"{", j + 1)
                    break
        else:
            i = buf.find(b"{", i + 1)
            continue
        if depth != 0:
            i = buf.find(b"{", i + 1)


_JSON = re.compile(rb"\{[ -~\r\n\t]{15,4000}?\}")   # kept for the loose fallback
# Tuya's pin map uses unquoted keys: {rl1_pin:6,module:CB2S,crc:74,}
_LOOSE = re.compile(rb"\{[a-zA-Z0-9_]+:[ -~]{20,2000}?\}")


def _decode(blob):
    try:
        return json.loads(blob.decode("utf-8", "replace"))
    except Exception:
        return None


_NETWORK_SECRET_FIELDS = {
    "ssid", "passwd", "password", "ap_ssid", "ap_passwd",
    "pskKey", "psk_key", "psk30_key", "auth_key", "token", "reg_key",
}

_STORED_ID_FIELDS = (
    "uuid", "auth_key", "ap_ssid", "pskKey", "psk_key", "psk30_key",
)
_MIN_STORED_ID_LEN = 8
_MAX_STORED_ID_LEN = 512


def _stored_id_value(buf, name):
    """Return one bounded ASCII value from a loose storage record.

    Valid JSON is decoded separately in :func:`_collect`.  This fallback is
    for the adjacent, torn, or ``name=value`` records found in some storage
    sectors.  Tuya PSK 3.0 values use standard Base64, so ``+``, ``/`` and
    padding ``=`` are part of the token.  Requiring a real field separator and
    a trailing record delimiter prevents a damaged printable run from being
    accepted only as a matching prefix.
    """
    key = name.encode("ascii") if isinstance(name, str) else name
    token = rb"([A-Za-z0-9_+/\-=]{%d,%d})" % (
        _MIN_STORED_ID_LEN, _MAX_STORED_ID_LEN)
    pattern = (rb"(?<![A-Za-z0-9_])" + re.escape(key)
               + rb"(?:[\"']?\s*[:=]\s*[\"']?|\s+)"
               + token + rb"(?=$|[\"'\s,;}\]\x00])")
    match = re.search(pattern, buf)
    if match is None:
        return None
    return match.group(1).decode("ascii")


def _network_raw(obj, original):
    """JSON text safe for reports while retaining the record's shape."""
    if not REDACT_SECRETS:
        return original
    safe = dict(obj)
    for name in _NETWORK_SECRET_FIELDS:
        if safe.get(name) not in (None, ""):
            safe[name] = _redact(safe[name])
    return json.dumps(safe, separators=(",", ":"), ensure_ascii=False)


def _split_loose_fields(text):
    """Split a Tuya ``key:value`` record on top-level commas.

    Values are usually scalars, but some light firmwares store arrays such as
    ``irfunset:[[6,02],[7,1e]]``.  A plain ``str.split(',')`` turns every array
    element into a bogus key.  Keep quotes and nested brackets intact instead.
    """
    out, start, depth = [], 0, 0
    quote, escaped = None, False
    for i, char in enumerate(text):
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in ('"', "'"):
            quote = char
        elif char in "[({":
            depth += 1
        elif char in "]) }".replace(" ", ""):
            depth = max(0, depth - 1)
        elif char == "," and depth == 0:
            out.append(text[start:i])
            start = i + 1
    out.append(text[start:])
    return out


def _parse_loose(text):
    out = []
    body = text.strip()
    if body.startswith("{"):
        body = body[1:]
    if body.endswith("}"):
        body = body[:-1]
    for part in _split_loose_fields(body):
        k, sep, v = part.strip().partition(":")
        key = k.strip().strip('"')
        # A damaged record can run into the JSON record after it.  Never turn
        # braces, quotes, or array fragments from that neighbour into fields.
        if sep and re.fullmatch(r"[A-Za-z0-9_]+", key):
            out.append((key, v.strip().strip('"\'')))
    return out


def _collect(buf):
    """Pull the interesting records out of a (decrypted) buffer."""
    found = {"network": None, "dps": [], "pins": [], "ids": {}, "raw": [],
             "tls_mode": None}
    seen_dp = set()
    for _off, blob in _json_objects(buf):
        obj = _decode(blob)
        if not isinstance(obj, dict):
            continue
        # Credential-only KV records do not carry schemaId/productKey/devId,
        # so recover their known fields from every valid JSON object.  Keep
        # the exact decoded string; presentation code masks it below.
        for name in _STORED_ID_FIELDS:
            value = obj.get(name)
            if isinstance(value, (str, int)):
                value = str(value)
                if _MIN_STORED_ID_LEN <= len(value) <= _MAX_STORED_ID_LEN:
                    found["ids"].setdefault(name, value)
        # dy_tls_m is not a credential.  Mode 2 identifies the older Tuya
        # PSK-only/bootstrap path whose firmware may configure the same
        # 32-byte constant as both the TLS key and its clear identity.
        if found["tls_mode"] is None and "dy_tls_m" in obj:
            try:
                found["tls_mode"] = int(obj["dy_tls_m"])
            except (TypeError, ValueError):
                pass
        text = blob.decode("ascii", "replace")
        if "nc_tp" in obj or "ssid" in obj:
            if found["network"] is None:
                found["network"] = obj
                found["raw"].append(_network_raw(obj, text))
        elif "id" in obj and "property" in obj:
            if obj["id"] in seen_dp:        # the schema is stored more than once
                continue
            seen_dp.add(obj["id"])
            found["dps"].append(obj)
            if len(found["raw"]) < 6:
                found["raw"].append(text)
        elif "schemaId" in obj or "productKey" in obj or "devId" in obj:
            found["ids"].update({k: str(v) for k, v in obj.items()
                                 if isinstance(v, (str, int)) and len(str(v)) < 48})
    for m in _LOOSE.finditer(buf):
        blob = m.group()
        # A few dumps have a torn final copy of user_param_key immediately
        # followed by a valid JSON network record.  The loose regex otherwise
        # borrows that JSON's closing brace and presents the two records as
        # one.  Preserve the recoverable prefix and discard the neighbour.
        json_start = blob.find(b'{"', 1)
        if json_start >= 0:
            blob = blob[:json_start].rstrip() + b"}"
        text = blob.decode("ascii", "replace")
        if any(s in text for s in ("_pin", "module", "Jsonver", "jv:")):
            pairs = _parse_loose(text)
            if pairs:
                found["pins"] = pairs
                found["raw"].insert(0, text)
                break
    for name in _STORED_ID_FIELDS:
        value = _stored_id_value(buf, name)
        if value is not None:
            # Prefer an exact json.loads result over the loose fallback.
            found["ids"].setdefault(name, value)
    return found


# --- human-readable summary --------------------------------------------------

# Ported from BK7231GUIFlashTool's GetKeysHumanReadableInternal
# (BK7231Flasher/Utils/TuyaConfig.cs) so the wording matches the tool exactly.
# Each rule is (pattern, template); {n} is the channel number taken from the
# key, {v} is the stored value. Order matters - first match wins.
_PIN_RULES = [
    (r"^led(\d+)_pin$",        "LED (channel {n}) on P{v}"),
    (r"^netled\d+_pin$",       "WiFi LED on P{v}"),
    (r"^netled_pin$",          "WiFi LED on P{v}"),
    (r"^wfst$",                "WiFi LED on P{v}"),
    (r"^wfst_pin$",            "WiFi LED on P{v}"),
    (r"bz_pin_pin",            "Buzzer Pin (TODO) on P{v}"),
    (r"^buzzer_io$",           "Buzzer Pin (TODO) on P{v}"),
    (r"status_led_pin",        "Status LED on P{v}"),
    (r"remote_io",             "RF Remote on P{v}"),
    (r"samp_sw_pin",           "Battery Relay on P{v}"),
    (r"samp_pin",              "Battery ADC on P{v}"),
    (r"i2c_scl_pin",           "I2C SCL on P{v}"),
    (r"i2c_sda_pin",           "I2C SDA on P{v}"),
    (r"alt_pin_pin",           "ALT pin on P{v}"),
    (r"one_wire_pin",          "OneWire IO pin on P{v}"),
    (r"backlit_io_pin",        "Backlit IO pin on P{v}"),
    (r"^max_V$",               "Battery Max Voltage: {v}"),
    (r"^min_V$",               "Battery Min Voltage: {v}"),
    (r"^rl$",                  "Relay (channel 0) on P{v}"),
    (r"^rl(\d+)_pin$",         "Relay (channel {n}) on P{v}"),
    (r"^rl_on(\d+)_pin$",      "Bridge Relay On (channel {n}) on P{v}"),
    (r"^rl_off(\d+)_pin$",     "Bridge Relay Off (channel {n}) on P{v}"),
    (r"^bt_pin$",              "Button (channel 0) on P{v}"),
    (r"^bt$",                  "Button (channel 0) on P{v}"),
    (r"^k(\d+)pin_pin$",       "Button (channel {n}) on P{v}"),
    (r"^bt(\d+)_pin$",         "Button (channel {n}) on P{v}"),
    (r"^door(\d+)_magt_pin$",  "Door Sensor (channel {n}) on P{v}"),
    (r"^onoff(\d+)$",          "TglChannelToggle (channel {n}) on P{v}"),
    (r"gate_sensor_pin_pin",   "Door/Gate sensor on P{v}"),
    (r"basic_pin_pin",         "PIR sensor on P{v}"),
    (r"^ele_pin$",             "BL0937 ELE (CF) on P{v}"),
    (r"^epin$",                "BL0937 ELE (CF) on P{v}"),
    (r"^vi_pin$",              "BL0937 VI (CF1) on P{v}"),
    (r"^ivpin$",               "BL0937 VI (CF1) on P{v}"),
    (r"sel_pin_pin",           "BL0937 SEL on P{v}"),
    (r"^ivcpin$",              "BL0937 SEL on P{v}"),
    (r"^r_pin$",               "LED Red (Channel 1) on P{v}"),
    (r"^g_pin$",               "LED Green (Channel 2) on P{v}"),
    (r"^b_pin$",               "LED Blue (Channel 3) on P{v}"),
    (r"^c_pin$",               "LED Cool (Channel 4) on P{v}"),
    (r"^w_pin$",               "LED Warm (Channel 5) on P{v}"),
    (r"^mic$",                 "Microphone (TODO) on P{v}"),
    (r"^micpin$",              "Microphone (TODO) on P{v}"),
    (r"^ctrl_pin$",            "Control Pin (TODO) on P{v}"),
    (r"^buzzer_pwm$",          "Buzzer Frequency (TODO) is {v}"),
    (r"^irpin$",               "IR Receiver is on P{v}"),
    (r"^infrr$",               "IR Receiver is on P{v}"),
    (r"^infre$",               "IR Transmitter is on P{v}"),
    (r"^reset_pin$",           "Button is on P{v}"),
    (r"^pwmhz$",               "PWM Frequency {v}"),
    (r"^pirsense_pin$",        "PIR Sensitivity {v}"),
    (r"^pirlduty$",            "PIR Low Duty {v}"),
    (r"^pirfreq$",             "PIR Frequency {v}"),
    (r"^pirmduty$",            "PIR High Duty {v}"),
    (r"^pirin_pin$",           "PIR Input {v}"),
    (r"^mosi$",                "SPI MOSI {v}"),
    (r"^miso$",                "SPI MISO {v}"),
    (r"^SCL$",                 "SPI SCL {v}"),
    (r"^CS$",                  "SPI CS {v}"),
    (r"^total_bt_pin$",        "Pair/Toggle All Button on P{v}"),
]
_PIN_RULES = [(re.compile(p), t) for p, t in _PIN_RULES]


def describe_pin(key, value):
    """Return the tool's bullet text for a key, or None if it is not a pin key."""
    for rx, template in _PIN_RULES:
        m = rx.search(key)
        if m:
            n = m.group(1) if m.groups() else ""
            return template.format(n=n, v=value)
    return None


_NAMES = {
    "module": "Tuya module", "jv": "Config version", "Jsonver": "Config version",
    "crc": "Config checksum", "category": "Product category",
    "ch_num": "Channels (gangs)", "net_trig": "Net-config trigger",
    "reset_t": "Reset hold time (s)", "rstnum": "Power cycles to reset",
    "wfcfg": "Pairing mode", "wfct": "Pairing timeout",
    "cmod": "Colour mode", "cwtype": "Cold/warm driver", "dmod": "Dimmer mode",
    "pwmhz": "PWM frequency (Hz)", "brightmin": "Min brightness (%)",
    "brightmax": "Max brightness (%)", "colormin": "Min colour (%)",
    "colormax": "Max colour (%)", "cwmaxp": "Max C+W power (%)",
    "deftemp": "Default colour temp", "defbright": "Default brightness (%)",
    "defcolor": "Default colour", "pmemory": "Restore state after power loss",
    "onoffmode": "On/off behaviour", "remdmode": "Remote/dimming mode",
    "prodagain": "Allow re-running prod test", "title20": "title20 flag",
    "nety_led": "Net LED state (paired)", "netn_led": "Net LED state (unpaired)",
    "netled_reuse": "Net LED pin reused", "total_stat": "Total-status mode",
    "rstcor": "Reset indicator colour", "rstbr": "Reset indicator brightness (%)",
    "rsttemp": "Reset indicator temp", "cagt": "Colour adjust time",
    "wt": "White transition", "rgbt": "RGB transition", "ffc_select": "FFC variant",
}
_ROLE = {"rl": "Relay", "ch": "Channel", "netled": "Network LED", "bt": "Button",
         "total_bt": "Button (combined)", "c": "Cold white", "w": "Warm white",
         "r": "Red", "g": "Green", "b": "Blue", "net": "Network"}
_VALUES = {("cmod", "cw"): "cold/warm white", ("cmod", "rgb"): "RGB",
           ("cmod", "rgbcw"): "RGB + cold/warm", ("cmod", "c"): "single white",
           ("defcolor", "c"): "cold white", ("defcolor", "w"): "warm white",
           ("rstcor", "c"): "cold white", ("wfcfg", "spcl"): "special (hold button)",
           ("wfcfg", "old"): "legacy pairing"}


def _describe(key, value):
    label = _NAMES.get(key)
    if label is None:
        m = re.match(r"^([a-z_]*?)(\d*)(_pin|_lv|_dpid|_type)$", key)
        if m:
            base, idx, suffix = m.groups()
            role = _ROLE.get(base.rstrip("_"), base.rstrip("_") or "Pin")
            what = {"_pin": "GPIO", "_lv": "active level",
                    "_dpid": "datapoint id", "_type": "type"}[suffix]
            label = " ".join(("%s %s %s" % (role, idx, what)).split())
        else:
            label = key
    pretty = _VALUES.get((key, value))
    if pretty is None and key.endswith("_lv"):
        pretty = {"0": "active low", "1": "active high"}.get(value)
    if pretty is None and key.endswith("_pin"):
        pretty = "P%s" % value
    return label, (pretty or value)


_DP_TYPE = {"value": "numeric", "bool": "on/off", "enum": "enum",
            "string": "text", "bitmap": "bitmap", "raw": "raw"}


def _redact(value):
    """Mask secrets before they reach a published report.

    Decrypted Tuya storage carries the owner's WiFi SSID and PSK plus the
    device's auth key. These dumps are public, but re-publishing someone's home
    network name and credentials on a web page is not something to do by
    default. Shape is kept so the field is still recognisable.
    """
    v = str(value)
    if len(v) <= 4:
        return "*" * len(v)
    return "%s%s%s" % (v[:2], "*" * (len(v) - 4), v[-2:])


REDACT_SECRETS = True       # set False to show raw values locally


def summarise(found, key_off, inner_key, encrypted):
    """Build the [(label, value)] list shown beside the raw records."""
    out = []
    out.append(("Storage", "encrypted (decrypted with device key)" if encrypted
                else "plaintext"))
    if key_off is not None:
        out.append(("Key block", "0x%06X" % key_off))
    if inner_key:
        value = inner_key.hex()
        out.append(("Device key", _redact(value) if REDACT_SECRETS else value))
    for name, label in (("uuid", "Device UUID"), ("auth_key", "Auth key"),
                        ("ap_ssid", "AP SSID"), ("pskKey", "PSK key"),
                        ("psk_key", "PSK key"), ("psk30_key", "PSK 3.0 key")):
        if found["ids"].get(name):
            val = found["ids"][name]
            if REDACT_SECRETS and name in ("auth_key", "pskKey", "psk_key",
                                           "psk30_key", "ap_ssid"):
                val = _redact(val)
            out.append((label, val))
    net = found.get("network")
    if net:
        if net.get("ssid"):
            ssid = str(net["ssid"])
            out.append(("Paired WiFi SSID",
                        _redact(ssid) if REDACT_SECRETS else ssid))
        out.append(("Network config type", str(net.get("nc_tp"))))
        out.append(("Network status", str(net.get("stat"))))
    if found["dps"]:
        out.append(("Datapoints defined", str(len(found["dps"]))))
        for dp in found["dps"][:8]:
            prop = dp.get("property", {})
            kind = _DP_TYPE.get(prop.get("type"), prop.get("type", "?"))
            detail = kind
            if "min" in prop and "max" in prop:
                detail += " %s..%s" % (prop["min"], prop["max"])
            if "range" in prop:
                detail += " " + "/".join(str(x) for x in prop["range"][:4])
            out.append(("  DP %s (%s)" % (dp.get("id"), dp.get("mode", "?")), detail))
    # Pin/wiring lines first, worded exactly as BK7231GUIFlashTool prints them.
    bullets = []
    others = []
    for k, v in found["pins"]:
        text = describe_pin(k, v)
        if text:
            bullets.append(("-", text))
        else:
            others.append(_describe(k, v))
    if bullets:
        out.append(("Pin configuration", "%d entries" % len(bullets)))
        out.extend(bullets)
    out.extend(others)
    return out


def extract(path):
    """Return a dict for the report, or None when nothing can be recovered."""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return None

    key_off, inner = find_key_block(data)
    found, encrypted = None, False
    if inner:
        found = _collect(decrypt_storage(data, inner))
        encrypted = True
    plain = _collect(data[STORAGE_FROM:])
    if found is None:
        found = plain
    else:
        # Older images keep the pin map in the clear even when the rest is not.
        if not found["pins"] and plain["pins"]:
            found["pins"] = plain["pins"]
            found["raw"].insert(0, plain["raw"][0] if plain["raw"] else "")
        for k, v in plain["ids"].items():
            found["ids"].setdefault(k, v)
        if found["tls_mode"] is None:
            found["tls_mode"] = plain["tls_mode"]

    if not (found["pins"] or found["dps"] or found["network"] or found["ids"]):
        return None
    return {
        "offset": key_off if key_off is not None else STORAGE_FROM,
        "encrypted": encrypted,
        "raw": "\n\n".join(x for x in found["raw"][:6] if x),
        "pairs": found["pins"],
        # Keep the recovered data structured as well as presentation-ready.
        # Front ends can render only the safe pieces they need without parsing
        # the human summary or exposing the raw network record.
        "network": found["network"],
        "dps": found["dps"],
        "ids": found["ids"],
        "tls_mode": found["tls_mode"],
        "human": summarise(found, key_off, inner, encrypted),
    }


def tls_psk_candidates(decoded):
    """Return private TLS-PSK byte candidates from an extracted config.

    Tuya generations use slightly different field spellings.  Prefer PSK 3.0,
    retain the older spellings as authenticated fallbacks, and never derive a
    key from the masked human summary.  The TLS peer decides which candidate is
    correct only by verifying the client's encrypted Finished message.
    """
    ids = (decoded or {}).get("ids")
    if not isinstance(ids, dict):
        return ()
    out = []
    for name in ("psk30_key", "psk_key", "pskKey"):
        value = ids.get(name)
        if not isinstance(value, str):
            continue
        try:
            candidate = value.encode("ascii")
        except UnicodeEncodeError:
            continue
        if not (_MIN_STORED_ID_LEN <= len(candidate) <= _MAX_STORED_ID_LEN):
            continue
        if candidate not in out:
            out.append(candidate)
    return tuple(out)


def uses_tuya_legacy_identity_psk(decoded):
    """Whether this config enables Tuya's legacy identity-as-PSK trial.

    Some PSK-only TuyaOS builds keep a normal 37-character cloud ``psk_key``
    in storage but use a separate embedded 32-byte bootstrap value for an
    initial connection, passing that value to mbedTLS as both PSK and identity.
    Keep this compatibility behavior narrowly gated to the observed config
    generation and token shape.  The network peer still authenticates the
    encrypted Finished before accepting the identity as a usable key.
    """
    if not isinstance(decoded, dict) or decoded.get("tls_mode") != 2:
        return False
    ids = decoded.get("ids")
    if not isinstance(ids, dict) or ids.get("psk30_key"):
        return False
    value = ids.get("psk_key", ids.get("pskKey"))
    if not isinstance(value, str):
        return False
    try:
        candidate = value.encode("ascii")
    except UnicodeEncodeError:
        return False
    return len(candidate) == 37 and candidate.isalnum()


def offline_tls_config(decoded, net_out=False):
    """Return ``(tls_psks, tuya_legacy_identity_psk)`` for an offline Wi-Fi peer.

    ``--net-out`` is an opaque end-to-end relay, so no local TLS-PSK candidates
    or legacy identity-key trial are enabled when ``net_out`` is true.
    """
    if net_out:
        return (), False
    return (tls_psk_candidates(decoded),
            uses_tuya_legacy_identity_psk(decoded))


def _run_selftests():
    n = 0

    def check(cond, message):
        nonlocal n
        assert cond, "FAIL: " + message
        n += 1
        print("  [PASS]", message)

    print("== loose Tuya user_param_key parser ==")
    pairs = _parse_loose(
        "{module:CBU,r_pin:26,irfunset:[[6,02],[7,1e],[3,01]],label:'a,b',crc:13,}")
    check(dict(pairs)["irfunset"] == "[[6,02],[7,1e],[3,01]]",
          "commas inside nested arrays stay in one value")
    check(dict(pairs)["label"] == "a,b" and len(pairs) == 5,
          "commas inside quoted values do not create bogus keys")
    check(all(re.fullmatch(r"[A-Za-z0-9_]+", k) for k, _ in pairs),
          "every recovered key has the storage format's key shape")

    print("== adjacent/truncated records ==")
    torn = (b'xxxx{rstnum:3,c_pin:8,module:WB2L,def{"nc_tp":3,'
            b'"ssid":"U3VsaWFuYQ==","passwd":"secret" }yyyy')
    found = _collect(torn)
    check(found["pins"] == [("rstnum", "3"), ("c_pin", "8"), ("module", "WB2L")],
          "a torn config does not absorb fields from the following network JSON")
    check(not any("ssid" in k or "passwd" in k for k, _ in found["pins"]),
          "network credentials never appear as pin/config keys")
    network = _collect(b'{"nc_tp":3,"ssid":"Home Net","passwd":"password1"}')
    check("Home Net" not in network["raw"][0] and "password1" not in network["raw"][0],
          "raw report records mask stored WiFi credentials")

    print("== stored credential recovery ==")
    # Synthetic rather than copied from a dump: its shape exercises both
    # standard-Base64 punctuation and the former 40-character truncation.
    psk30 = "A" * 21 + "+" + "B" * 20 + "/="
    from_json = _collect(
        b'{"psk30_key":"' + psk30.encode("ascii") + b'"}')
    json_value = from_json["ids"].get("psk30_key")
    check(json_value is not None, "PSK 3.0 is recovered from credential-only JSON")
    check(json_value is not None and len(json_value) == len(psk30),
          "standard Base64 PSK 3.0 keeps its full length")
    check(json_value == psk30,
          "standard Base64 punctuation and padding survive JSON recovery")

    from_loose = _collect(
        b"\x00psk30_key=" + psk30.encode("ascii") + b"\x00")
    check(from_loose["ids"].get("psk30_key") == psk30,
          "the loose-storage fallback preserves the same full value")
    too_long = b"A" * (_MAX_STORED_ID_LEN + 1)
    overrun = _collect(b"psk30_key=" + too_long + b"\x00")
    check("psk30_key" not in overrun["ids"],
          "the loose-storage fallback does not accept a truncated prefix")
    embedded = _collect(
        b"backup_psk30_key=" + psk30.encode("ascii") + b"\x00")
    check("psk30_key" not in embedded["ids"],
          "the loose-storage fallback requires an exact field name")

    masked = [value for label, value in summarise(from_json, None, None, False)
              if label == "PSK 3.0 key"]
    mask_shape_ok = (len(masked) == 1 and len(masked[0]) == len(psk30)
                     and masked[0].count("*") == len(psk30) - 4)
    check(mask_shape_ok, "the human/GUI summary keeps the recovered PSK masked")

    candidates = tls_psk_candidates({"ids": {
        "psk30_key": "synthetic-psk30-value==",
        "psk_key": "synthetic-legacy-value",
        "pskKey": "synthetic-legacy-value",
        "auth_key": "not-a-tls-candidate",
    }})
    check(candidates == (b"synthetic-psk30-value==", b"synthetic-legacy-value"),
          "TLS candidates prefer PSK 3.0, include legacy spelling and remove duplicates")
    check(tls_psk_candidates({"ids": {"psk30_key": "nonascii-\u017c"}}) == ()
          and tls_psk_candidates(None) == (),
          "invalid or absent private PSKs are ignored without inventing a key")

    legacy_cfg = {
        "tls_mode": 2,
        "ids": {"psk_key": "A" * 37},
    }
    check(uses_tuya_legacy_identity_psk(legacy_cfg),
          "Tuya TLS mode 2 with its exact legacy PSK shape enables identity-key trial")
    check(offline_tls_config(legacy_cfg, net_out=False) == ((b"A" * 37,), True)
          and offline_tls_config(legacy_cfg, net_out=True) == ((), False),
          "offline_tls_config returns PSK candidates and legacy flag only when offline")
    check(not uses_tuya_legacy_identity_psk({
              "tls_mode": 2,
              "ids": {"psk_key": "A" * 37, "psk30_key": "B" * 44},
          })
          and not uses_tuya_legacy_identity_psk({
              "tls_mode": 1,
              "ids": {"psk_key": "A" * 37},
          })
          and not uses_tuya_legacy_identity_psk({
              "tls_mode": 2,
              "ids": {"psk_key": "A" * 36},
          }),
          "PSK 3.0, another TLS mode, or another key shape keeps legacy trial disabled")

    print("\nAll %d Tuya config self-tests passed." % n)
    return n


if __name__ == "__main__":
    _run_selftests()
