"""Compatibility import for the Tuya decoder's former test-harness location.

Runtime users should import :mod:`src.tuya_config`; this keeps older report and
ad-hoc tooling that put ``tests`` on ``sys.path`` working.
"""

import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from src import tuya_config as _impl
from src.tuya_config import *  # noqa: F401,F403


_PAIRED_IR_FIXTURE = os.path.join(
    _ROOT, "firmwares", "BK7238_Tuya_IHSENO_HAZ_IR_V3_T1-3S_0.0.5.bin")
_PAIRED_LSC_FIXTURE = os.path.join(
    _ROOT, "firmwares", "BK7231N_Tuya_LSC_GLS_A60_CBLC5_1.6.0.bin")


def test_paired_ir_psk30_recovery():
    """The paired BK7238 image retains its complete PSK without displaying it."""
    fixture_present = os.path.isfile(_PAIRED_IR_FIXTURE)
    assert fixture_present, "paired BK7238 IR fixture is missing"

    result = _impl.extract(_PAIRED_IR_FIXTURE)
    result_present = result is not None
    assert result_present, "paired BK7238 IR config was not recovered"
    recovered = (result.get("ids") or {}).get("psk30_key")
    key_present = isinstance(recovered, str)
    assert key_present, "paired BK7238 IR PSK 3.0 key is missing"
    full_length = len(recovered) == 44
    assert full_length, "paired BK7238 IR PSK 3.0 key is not full length"

    # Independently walk the decoded JSON records.  All comparisons are first
    # reduced to booleans so a failing assertion cannot print credential data.
    with open(_PAIRED_IR_FIXTURE, "rb") as stream:
        image = stream.read()
    _key_off, inner_key = _impl.find_key_block(image)
    device_key_present = inner_key is not None
    assert device_key_present, "paired BK7238 IR storage key block is missing"
    storage = _impl.decrypt_storage(image, inner_key)
    copies = []
    for _offset, blob in _impl._json_objects(storage):
        obj = _impl._decode(blob)
        if isinstance(obj, dict) and isinstance(obj.get("psk30_key"), str):
            copies.append(obj["psk30_key"])
    duplicate_records_present = len(copies) > 1
    assert duplicate_records_present, "paired BK7238 IR PSK records are missing"
    copies_have_full_length = all(len(value) == len(recovered) for value in copies)
    assert copies_have_full_length, "paired BK7238 IR PSK record length differs"
    copies_equal_recovered = all(value == recovered for value in copies)
    assert copies_equal_recovered, "paired BK7238 IR PSK records disagree"

    displayed = [value for label, value in result.get("human", [])
                 if label == "PSK 3.0 key"]
    summary_is_masked = (len(displayed) == 1
                         and len(displayed[0]) == len(recovered)
                         and displayed[0].count("*") == len(recovered) - 4)
    assert summary_is_masked, "paired BK7238 IR PSK summary is not masked"
    raw_excludes_value = recovered not in result.get("raw", "")
    assert raw_excludes_value, "paired BK7238 IR raw report exposes the PSK"


def test_paired_lsc_legacy_tls_mode():
    """The LSC fixture alone opts into its authenticated identity-key mode."""
    fixture_present = os.path.isfile(_PAIRED_LSC_FIXTURE)
    assert fixture_present, "paired LSC fixture is missing"

    result = _impl.extract(_PAIRED_LSC_FIXTURE)
    result_present = result is not None
    assert result_present, "paired LSC config was not recovered"
    legacy = (result.get("ids") or {}).get("psk_key")
    legacy_shape_ok = (isinstance(legacy, str) and len(legacy) == 37
                       and legacy.isascii() and legacy.isalnum())
    assert legacy_shape_ok, "paired LSC legacy PSK has the wrong shape"
    mode_is_exact = result.get("tls_mode") == 2
    assert mode_is_exact, "paired LSC dynamic TLS mode was not recovered"
    gate_enabled = _impl.uses_tuya_legacy_identity_psk(result)
    assert gate_enabled, "paired LSC did not enable its narrowly gated TLS compatibility mode"
    candidate_lengths = tuple(len(value) for value in _impl.tls_psk_candidates(result))
    assert candidate_lengths == (37,), "paired LSC exposed an unexpected TLS candidate set"

    displayed = [value for label, value in result.get("human", [])
                 if label == "PSK key"]
    summary_is_masked = (len(displayed) == 1 and len(displayed[0]) == len(legacy)
                         and displayed[0].count("*") == len(legacy) - 4)
    assert summary_is_masked, "paired LSC PSK summary is not masked"
    raw_excludes_value = legacy not in result.get("raw", "")
    assert raw_excludes_value, "paired LSC raw report exposes the PSK"


if __name__ == "__main__":
    test_paired_ir_psk30_recovery()
    test_paired_lsc_legacy_tls_mode()
    print("Paired Tuya-config regressions passed.")
