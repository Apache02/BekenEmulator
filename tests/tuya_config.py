"""Compatibility import for the Tuya decoder's former test-harness location.

Runtime users should import :mod:`src.tuya_config`; this keeps older report and
ad-hoc tooling that put ``tests`` on ``sys.path`` working.
"""

import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from src.tuya_config import *  # noqa: F401,F403
