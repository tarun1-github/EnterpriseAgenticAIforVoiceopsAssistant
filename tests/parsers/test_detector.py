"""Unit tests for protocol autodetection heuristics."""

from pathlib import Path
from app.models.event import ProtocolEnum
from app.parsers.detector import detect_protocol

SAMPLE_DIR = Path(__file__).parents[2] / "sample_data"


def test_detect_isdn_protocol():
    path = SAMPLE_DIR / "isdn" / "sample_isdn_call.txt"
    content = path.read_text(encoding="utf-8")
    assert detect_protocol(content) == ProtocolEnum.ISDN


def test_detect_sip_protocol():
    path = SAMPLE_DIR / "sip" / "sample_sip_call.txt"
    content = path.read_text(encoding="utf-8")
    assert detect_protocol(content) == ProtocolEnum.SIP


def test_detect_mgcp_protocol():
    path = SAMPLE_DIR / "mgcp" / "sample_mgcp_call.txt"
    content = path.read_text(encoding="utf-8")
    assert detect_protocol(content) == ProtocolEnum.MGCP


def test_detect_unknown_protocol():
    content = "Hello world, this is a plain text file without any telephony signaling."
    assert detect_protocol(content) == ProtocolEnum.UNKNOWN


def test_detect_empty_string():
    assert detect_protocol("") == ProtocolEnum.UNKNOWN
