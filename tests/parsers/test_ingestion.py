"""Unit tests for the TraceIngestionEngine."""

from pathlib import Path
from app.models.event import ProtocolEnum
from app.parsers.ingestion import TraceIngestionEngine

SAMPLE_DIR = Path(__file__).parents[2] / "sample_data"


def test_ingest_content_with_autodetection():
    engine = TraceIngestionEngine()
    isdn_text = (SAMPLE_DIR / "isdn" / "sample_isdn_call.txt").read_text(encoding="utf-8")

    events = engine.ingest_content(isdn_text, source="test_isdn")
    assert len(events) == 8
    assert all(ev.protocol == ProtocolEnum.ISDN for ev in events)


def test_ingest_file():
    engine = TraceIngestionEngine()
    sip_path = SAMPLE_DIR / "sip" / "sample_sip_call.txt"

    events = engine.ingest_file(sip_path)
    assert len(events) == 7
    assert events[0].protocol == ProtocolEnum.SIP
    assert events[0].source == "sample_sip_call.txt"


def test_ingest_multiple_files():
    engine = TraceIngestionEngine()
    paths = [
        SAMPLE_DIR / "isdn" / "sample_isdn_call.txt",
        SAMPLE_DIR / "sip" / "sample_sip_call.txt",
        SAMPLE_DIR / "mgcp" / "sample_mgcp_call.txt",
    ]

    all_events = engine.ingest_multiple_files(paths)
    # 8 ISDN + 7 SIP + 6 MGCP = 21 events
    assert len(all_events) == 21

    protocols = {ev.protocol for ev in all_events}
    assert ProtocolEnum.ISDN in protocols
    assert ProtocolEnum.SIP in protocols
    assert ProtocolEnum.MGCP in protocols
