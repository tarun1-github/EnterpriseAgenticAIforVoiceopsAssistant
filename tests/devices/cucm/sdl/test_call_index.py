"""Unit tests for CUCM CallIndex."""

from datetime import date, datetime, timedelta, timezone
from zoneinfo import ZoneInfo
import pytest

from app.devices.cucm.sdl.call_index import CallIndex
from app.devices.cucm.sdl.models import Call, SDLEvent

IST_TZ = ZoneInfo("Asia/Kolkata")


@pytest.fixture
def sample_calls():
    t0 = datetime(2026, 9, 20, 10, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 9, 20, 10, 2, 0, tzinfo=timezone.utc)

    t2 = datetime(2026, 9, 20, 11, 0, 0, tzinfo=timezone.utc)
    t3 = datetime(2026, 9, 20, 11, 5, 0, tzinfo=timezone.utc)

    t4 = datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)
    t5 = datetime(2026, 9, 20, 12, 1, 0, tzinfo=timezone.utc)

    # Call 1: 1001 -> 2002 at 10:00 UTC
    c1 = Call(
        id="call-001",
        call_id="callid-1001-2002-a",
        ci="11111",
        cdcc="22222",
        calling_number="1001",
        called_number="2002",
        start_time=t0,
        end_time=t1,
        nodes=["UCM15-HQ-PUB"],
        devices=["SEP001122334455"],
        protocols=["SIP"],
    )

    # Call 2: Same numbers (1001 -> 2002) but 1 hour later at 11:00 UTC
    c2 = Call(
        id="call-002",
        call_id="callid-1001-2002-b",
        ci="33333",
        cdcc="44444",
        calling_number="1001",
        called_number="2002",
        start_time=t2,
        end_time=t3,
        nodes=["UCM15-HQ-PUB"],
        devices=["SEP001122334455"],
        protocols=["SIP"],
    )

    # Call 3: Different numbers (3003 -> 4004) at 12:00 UTC
    c3 = Call(
        id="call-003",
        call_id="callid-3003-4004-c",
        ci="55555",
        cdcc="66666",
        calling_number="3003",
        called_number="4004",
        start_time=t4,
        end_time=t5,
        nodes=["UCM15-HQ-SUB"],
        devices=["vg224-branch1"],
        protocols=["Q931", "MGCP"],
    )

    return [c1, c2, c3]


def test_index_and_find_by_numbers(sample_calls):
    idx = CallIndex()
    idx.add_calls(sample_calls)
    assert idx.total_calls == 3

    # Should find both calls with same calling number
    calls_1001 = idx.find_calls(calling_number="1001")
    assert len(calls_1001) == 2
    assert {c.id for c in calls_1001} == {"call-001", "call-002"}

    # Should find single call for 3003
    calls_3003 = idx.find_calls(calling_number="3003")
    assert len(calls_3003) == 1
    assert calls_3003[0].id == "call-003"


def test_multiple_calls_same_numbers_distinguished_by_time(sample_calls):
    idx = CallIndex()
    idx.add_calls(sample_calls)

    # Find calls around 10:00 UTC only
    t_start = datetime(2026, 9, 20, 9, 50, 0, tzinfo=timezone.utc)
    t_end = datetime(2026, 9, 20, 10, 15, 0, tzinfo=timezone.utc)

    calls_morning = idx.find_calls(
        calling_number="1001",
        called_number="2002",
        start_time=t_start,
        end_time=t_end,
    )
    assert len(calls_morning) == 1
    assert calls_morning[0].id == "call-001"
    assert calls_morning[0].ci == "11111"


def test_find_by_identifiers(sample_calls):
    idx = CallIndex()
    idx.add_calls(sample_calls)

    # By CI
    by_ci = idx.find_calls(ci="33333")
    assert len(by_ci) == 1
    assert by_ci[0].id == "call-002"

    # By CDCC
    by_cdcc = idx.find_calls(cdcc="66666")
    assert len(by_cdcc) == 1
    assert by_cdcc[0].id == "call-003"

    # By Device
    by_dev = idx.find_calls(device="vg224-branch1")
    assert len(by_dev) == 1
    assert by_dev[0].id == "call-003"

    # By Node
    by_node = idx.find_calls(node="UCM15-HQ-SUB")
    assert len(by_node) == 1
    assert by_node[0].id == "call-003"


def test_find_by_date(sample_calls):
    idx = CallIndex()
    idx.add_calls(sample_calls)

    by_date = idx.find_calls(date_filter=date(2026, 9, 20))
    assert len(by_date) == 3

    by_wrong_date = idx.find_calls(date_filter=date(2026, 9, 21))
    assert len(by_wrong_date) == 0
