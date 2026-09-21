"""Multi-criteria search index for CUCM calls and SDL events."""

from collections import defaultdict
from datetime import date, datetime, timezone
from typing import Dict, Iterable, List, Optional, Set

from app.devices.cucm.sdl.models import Call, SDLEvent


class CallIndex:
    """In-memory index supporting fast, multi-criteria lookup across correlated CUCM calls."""

    def __init__(self):
        self._calls: Dict[str, Call] = {}
        # Inverted index mappings: key -> set of call IDs
        self._calling_idx: Dict[str, Set[str]] = defaultdict(set)
        self._called_idx: Dict[str, Set[str]] = defaultdict(set)
        self._call_id_idx: Dict[str, Set[str]] = defaultdict(set)
        self._ci_idx: Dict[str, Set[str]] = defaultdict(set)
        self._cdcc_idx: Dict[str, Set[str]] = defaultdict(set)
        self._device_idx: Dict[str, Set[str]] = defaultdict(set)
        self._node_idx: Dict[str, Set[str]] = defaultdict(set)
        self._protocol_idx: Dict[str, Set[str]] = defaultdict(set)

    def add_call(self, call: Call) -> None:
        """Add a single Call object to the index."""
        call_id = call.id
        self._calls[call_id] = call

        if call.calling_number:
            self._calling_idx[call.calling_number.strip().lower()].add(call_id)
        if call.called_number:
            self._called_idx[call.called_number.strip().lower()].add(call_id)
        if call.call_id:
            self._call_id_idx[call.call_id.strip().lower()].add(call_id)
        if call.ci:
            self._ci_idx[call.ci.strip().lower()].add(call_id)
        if call.cdcc:
            self._cdcc_idx[call.cdcc.strip().lower()].add(call_id)

        for dev in call.devices:
            if dev:
                self._device_idx[dev.strip().lower()].add(call_id)

        for node in call.nodes:
            if node:
                self._node_idx[node.strip().lower()].add(call_id)

        for proto in call.protocols:
            if proto:
                self._protocol_idx[proto.strip().upper()].add(call_id)

        # Index identifiers stored in call_identifiers
        for ident in call.call_identifiers:
            key_low = ident.key.lower()
            val_low = ident.value.strip().lower()
            if key_low in ("ci", "cucm_ci"):
                self._ci_idx[val_low].add(call_id)
            elif key_low in ("cdcc",):
                self._cdcc_idx[val_low].add(call_id)
            elif key_low in ("call_id", "call-id", "callid"):
                self._call_id_idx[val_low].add(call_id)

    def add_calls(self, calls: Iterable[Call]) -> None:
        """Batch index multiple Call objects."""
        for call in calls:
            self.add_call(call)

    def clear(self) -> None:
        """Reset all indexes."""
        self._calls.clear()
        self._calling_idx.clear()
        self._called_idx.clear()
        self._call_id_idx.clear()
        self._ci_idx.clear()
        self._cdcc_idx.clear()
        self._device_idx.clear()
        self._node_idx.clear()
        self._protocol_idx.clear()

    @property
    def total_calls(self) -> int:
        """Count of indexed calls."""
        return len(self._calls)

    def get_all_calls(self) -> List[Call]:
        """Return all calls sorted chronologically by start time."""
        return sorted(self._calls.values(), key=lambda c: c.start_time)

    def find_calls(
        self,
        calling_number: Optional[str] = None,
        called_number: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        date_filter: Optional[date] = None,
        node: Optional[str] = None,
        call_id: Optional[str] = None,
        ci: Optional[str] = None,
        cdcc: Optional[str] = None,
        device: Optional[str] = None,
        protocol: Optional[str] = None,
    ) -> List[Call]:
        """Find calls matching any combination of criteria.

        Returns multiple distinct calls even when numbers match.
        """
        candidate_ids: Optional[Set[str]] = None

        def intersect_candidates(matches: Set[str]) -> None:
            nonlocal candidate_ids
            if candidate_ids is None:
                candidate_ids = set(matches)
            else:
                candidate_ids.intersection_update(matches)

        # Lookup inverted indexes
        if calling_number:
            num = calling_number.strip().lower()
            matches = {
                cid for cnum, cids in self._calling_idx.items()
                if num in cnum for cid in cids
            }
            intersect_candidates(matches)

        if called_number:
            num = called_number.strip().lower()
            matches = {
                cid for cnum, cids in self._called_idx.items()
                if num in cnum for cid in cids
            }
            intersect_candidates(matches)

        if ci:
            val = ci.strip().lower()
            intersect_candidates(self._ci_idx.get(val, set()))

        if cdcc:
            val = cdcc.strip().lower()
            intersect_candidates(self._cdcc_idx.get(val, set()))

        if call_id:
            val = call_id.strip().lower()
            matches = {
                cid for cid_key, cids in self._call_id_idx.items()
                if val in cid_key for cid in cids
            }
            intersect_candidates(matches)

        if device:
            val = device.strip().lower()
            matches = {
                cid for d_key, cids in self._device_idx.items()
                if val in d_key for cid in cids
            }
            intersect_candidates(matches)

        if node:
            val = node.strip().lower()
            matches = {
                cid for n_key, cids in self._node_idx.items()
                if val in n_key for cid in cids
            }
            intersect_candidates(matches)

        if protocol:
            val = protocol.strip().upper()
            intersect_candidates(self._protocol_idx.get(val, set()))

        # Determine working candidate pool
        if candidate_ids is None:
            pool = list(self._calls.values())
        else:
            pool = [self._calls[cid] for cid in candidate_ids if cid in self._calls]

        # Time range and date filtering
        results: List[Call] = []

        for call in pool:
            # Date filter
            if date_filter is not None:
                if call.start_time.date() != date_filter and call.end_time.date() != date_filter:
                    continue

            # Ensure timezone-aware comparisons
            if start_time is not None:
                st = start_time if start_time.tzinfo else start_time.replace(tzinfo=timezone.utc)
                if call.end_time < st:
                    continue

            if end_time is not None:
                et = end_time if end_time.tzinfo else end_time.replace(tzinfo=timezone.utc)
                if call.start_time > et:
                    continue

            results.append(call)

        # Sort chronologically
        results.sort(key=lambda c: c.start_time)
        return results
