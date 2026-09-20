"""In-memory and session command history ledger."""

from typing import List, Optional
from app.commands.models import CommandHistoryEntry


class CommandHistoryManager:
    """Maintains an ordered ledger of executed device commands."""

    def __init__(self, max_entries: int = 200):
        self._entries: List[CommandHistoryEntry] = []
        self._max_entries = max_entries

    def add_entry(self, entry: CommandHistoryEntry) -> None:
        """Add an entry to the top of the history log."""
        self._entries.insert(0, entry)
        if len(self._entries) > self._max_entries:
            self._entries.pop()

    def get_entries(self) -> List[CommandHistoryEntry]:
        """Return all history entries."""
        return list(self._entries)

    def get_entry(self, entry_id: str) -> Optional[CommandHistoryEntry]:
        """Find an entry by its ID."""
        for e in self._entries:
            if e.entry_id == entry_id:
                return e
        return None

    def clear(self) -> None:
        """Clear all entries."""
        self._entries.clear()
