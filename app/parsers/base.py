"""Abstract base class for all deterministic protocol parsers."""

from abc import ABC, abstractmethod
from typing import List
from app.models.event import VoiceEvent


class BaseParser(ABC):
    """Protocol parser interface ensuring uniform deterministic parsing behavior."""

    @abstractmethod
    def parse(self, content: str, source: str = "unknown") -> List[VoiceEvent]:
        """Parse raw trace content into a sequence of normalized VoiceEvents.

        Args:
            content: Raw text content from trace file or stream.
            source: Name or identifier of the source file/node.

        Returns:
            List of normalized VoiceEvent objects.
        """
        pass
