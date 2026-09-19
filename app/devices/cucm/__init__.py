"""CUCM Device Integration Module.

Provides SSH-based CLI access to Cisco Unified Communications Manager
for trace collection and diagnostic operations.
"""

from app.devices.cucm.client import CUCMClient
from app.devices.cucm.collector import CUCMTraceCollector, CollectionResult, CollectorConfig
from app.devices.cucm.transport import CUCMTransport, NetmikoTransport, TransportConfig, create_transport
from app.devices.cucm.models import CUCMVersion, CUCMTraceFile
from app.devices.cucm.exceptions import (
    CUCMError,
    CUCMConnectionError,
    CUCMAuthenticationError,
    CUCMTimeoutError,
    CUCMPromptError,
    CUCMCommandError,
    CUCMTraceCollectionError,
)

__all__ = [
    "CUCMClient",
    "CUCMTraceCollector",
    "CollectionResult",
    "CollectorConfig",
    "CUCMTransport",
    "NetmikoTransport",
    "TransportConfig",
    "create_transport",
    "CUCMVersion",
    "CUCMTraceFile",
    "CUCMError",
    "CUCMConnectionError",
    "CUCMAuthenticationError",
    "CUCMTimeoutError",
    "CUCMPromptError",
    "CUCMCommandError",
    "CUCMTraceCollectionError",
]