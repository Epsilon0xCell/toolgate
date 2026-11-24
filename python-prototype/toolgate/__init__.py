"""ToolGate: the gate. Pins tools, enforces authority, receipts all.

Author: Gavin Blacklock
Prototype, in-process only: no network, no MCP transport.
"""

from .gate import (
    DELEGATION_PAYLOAD_TYPE,
    Decision,
    ToolGate,
    delegation_payload_bytes,
    sign_delegation,
)

__all__ = [
    "DELEGATION_PAYLOAD_TYPE",
    "Decision",
    "ToolGate",
    "delegation_payload_bytes",
    "sign_delegation",
]
