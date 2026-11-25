"""
ChainCaps: Declassification Token Issuer

Trusted component that issues HMAC-signed declassification tokens.
This runs in the trusted issuer context (system/user), NOT in the LLM.
"""

import hashlib
import hmac
import json
import uuid
from typing import List

from .budget import SinkPrivilege


def issue_declassification_token(
    signing_key: bytes,
    sink_privilege: SinkPrivilege,
    lineage_node_ids: List[str],
) -> str:
    """Issue a cryptographically signed declassification token.

    This function is called by the TRUSTED ISSUER (system/user) when
    explicit user approval authorizes a normally-blocked sink operation.

    The signing_key must match the DAG's signing_key. The LLM never
    has access to the signing_key.

    Args:
        signing_key: The HMAC signing key (shared with the DAG)
        sink_privilege: The specific sink privilege to declassify
        lineage_node_ids: The data node IDs in the lineage

    Returns:
        JSON string with signed token
    """
    payload = json.dumps({
        "token_id": f"tok_{uuid.uuid4().hex[:12]}",
        "sink": str(sink_privilege),
        "lineage": lineage_node_ids,
        "user_approval": True,
        "scope": "one-shot",
    }, sort_keys=True)

    token_hmac = hmac.new(
        signing_key, payload.encode(), hashlib.sha256
    ).hexdigest()

    return json.dumps({
        "payload": payload,
        "hmac": token_hmac,
    })
