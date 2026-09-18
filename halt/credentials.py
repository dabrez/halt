"""Credential revocation.

"Credentials first, always" (kill.py) is only a real guarantee if something
actually revokes them. Both infra backends delegate to an injected
`revoke_credential_fn` because neither Firecracker nor gVisor has any
notion of an application token — the revoking has to happen wherever the
token was issued.

`HttpRevoker` is the generic shape of that: one POST per token to an
endpoint you control (an IAM proxy, an internal token service), with an
optional bearer for the revoker's own identity. It plugs straight in as
`revoke_credential_fn=HttpRevoker(...).revoke`.

HONEST STATUS: verified against a local fake endpoint, not a real IAM.
There are no cloud credentials in this environment to test against. What
*is* verified is the contract that matters to the kill path — a revoke
that fails for any reason returns False and records why, and never raises
into execute_kill(), because a broken revocation service must not stop the
network severance and termination that follow it.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Callable


class CredentialRevoker(ABC):
    @abstractmethod
    def revoke(self, token_id: str) -> bool:
        raise NotImplementedError


@dataclass
class RevocationFailure:
    token_id: str
    reason: str


class HttpRevoker(CredentialRevoker):
    def __init__(
        self,
        url: str,
        bearer: str | None = None,
        timeout: float = 5.0,
        opener: Callable = urllib.request.urlopen,
    ):
        self.url = url
        self._bearer = bearer
        self._timeout = timeout
        self._open = opener
        self.failures: list[RevocationFailure] = []

    def revoke(self, token_id: str) -> bool:
        body = json.dumps({"token_id": token_id, "action": "revoke"}).encode()
        headers = {"Content-Type": "application/json"}
        if self._bearer:
            headers["Authorization"] = f"Bearer {self._bearer}"
        req = urllib.request.Request(self.url, data=body, headers=headers, method="POST")
        try:
            with self._open(req, timeout=self._timeout) as resp:
                status = getattr(resp, "status", 200)
        except urllib.error.HTTPError as e:
            self.failures.append(RevocationFailure(token_id, f"HTTP {e.code}"))
            return False
        except Exception as e:  # noqa: BLE001 - must never raise into the kill path
            self.failures.append(RevocationFailure(token_id, f"{type(e).__name__}: {e}"))
            return False
        if 200 <= status < 300:
            return True
        self.failures.append(RevocationFailure(token_id, f"HTTP {status}"))
        return False
