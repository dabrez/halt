"""Certificate authority for TLS termination.

To read a path out of an HTTPS request the proxy has to be the TLS server
the agent talks to, which means presenting a certificate for whatever
hostname the agent asked for (via SNI). This module mints those: one CA per
proxy lifetime, one leaf per hostname, cached.

Implemented with the `openssl` CLI rather than a Python crypto dependency —
the project has none and adding one for cert minting would be the tail
wagging the dog. Keys are ECDSA P-256; leaves are short-lived (30 days) and
regenerated on demand.

DEPLOYMENT NOTE, and it is not optional: the sandbox must trust
`ca_cert_path`. Nothing here injects it — how a CA gets into a guest's
trust store is a property of the sandbox image, not of HALT. An agent whose
trust store lacks the CA will fail its TLS handshake against the proxy,
which is *contained* (nothing leaks) but also *unobserved beyond host and
port* — the path never arrives because the handshake never completes.
That is the same visibility/containment split from milestone 1, one layer
up, and it is the reason the live test verifies the trust path explicitly.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class CertPair:
    cert_path: str
    key_path: str


class CertAuthority:
    def __init__(self, workdir: str | os.PathLike | None = None, openssl: str = "openssl"):
        self._dir = Path(workdir) if workdir else Path(tempfile.mkdtemp(prefix="halt-ca-"))
        self._dir.mkdir(parents=True, exist_ok=True)
        self._openssl = openssl
        self._lock = threading.Lock()
        self._leaves: dict[str, CertPair] = {}

        self.ca = CertPair(
            cert_path=str(self._dir / "ca.crt"),
            key_path=str(self._dir / "ca.key"),
        )
        if not Path(self.ca.cert_path).exists():
            self._mint_ca()

    @property
    def ca_cert_path(self) -> str:
        """Hand this to the sandbox's trust store. See module docstring."""
        return self.ca.cert_path

    def leaf_for(self, hostname: str) -> CertPair:
        """A certificate valid for `hostname`, minted on first use."""
        with self._lock:
            pair = self._leaves.get(hostname)
            if pair is None:
                pair = self._mint_leaf(hostname)
                self._leaves[hostname] = pair
            return pair

    # -- openssl ------------------------------------------------------

    def _run(self, *args: str) -> None:
        r = subprocess.run(
            [self._openssl, *args], capture_output=True, text=True
        )
        if r.returncode != 0:
            raise RuntimeError(f"openssl {args[0]} failed: {r.stderr.strip()}")

    def _mint_ca(self) -> None:
        self._run(
            "req", "-x509", "-newkey", "ec",
            "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
            "-keyout", self.ca.key_path, "-out", self.ca.cert_path,
            "-days", "3650", "-subj", "/CN=HALT egress CA",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        )

    def _mint_leaf(self, hostname: str) -> CertPair:
        # Filesystem-safe name; hostnames can contain '*' via policy globs
        # but a leaf is always minted for the concrete SNI value.
        safe = "".join(ch if ch.isalnum() or ch in ".-" else "_" for ch in hostname)
        key = self._dir / f"{safe}.key"
        csr = self._dir / f"{safe}.csr"
        crt = self._dir / f"{safe}.crt"
        ext = self._dir / f"{safe}.ext"

        san = f"IP:{hostname}" if _looks_like_ipv4(hostname) else f"DNS:{hostname}"
        ext.write_text(
            "subjectAltName=" + san + "\n"
            "basicConstraints=CA:FALSE\n"
            "keyUsage=digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\n"
        )
        self._run(
            "req", "-new", "-newkey", "ec",
            "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
            "-keyout", str(key), "-out", str(csr), "-subj", f"/CN={hostname}",
        )
        self._run(
            "x509", "-req", "-in", str(csr),
            "-CA", self.ca.cert_path, "-CAkey", self.ca.key_path,
            "-CAcreateserial", "-out", str(crt), "-days", "30",
            "-extfile", str(ext),
        )
        return CertPair(cert_path=str(crt), key_path=str(key))


def _looks_like_ipv4(s: str) -> bool:
    parts = s.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
