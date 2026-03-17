#!/usr/bin/env python3
"""Refresh Google attestation roots stored in res/raw."""

from __future__ import annotations

import pathlib
import sys
import urllib.request

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
except ImportError as exc:  # pragma: no cover
    raise SystemExit(
        "cryptography is required for this script. Install it with: pip install cryptography"
    ) from exc


ROOT_URL = "https://android.googleapis.com/attestation/root"
RAW_DIR = pathlib.Path(__file__).resolve().parents[1] / "app" / "src" / "main" / "res" / "raw"
RSA_OUTPUT = RAW_DIR / "google_attestation_root_rsa.pem"
EC_OUTPUT = RAW_DIR / "google_attestation_root_ecdsa.pem"


def split_pems(pem_bundle: str) -> list[str]:
    blocks: list[str] = []
    current: list[str] = []
    for line in pem_bundle.splitlines():
        current.append(line)
        if line.strip() == "-----END CERTIFICATE-----":
            blocks.append("\n".join(current) + "\n")
            current = []
    return blocks


def main() -> int:
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(ROOT_URL, timeout=10) as response:
        payload = response.read().decode("utf-8")

    rsa_pem: str | None = None
    ec_pem: str | None = None
    for pem in split_pems(payload):
        certificate = x509.load_pem_x509_certificate(pem.encode("utf-8"))
        public_key = certificate.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            rsa_pem = pem
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            ec_pem = pem

    if rsa_pem is None or ec_pem is None:
        raise SystemExit("Could not identify both RSA and EC attestation roots from the download.")

    RSA_OUTPUT.write_text(rsa_pem, encoding="utf-8")
    EC_OUTPUT.write_text(ec_pem, encoding="utf-8")

    print(f"Updated {RSA_OUTPUT}")
    print(f"Updated {EC_OUTPUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
