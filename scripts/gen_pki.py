"""Generate a throwaway local PKI for the hardened compose profile (DEMO ONLY).

Writes to .build/pki/ (git-ignored):
  ca.crt / ca.key            local CA (ECDSA P-256, 30 days)
  keycloak.crt / .key        server cert: localhost, keycloak, 127.0.0.1
  opa.crt / .key             server cert: opa, localhost, 127.0.0.1
  pep.crt / .key             client cert for the API/MCP policy enforcement points (CN=aegis-pep)

Uses the `cryptography` library's X.509 builder (no custom crypto). Keys are written readable by the
container users because uids differ per image; they protect nothing outside this local demo.
Re-run with --force to rotate everything.
"""

from __future__ import annotations

import ipaddress
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

OUT = Path(__file__).resolve().parent.parent / ".build" / "pki"
PEP_CN = "aegis-pep"
VALIDITY = timedelta(days=30)


def name(cn: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AegisAccess demo"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )


def write_key(path: Path, key: ec.EllipticCurvePrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    path.chmod(0o644)


def write_cert(path: Path, cert: x509.Certificate) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def make_ca() -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name("AegisAccess local demo CA"))
        .issuer_name(name("AegisAccess local demo CA"))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + VALIDITY)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert, key


def issue(
    ca: x509.Certificate,
    ca_key: ec.EllipticCurvePrivateKey,
    cn: str,
    *,
    dns: tuple[str, ...] = (),
    ips: tuple[str, ...] = (),
    client: bool = False,
) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name(cn))
        .issuer_name(ca.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + VALIDITY)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.CLIENT_AUTH if client else ExtendedKeyUsageOID.SERVER_AUTH]
            ),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
    )
    if dns or ips:
        sans: list[x509.GeneralName] = [x509.DNSName(d) for d in dns]
        sans += [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    return builder.sign(ca_key, hashes.SHA256()), key


def main(argv: list[str]) -> int:
    if (OUT / "ca.crt").exists() and "--force" not in argv:
        print(f"local PKI already present in {OUT} (use --force to rotate)")
        return 0
    OUT.mkdir(parents=True, exist_ok=True)
    ca, ca_key = make_ca()
    write_cert(OUT / "ca.crt", ca)
    write_key(OUT / "ca.key", ca_key)
    for stem, cn, kwargs in (
        ("keycloak", "keycloak", {"dns": ("localhost", "keycloak"), "ips": ("127.0.0.1",)}),
        ("opa", "opa", {"dns": ("opa", "localhost"), "ips": ("127.0.0.1",)}),
        ("pep", PEP_CN, {"client": True}),
    ):
        cert, key = issue(ca, ca_key, cn, **kwargs)  # type: ignore[arg-type]
        write_cert(OUT / f"{stem}.crt", cert)
        write_key(OUT / f"{stem}.key", key)
    print(f"wrote local demo PKI to {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
