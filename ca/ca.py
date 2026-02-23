import json
from datetime import datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

# Private enterprise OID range — safe for prototypes, replace before production
TOOL_PERMISSIONS_OID = x509.ObjectIdentifier("1.3.6.1.4.1.99999.1")


class CertificateAuthority:
    """Issues user certs with embedded tool permissions."""

    def __init__(self, ca_dir: Path):
        self.ca_dir = Path(ca_dir)
        self.ca_dir.mkdir(parents=True, exist_ok=True)

        self.ca_key_path = self.ca_dir / "ca_key.pem"
        self.ca_cert_path = self.ca_dir / "ca_cert.pem"

        if not self.ca_key_path.exists() or not self.ca_cert_path.exists():
            self._bootstrap()

        self.ca_key = _load_private_key(self.ca_key_path)
        self.ca_cert = _load_cert(self.ca_cert_path)

    def _bootstrap(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PKI-MCP-Core"),
            x509.NameAttribute(NameOID.COMMON_NAME, "PKI-MCP-Core CA"),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_cert_sign=True, crl_sign=True,
                    key_encipherment=False, content_commitment=False,
                    data_encipherment=False, key_agreement=False,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )

        with open(self.ca_key_path, "wb") as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ))
        with open(self.ca_cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        print(f"Created CA: {self.ca_cert_path}")

    def issue_certificate(self, username: str, allowed_tools: list[str], output_dir: Path) -> tuple[Path, Path]:
        """
        Issue a user cert encoding tool permissions in a custom extension.

        Returns (cert_path, key_path).
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PKI-MCP-Core"),
            x509.NameAttribute(NameOID.COMMON_NAME, username),
        ])

        # Permissions travel with the cert, not in a database — that's the whole point
        perms_ext = x509.UnrecognizedExtension(
            TOOL_PERMISSIONS_OID,
            json.dumps({"allowed_tools": allowed_tools}).encode(),
        )

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_encipherment=True, key_cert_sign=False,
                    crl_sign=False, content_commitment=False, data_encipherment=False,
                    key_agreement=False, encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(perms_ext, critical=False)
            .sign(self.ca_key, hashes.SHA256())
        )

        cert_path = output_dir / f"{username}_cert.pem"
        key_path = output_dir / f"{username}_key.pem"

        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(key_path, "wb") as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ))

        print(f"Issued cert for {username}: {cert_path}")
        print(f"  Tools: {', '.join(allowed_tools)}")

        return cert_path, key_path


def extract_permissions(cert: x509.Certificate) -> list[str]:
    """Extract allowed tool list from cert's custom extension."""
    try:
        ext = cert.extensions.get_extension_for_oid(TOOL_PERMISSIONS_OID)
        data = json.loads(ext.value.value.decode())
        return data.get("allowed_tools", [])
    except x509.ExtensionNotFound:
        raise ValueError("cert missing tool permissions extension")
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ValueError(f"corrupt permissions extension: {e}")


def extract_username(cert: x509.Certificate) -> str:
    for attr in cert.subject:
        if attr.oid == NameOID.COMMON_NAME:
            return attr.value
    raise ValueError("cert missing CN")


def _load_private_key(path: Path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def _load_cert(path: Path) -> x509.Certificate:
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())
