#!/usr/bin/env python3
import argparse
import ipaddress
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def utc_now():
    return datetime.now(timezone.utc)


def write_pem(path: Path, data: bytes, private=False, overwrite=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not overwrite:
        raise FileExistsError(f"{path} already exists (use --overwrite)")
    path.write_bytes(data)
    if private:
        path.chmod(0o600)


def new_rsa_private_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=4096)


def key_to_pem(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def cert_to_pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


def pem_to_oneline(pem_text: str) -> str:
    raw = str(pem_text or "").strip()
    if not raw:
        return ""
    return raw.replace("\r", "").replace("\n", "\\n")


def build_ca(cn: str, years=10):
    ca_key = new_rsa_private_key()
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PortHound"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )
    now = utc_now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365 * int(years)))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                key_cert_sign=True,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )
    return ca_key, cert


def parse_sans(hosts, ips):
    san_items = []
    for host in hosts:
        value = str(host or "").strip()
        if value:
            san_items.append(x509.DNSName(value))
    for ip_value in ips:
        value = str(ip_value or "").strip()
        if not value:
            continue
        san_items.append(x509.IPAddress(ipaddress.ip_address(value)))
    if not san_items:
        san_items.append(x509.DNSName("localhost"))
    return san_items


def build_leaf_cert(
    ca_key,
    ca_cert,
    common_name: str,
    sans,
    days_valid=825,
    server_auth=False,
    client_auth=False,
):
    leaf_key = new_rsa_private_key()
    now = utc_now()
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PortHound"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )
    eku_values = []
    if server_auth:
        eku_values.append(ExtendedKeyUsageOID.SERVER_AUTH)
    if client_auth:
        eku_values.append(ExtendedKeyUsageOID.CLIENT_AUTH)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=int(days_valid)))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(list(sans)), critical=False)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    if eku_values:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku_values), critical=False)
    cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    return leaf_key, cert


def write_env_files(out_dir: Path, master_host: str):
    abs_dir = out_dir.resolve()
    ca_cert = abs_dir / "ca" / "ca.cert.pem"
    master_cert = abs_dir / "master" / "master.cert.pem"
    master_key = abs_dir / "master" / "master.key.pem"
    admin_cert = abs_dir / "admin" / "admin.cert.pem"
    admin_key = abs_dir / "admin" / "admin.key.pem"
    agent_cert = abs_dir / "agent" / "agent.cert.pem"
    agent_key = abs_dir / "agent" / "agent.key.pem"
    ca_oneline = pem_to_oneline(ca_cert.read_text(encoding="utf-8", errors="ignore"))

    (abs_dir / "master.env").write_text(
        "\n".join(
            [
                "export PORTHOUND_ROLE=master",
                "export PORTHOUND_HOST=0.0.0.0",
                "export PORTHOUND_PORT=45678",
                "export PORTHOUND_TLS_ENABLED=1",
                "export PORTHOUND_TLS_REQUIRE_CLIENT_CERT=1",
                f"export PORTHOUND_CA={ca_cert}",
                f"export PORTHOUND_CA_ONELINE='{ca_oneline}'",
                f"export PORTHOUND_TLS_CERT_FILE={master_cert}",
                f"export PORTHOUND_TLS_KEY_FILE={master_key}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (abs_dir / "agent.env").write_text(
        "\n".join(
            [
                "export PORTHOUND_ROLE=agent",
                f"export PORTHOUND_MASTER=https://{master_host}:45678",
                f"export PORTHOUND_CA={ca_cert}",
                f"export PORTHOUND_CA_ONELINE='{ca_oneline}'",
                f"export PORTHOUND_AGENT_CERT={agent_cert}",
                f"export PORTHOUND_AGENT_KEY={agent_key}",
                "export PORTHOUND_IP=",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (abs_dir / "admin.env").write_text(
        "\n".join(
            [
                f"export PORTHOUND_CA={ca_cert}",
                f"export PORTHOUND_ADMIN_CERT={admin_cert}",
                f"export PORTHOUND_ADMIN_KEY={admin_key}",
                "",
            ]
        ),
        encoding="utf-8",
    )


def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate PortHound CA, master, admin and agent certificates."
    )
    parser.add_argument("--out-dir", default="certs", help="Output directory (default: certs)")
    parser.add_argument(
        "--master-host",
        action="append",
        default=["localhost"],
        help="DNS name for master cert SAN (repeatable)",
    )
    parser.add_argument(
        "--master-ip",
        action="append",
        default=["127.0.0.1"],
        help="IP for master cert SAN (repeatable)",
    )
    parser.add_argument("--ca-cn", default="PortHound Root CA")
    parser.add_argument("--master-cn", default="porthound-master")
    parser.add_argument("--admin-cn", default="porthound-admin")
    parser.add_argument("--agent-cn", default="porthound-agent")
    parser.add_argument("--days", type=int, default=825, help="Leaf cert validity in days")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite existing files")
    return parser.parse_args()


def main():
    args = parse_args()
    out_dir = Path(args.out_dir).resolve()
    sans = parse_sans(args.master_host, args.master_ip)

    ca_key, ca_cert = build_ca(args.ca_cn, years=10)
    master_key, master_cert = build_leaf_cert(
        ca_key=ca_key,
        ca_cert=ca_cert,
        common_name=args.master_cn,
        sans=sans,
        days_valid=args.days,
        server_auth=True,
        client_auth=False,
    )
    admin_key, admin_cert = build_leaf_cert(
        ca_key=ca_key,
        ca_cert=ca_cert,
        common_name=args.admin_cn,
        sans=[x509.DNSName("admin")],
        days_valid=args.days,
        server_auth=False,
        client_auth=True,
    )
    agent_key, agent_cert = build_leaf_cert(
        ca_key=ca_key,
        ca_cert=ca_cert,
        common_name=args.agent_cn,
        sans=[x509.DNSName("agent")],
        days_valid=args.days,
        server_auth=False,
        client_auth=True,
    )

    write_pem(out_dir / "ca" / "ca.key.pem", key_to_pem(ca_key), private=True, overwrite=args.overwrite)
    write_pem(out_dir / "ca" / "ca.cert.pem", cert_to_pem(ca_cert), overwrite=args.overwrite)
    write_pem(
        out_dir / "master" / "master.key.pem",
        key_to_pem(master_key),
        private=True,
        overwrite=args.overwrite,
    )
    write_pem(
        out_dir / "master" / "master.cert.pem",
        cert_to_pem(master_cert),
        overwrite=args.overwrite,
    )
    write_pem(
        out_dir / "admin" / "admin.key.pem",
        key_to_pem(admin_key),
        private=True,
        overwrite=args.overwrite,
    )
    write_pem(
        out_dir / "admin" / "admin.cert.pem",
        cert_to_pem(admin_cert),
        overwrite=args.overwrite,
    )
    write_pem(
        out_dir / "agent" / "agent.key.pem",
        key_to_pem(agent_key),
        private=True,
        overwrite=args.overwrite,
    )
    write_pem(
        out_dir / "agent" / "agent.cert.pem",
        cert_to_pem(agent_cert),
        overwrite=args.overwrite,
    )

    primary_host = str(args.master_host[0] or "localhost").strip() or "localhost"
    write_env_files(out_dir, primary_host)

    print("Certificates generated:")
    print(f"  CA:     {out_dir / 'ca' / 'ca.cert.pem'}")
    print(f"  Master: {out_dir / 'master' / 'master.cert.pem'}")
    print(f"  Admin:  {out_dir / 'admin' / 'admin.cert.pem'}")
    print(f"  Agent:  {out_dir / 'agent' / 'agent.cert.pem'}")
    print(f"Env files: {out_dir / 'master.env'}, {out_dir / 'agent.env'}, {out_dir / 'admin.env'}")


if __name__ == "__main__":
    main()
