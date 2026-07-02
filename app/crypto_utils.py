"""
PKI/CA cryptographic operations using OpenSSL CLI.
Supports SM2 (Chinese national standard) and ECDSA P-256.
"""

import os
import re
import subprocess
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
PKI_DIR = BASE_DIR / "data" / "pki"
PKI_DIR.mkdir(parents=True, exist_ok=True)
(PKI_DIR / "ca").mkdir(exist_ok=True)

OPENSSL_BIN = os.environ.get("PKI_OPENSSL", "openssl")


def _run(cmd: str) -> tuple[int, str, str]:
    """Run a shell command and return (returncode, stdout, stderr)."""
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"


def _run_ok(cmd: str) -> bool:
    """Run command and return True if successful."""
    rc, _, _ = _run(cmd)
    return rc == 0


def _capture(cmd: str) -> str:
    """Run command and return stdout, or empty string on failure."""
    rc, out, _ = _run(cmd)
    return out if rc == 0 else ""


def _now_compact() -> str:
    return datetime.now().strftime("%Y%m%d%H%M%S")


def _now_iso() -> str:
    return datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")


def generate_sm2_keypair(private_path: str) -> tuple[bool, str]:
    """Generate SM2 key pair. Returns (success, error_message)."""
    cmd = f'{OPENSSL_BIN} ecparam -name SM2 -genkey -noout -out "{private_path}"'
    ok = _run_ok(cmd)
    if not ok:
        return False, f"SM2 key generation failed: {cmd}"
    return True, ""


def generate_ecdsa_keypair(private_path: str) -> tuple[bool, str]:
    """Generate ECDSA P-256 key pair. Returns (success, error_message)."""
    cmd = f'{OPENSSL_BIN} ecparam -name prime256v1 -genkey -noout -out "{private_path}"'
    ok = _run_ok(cmd)
    if not ok:
        return False, f"ECDSA key generation failed: {cmd}"
    return True, ""


def generate_keypair(private_path: str, algorithm: str = "SM2") -> tuple[bool, str]:
    """Generate a key pair for the given algorithm."""
    if algorithm == "SM2":
        return generate_sm2_keypair(private_path)
    elif algorithm == "ECDSA-P256":
        return generate_ecdsa_keypair(private_path)
    else:
        return False, f"Unsupported algorithm: {algorithm}"


def extract_public_key(private_path: str, public_path: str) -> tuple[bool, str]:
    """Extract public key from private key."""
    cmd = f'{OPENSSL_BIN} pkey -in "{private_path}" -pubout -out "{public_path}"'
    ok = _run_ok(cmd)
    if not ok:
        return False, f"Public key extraction failed"
    return True, ""


def get_cert_serial(cert_path: str) -> str:
    """Get the serial number of a certificate (hex)."""
    out = _capture(f'{OPENSSL_BIN} x509 -in "{cert_path}" -noout -serial')
    if out.startswith("serial="):
        return out[7:].strip().lower()
    return out.strip().lower()


def get_cert_subject(cert_path: str) -> str:
    """Get the subject DN of a certificate."""
    out = _capture(
        f'{OPENSSL_BIN} x509 -in "{cert_path}" -noout -subject -nameopt RFC2253,utf8'
    )
    if out.startswith("subject="):
        return out[8:].strip()
    return out.strip()


def get_cert_dates(cert_path: str) -> tuple[str, str]:
    """Get issue and expiry dates. Returns (not_before, not_after)."""
    out = _capture(f'{OPENSSL_BIN} x509 -in "{cert_path}" -noout -dates')
    start = ""
    end = ""
    for line in out.split("\n"):
        if line.startswith("notBefore="):
            start = line.split("=", 1)[1].strip()
        if line.startswith("notAfter="):
            end = line.split("=", 1)[1].strip()
    return start, end


def get_cert_text(cert_path: str) -> str:
    """Get full certificate details."""
    return _capture(f'{OPENSSL_BIN} x509 -in "{cert_path}" -noout -text')


def write_req_conf(path: str, dn: str) -> None:
    """Write an OpenSSL request config file from a DN string like /CN=.../OU=..."""
    parts = {}
    current_key = None
    for part in dn.split("/"):
        if "=" in part:
            key, _, value = part.partition("=")
            parts[key.strip()] = value.strip()

    with open(path, "w") as f:
        f.write("[req]\nprompt=no\nutf8=yes\nstring_mask=utf8only\ndistinguished_name=dn\n[dn]\n")
        for key in ["CN", "OU", "O", "emailAddress", "E", "ST", "L", "C"]:
            if key in parts and parts[key]:
                f.write(f"{key}={parts[key]}\n")


def write_ca_conf(pki_dir: str) -> None:
    """Write OpenSSL CA configuration."""
    ca_conf = os.path.join(pki_dir, "ca.cnf")
    ca_dir = os.path.join(pki_dir, "ca")

    os.makedirs(ca_dir, exist_ok=True)
    for fname in ["index.txt", "serial", "crlnumber"]:
        fpath = os.path.join(ca_dir, fname)
        if not os.path.exists(fpath):
            if fname == "index.txt":
                with open(fpath, "w") as f:
                    pass
            elif fname == "serial":
                with open(fpath, "w") as f:
                    f.write("1000\n")
            elif fname == "crlnumber":
                with open(fpath, "w") as f:
                    f.write("1000\n")

    with open(ca_conf, "w") as f:
        f.write(f"""[ca]
default_ca=CA_default

[CA_default]
dir={pki_dir}
database=$dir/ca/index.txt
serial=$dir/ca/serial
crlnumber=$dir/ca/crlnumber
new_certs_dir=$dir/ca
certificate=$dir/root.crt
private_key=$dir/root-private.key
default_md=sha256
default_days=365
unique_subject=no
policy=policy_any
copy_extensions=copy
email_in_dn=no
default_crl_days=7

[policy_any]
commonName=optional
organizationalUnitName=optional
organizationName=optional
emailAddress=optional
stateOrProvinceName=optional
localityName=optional
countryName=optional

[signing_cert]
basicConstraints=CA:FALSE
keyUsage=digitalSignature,nonRepudiation
extendedKeyUsage=clientAuth,serverAuth

[encryption_cert]
basicConstraints=CA:FALSE
keyUsage=keyAgreement,keyEncipherment,dataEncipherment
extendedKeyUsage=clientAuth,serverAuth

[sm_signing_cert]
basicConstraints=CA:FALSE
keyUsage=digitalSignature,nonRepudiation
extendedKeyUsage=clientAuth,serverAuth

[sm_encryption_cert]
basicConstraints=CA:FALSE
keyUsage=keyAgreement,keyEncipherment,dataEncipherment
extendedKeyUsage=clientAuth,serverAuth
""")

    return ca_conf


def issue_root_ca(
    dn: str,
    days: int = 3650,
    algorithm: str = "ECDSA-P256",
) -> tuple[bool, str, dict]:
    """
    Issue a self-signed root CA certificate.
    Returns (success, error_message, info_dict).
    """
    pki_dir = str(PKI_DIR)
    ca_conf = write_ca_conf(pki_dir)

    root_key = os.path.join(pki_dir, "root-private.key")
    root_cert = os.path.join(pki_dir, "root.crt")
    req_conf = os.path.join(pki_dir, "root-req.cnf")

    if os.path.exists(root_cert):
        return False, "Root CA certificate already exists. Revoke it first or use a new PKI directory.", {}

    write_req_conf(req_conf, dn)

    # Generate key pair
    ok, err = generate_keypair(root_key, algorithm)
    if not ok:
        return False, err, {}

    # Determine hash algorithm
    md_flag = "-sm3" if algorithm == "SM2" else "-sha256"

    # Self-sign the root certificate
    cmd = (
        f'{OPENSSL_BIN} req -new -x509 {md_flag} '
        f'-key "{root_key}" -days {days} '
        f'-config "{req_conf}" -out "{root_cert}" '
        f'-addext "basicConstraints=critical,CA:TRUE" '
        f'-addext "keyUsage=critical,digitalSignature,nonRepudiation,keyCertSign,cRLSign"'
    )
    if not _run_ok(cmd):
        return False, f"Root CA self-sign failed: {cmd}", {}

    # Re-write CA conf to reference the new root cert
    write_ca_conf(pki_dir)

    serial = get_cert_serial(root_cert)
    subject = get_cert_subject(root_cert)
    start, end = get_cert_dates(root_cert)

    with open(root_cert) as f:
        cert_pem = f.read()
    with open(root_key) as f:
        key_pem = f.read()

    info = {
        "serial": serial,
        "subject": subject,
        "algorithm": algorithm,
        "issue_date": start,
        "expiry_date": end,
        "cert_pem": cert_pem,
        "key_pem": key_pem,
        "days": days,
    }
    return True, "", info


def issue_user_cert(
    dn: str,
    days: int = 365,
    algorithm: str = "ECDSA-P256",
) -> tuple[bool, str, dict]:
    """
    Issue user certificates (signing + encryption dual cert).
    Returns (success, error_message, info_dict).
    """
    pki_dir = str(PKI_DIR)
    root_cert = os.path.join(pki_dir, "root.crt")

    if not os.path.exists(root_cert):
        return False, "Root CA not found. Please issue root CA first.", {}

    ts = _now_compact()
    results = {}

    # Determine extensions and hash based on algorithm
    if algorithm == "SM2":
        sign_ext = "sm_signing_cert"
        enc_ext = "sm_encryption_cert"
        md_flag = "-sm3"
        curve = "SM2"
    else:
        sign_ext = "signing_cert"
        enc_ext = "encryption_cert"
        md_flag = "-sha256"
        curve = "prime256v1"

    ca_conf = os.path.join(pki_dir, "ca.cnf")

    for cert_type, ext in [("signing", sign_ext), ("encryption", enc_ext)]:
        key_file = os.path.join(pki_dir, f"tmp-{cert_type}-{ts}.key")
        csr_file = os.path.join(pki_dir, f"tmp-{cert_type}-{ts}.csr")
        conf_file = os.path.join(pki_dir, f"tmp-{cert_type}-{ts}.cnf")
        cert_tmp = os.path.join(pki_dir, f"tmp-{cert_type}-{ts}.crt")

        write_req_conf(conf_file, dn)

        # Generate key
        cmd = f'{OPENSSL_BIN} ecparam -name {curve} -genkey -noout -out "{key_file}"'
        if not _run_ok(cmd):
            return False, f"{cert_type} key generation failed", {}

        # Create CSR
        cmd = (
            f'{OPENSSL_BIN} req -new {md_flag} -key "{key_file}" '
            f'-config "{conf_file}" -out "{csr_file}"'
        )
        if not _run_ok(cmd):
            return False, f"{cert_type} CSR generation failed", {}

        # Sign by CA
        cmd = (
            f'{OPENSSL_BIN} ca -batch -config "{ca_conf}" '
            f'-extensions {ext} -days {days} -in "{csr_file}" '
            f'-out "{cert_tmp}" -notext'
        )
        if not _run_ok(cmd):
            return False, f"{cert_type} CA signing failed", {}

        serial = get_cert_serial(cert_tmp)

        # Move to final location
        cert_final = os.path.join(pki_dir, "active-certificates", f"{serial}.cer.pem")
        key_final = os.path.join(pki_dir, "active-keys", f"{serial}.key.pem")
        os.makedirs(os.path.dirname(cert_final), exist_ok=True)
        os.makedirs(os.path.dirname(key_final), exist_ok=True)
        os.rename(cert_tmp, cert_final)
        os.rename(key_file, key_final)

        start, end = get_cert_dates(cert_final)
        with open(cert_final) as f:
            cert_pem = f.read()
        with open(key_final) as f:
            key_pem = f.read()

        results[cert_type] = {
            "serial": serial,
            "type": cert_type,
            "cert_file": cert_final,
            "key_file": key_final,
            "cert_pem": cert_pem,
            "key_pem": key_pem,
            "issue_date": start,
            "expiry_date": end,
        }

    return True, "", {
        "signing": results.get("signing", {}),
        "encryption": results.get("encryption", {}),
        "dn": dn,
        "algorithm": algorithm,
        "days": days,
    }


def revoke_certificate(serial: str, reason: str = "unspecified") -> tuple[bool, str, dict]:
    """
    Revoke a certificate by serial number.
    Returns (success, error_message, info_dict).
    """
    pki_dir = str(PKI_DIR)
    ca_conf = os.path.join(pki_dir, "ca.cnf")
    root_cert = os.path.join(pki_dir, "root.crt")

    if not os.path.exists(root_cert):
        return False, "Root CA not found.", {}

    cmd = (
        f'{OPENSSL_BIN} ca -batch -config "{ca_conf}" '
        f'-revoke "{pki_dir}/ca/{serial}.pem" '
        f'-crl_reason {reason}'
    )

    rc, stdout, stderr = _run(cmd)
    if rc != 0:
        combined = stdout + "\n" + stderr
        if "already revoked" in combined.lower():
            return False, f"Certificate {serial} is already revoked.", {}
        return False, f"Revocation failed: {stderr or stdout}", {}

    revoke_time = _now_iso()

    return True, "", {
        "serial": serial,
        "reason": reason,
        "revoke_time": revoke_time,
    }


def issue_crl(days: int = 7) -> tuple[bool, str, dict]:
    """
    Issue a Certificate Revocation List.
    Returns (success, error_message, info_dict).
    """
    pki_dir = str(PKI_DIR)
    ca_conf = os.path.join(pki_dir, "ca.cnf")
    root_cert = os.path.join(pki_dir, "root.crt")

    if not os.path.exists(root_cert):
        return False, "Root CA not found.", {}

    crl_file = os.path.join(pki_dir, "root.crl")
    cmd = (
        f'{OPENSSL_BIN} ca -batch -config "{ca_conf}" '
        f'-gencrl -crldays {days} -out "{crl_file}"'
    )

    if not _run_ok(cmd):
        return False, "CRL generation failed.", {}

    # Archive CRL
    archive = os.path.join(pki_dir, f"root-{_now_compact()}.crl")
    data = ""
    if os.path.exists(crl_file):
        with open(crl_file, "rb") as src:
            data = src.read()
        with open(archive, "wb") as dst:
            dst.write(data)

    # Parse CRL info
    crl_text = _capture(f'{OPENSSL_BIN} crl -in "{crl_file}" -noout -text')
    revoked_count = crl_text.count("Serial Number:")

    with open(crl_file) as f:
        crl_pem = f.read()

    return True, "", {
        "crl_file": crl_file,
        "archive_file": archive,
        "crl_pem": crl_pem,
        "days": days,
        "revoked_count": revoked_count,
        "crl_text": crl_text,
    }


def get_root_info() -> dict | None:
    """Get information about the current root CA certificate."""
    pki_dir = str(PKI_DIR)
    root_cert = os.path.join(pki_dir, "root.crt")

    if not os.path.exists(root_cert):
        return None

    serial = get_cert_serial(root_cert)
    subject = get_cert_subject(root_cert)
    start, end = get_cert_dates(root_cert)

    with open(root_cert) as f:
        cert_pem = f.read()

    return {
        "serial": serial,
        "subject": subject,
        "issue_date": start,
        "expiry_date": end,
        "cert_pem": cert_pem,
        "cert_file": root_cert,
    }


def get_crl_info() -> dict | None:
    """Get information about the current CRL."""
    pki_dir = str(PKI_DIR)
    crl_file = os.path.join(pki_dir, "root.crl")

    if not os.path.exists(crl_file):
        return None

    crl_text = _capture(f'{OPENSSL_BIN} crl -in "{crl_file}" -noout -text')
    with open(crl_file) as f:
        crl_pem = f.read()

    return {
        "crl_text": crl_text,
        "crl_pem": crl_pem,
        "crl_file": crl_file,
    }


def build_dn(cn: str, ou: str = "", o: str = "", email: str = "",
             st: str = "", l: str = "", c: str = "") -> str:
    """Build OpenSSL-style DN string."""
    parts = []
    if cn:
        parts.append(f"/CN={cn}")
    if ou:
        parts.append(f"/OU={ou}")
    if o:
        parts.append(f"/O={o}")
    if email:
        parts.append(f"/emailAddress={email}")
    if st:
        parts.append(f"/ST={st}")
    if l:
        parts.append(f"/L={l}")
    if c:
        parts.append(f"/C={c}")
    return "".join(parts)


def parse_dn(dn: str) -> dict:
    """Parse OpenSSL DN string into dict."""
    result = {}
    for part in dn.split("/"):
        if "=" in part:
            key, _, value = part.partition("=")
            result[key.strip()] = value.strip()
    return result
