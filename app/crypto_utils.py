"""
PKI/CA 加密操作模块，基于 OpenSSL 命令行工具。
支持 SM2（国密标准）和 ECDSA P-256 算法。
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
    """执行 shell 命令，返回 (返回码, 标准输出, 标准错误)。"""
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"


def _run_ok(cmd: str) -> bool:
    """执行命令，成功返回 True。"""
    rc, _, _ = _run(cmd)
    return rc == 0


def _capture(cmd: str) -> str:
    """执行命令并返回标准输出，失败时返回空字符串。"""
    rc, out, _ = _run(cmd)
    return out if rc == 0 else ""


def _now_compact() -> str:
    """返回紧凑格式的当前时间字符串（YYYYMMDDHHmmss）。"""
    return datetime.now().strftime("%Y%m%d%H%M%S")


def _now_iso() -> str:
    """返回 ISO 格式的当前时间字符串。"""
    return datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")


def generate_sm2_keypair(private_path: str) -> tuple[bool, str]:
    """生成 SM2 密钥对。返回 (是否成功, 错误信息)。"""
    cmd = f'{OPENSSL_BIN} ecparam -name SM2 -genkey -noout -out "{private_path}"'
    ok = _run_ok(cmd)
    if not ok:
        return False, f"SM2 密钥生成失败: {cmd}"
    return True, ""


def generate_ecdsa_keypair(private_path: str) -> tuple[bool, str]:
    """生成 ECDSA P-256 密钥对。返回 (是否成功, 错误信息)。"""
    cmd = f'{OPENSSL_BIN} ecparam -name prime256v1 -genkey -noout -out "{private_path}"'
    ok = _run_ok(cmd)
    if not ok:
        return False, f"ECDSA 密钥生成失败: {cmd}"
    return True, ""


def generate_keypair(private_path: str, algorithm: str = "SM2") -> tuple[bool, str]:
    """根据指定算法生成密钥对。"""
    if algorithm == "SM2":
        return generate_sm2_keypair(private_path)
    elif algorithm == "ECDSA-P256":
        return generate_ecdsa_keypair(private_path)
    else:
        return False, f"不支持的算法: {algorithm}"


def extract_public_key(private_path: str, public_path: str) -> tuple[bool, str]:
    """从私钥中提取公钥。"""
    cmd = f'{OPENSSL_BIN} pkey -in "{private_path}" -pubout -out "{public_path}"'
    ok = _run_ok(cmd)
    if not ok:
        return False, f"公钥提取失败"
    return True, ""


def get_cert_serial(cert_path: str) -> str:
    """获取证书的序列号（十六进制）。"""
    out = _capture(f'{OPENSSL_BIN} x509 -in "{cert_path}" -noout -serial')
    if out.startswith("serial="):
        return out[7:].strip().lower()
    return out.strip().lower()


def get_cert_subject(cert_path: str) -> str:
    """获取证书的主题 DN。"""
    out = _capture(
        f'{OPENSSL_BIN} x509 -in "{cert_path}" -noout -subject -nameopt RFC2253,utf8'
    )
    if out.startswith("subject="):
        return out[8:].strip()
    return out.strip()


def get_cert_dates(cert_path: str) -> tuple[str, str]:
    """获取证书的签发日期和过期日期。返回 (生效时间, 过期时间)。"""
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
    """获取证书的完整详细信息。"""
    return _capture(f'{OPENSSL_BIN} x509 -in "{cert_path}" -noout -text')


def write_req_conf(path: str, dn: str) -> None:
    """根据 DN 字符串（如 /CN=.../OU=...）写入 OpenSSL 请求配置文件。"""
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
    """写入 OpenSSL CA 配置文件。"""
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
    签发自签名根 CA 证书。
    返回 (是否成功, 错误信息, 信息字典)。
    """
    pki_dir = str(PKI_DIR)
    ca_conf = write_ca_conf(pki_dir)

    root_key = os.path.join(pki_dir, "root-private.key")
    root_cert = os.path.join(pki_dir, "root.crt")
    req_conf = os.path.join(pki_dir, "root-req.cnf")

    if os.path.exists(root_cert):
        return False, "根 CA 证书已存在，请先撤销或更换 PKI 目录。", {}

    write_req_conf(req_conf, dn)

    # 生成密钥对
    ok, err = generate_keypair(root_key, algorithm)
    if not ok:
        return False, err, {}

    # 根据算法确定哈希算法
    md_flag = "-sm3" if algorithm == "SM2" else "-sha256"

    # 自签名根证书
    cmd = (
        f'{OPENSSL_BIN} req -new -x509 {md_flag} '
        f'-key "{root_key}" -days {days} '
        f'-config "{req_conf}" -out "{root_cert}" '
        f'-addext "basicConstraints=critical,CA:TRUE" '
        f'-addext "keyUsage=critical,digitalSignature,nonRepudiation,keyCertSign,cRLSign"'
    )
    if not _run_ok(cmd):
        return False, f"根 CA 自签名失败: {cmd}", {}

    # 重写 CA 配置以引用新的根证书
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
    签发用户证书（签名证书 + 加密证书双证书）。
    返回 (是否成功, 错误信息, 信息字典)。
    """
    pki_dir = str(PKI_DIR)
    root_cert = os.path.join(pki_dir, "root.crt")

    if not os.path.exists(root_cert):
        return False, "未找到根 CA 证书，请先签发根证书。", {}

    ts = _now_compact()
    results = {}

    # 根据算法确定扩展段和哈希算法
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

        # 生成密钥
        cmd = f'{OPENSSL_BIN} ecparam -name {curve} -genkey -noout -out "{key_file}"'
        if not _run_ok(cmd):
            return False, f"{cert_type} 密钥生成失败", {}

        # 创建证书签名请求 (CSR)
        cmd = (
            f'{OPENSSL_BIN} req -new {md_flag} -key "{key_file}" '
            f'-config "{conf_file}" -out "{csr_file}"'
        )
        if not _run_ok(cmd):
            return False, f"{cert_type} CSR 生成失败", {}

        # 由 CA 签发
        cmd = (
            f'{OPENSSL_BIN} ca -batch -config "{ca_conf}" '
            f'-extensions {ext} -days {days} -in "{csr_file}" '
            f'-out "{cert_tmp}" -notext'
        )
        if not _run_ok(cmd):
            return False, f"{cert_type} CA 签发失败", {}

        serial = get_cert_serial(cert_tmp)

        # 移动到最终存储位置
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
    按序列号吊销证书。
    返回 (是否成功, 错误信息, 信息字典)。
    """
    pki_dir = str(PKI_DIR)
    ca_conf = os.path.join(pki_dir, "ca.cnf")
    root_cert = os.path.join(pki_dir, "root.crt")

    if not os.path.exists(root_cert):
        return False, "未找到根 CA 证书。", {}

    cmd = (
        f'{OPENSSL_BIN} ca -batch -config "{ca_conf}" '
        f'-revoke "{pki_dir}/ca/{serial}.pem" '
        f'-crl_reason {reason}'
    )

    rc, stdout, stderr = _run(cmd)
    if rc != 0:
        combined = stdout + "\n" + stderr
        if "already revoked" in combined.lower():
            return False, f"证书 {serial} 已被吊销。", {}
        return False, f"吊销失败: {stderr or stdout}", {}

    revoke_time = _now_iso()

    return True, "", {
        "serial": serial,
        "reason": reason,
        "revoke_time": revoke_time,
    }


def issue_crl(days: int = 7) -> tuple[bool, str, dict]:
    """
    签发证书吊销列表 (CRL)。
    返回 (是否成功, 错误信息, 信息字典)。
    """
    pki_dir = str(PKI_DIR)
    ca_conf = os.path.join(pki_dir, "ca.cnf")
    root_cert = os.path.join(pki_dir, "root.crt")

    if not os.path.exists(root_cert):
        return False, "未找到根 CA 证书。", {}

    crl_file = os.path.join(pki_dir, "root.crl")
    cmd = (
        f'{OPENSSL_BIN} ca -batch -config "{ca_conf}" '
        f'-gencrl -crldays {days} -out "{crl_file}"'
    )

    if not _run_ok(cmd):
        return False, "CRL 生成失败。", {}

    # 归档 CRL 副本
    archive = os.path.join(pki_dir, f"root-{_now_compact()}.crl")
    data = ""
    if os.path.exists(crl_file):
        with open(crl_file, "rb") as src:
            data = src.read()
        with open(archive, "wb") as dst:
            dst.write(data)

    # 解析 CRL 信息
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
    """获取当前根 CA 证书信息。"""
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
    """获取当前 CRL 信息。"""
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


def renew_single_cert(
    existing_key_path: str,
    dn: str,
    days: int,
    cert_type: str,
    algorithm: str = "ECDSA-P256",
) -> tuple[bool, str, dict]:
    """
    用已有密钥文件续期单张证书（保留原密钥对）。
    返回 (是否成功, 错误信息, 信息字典)。
    """
    pki_dir = str(PKI_DIR)
    root_cert = os.path.join(pki_dir, "root.crt")
    ca_conf = os.path.join(pki_dir, "ca.cnf")

    if not os.path.exists(root_cert):
        return False, "未找到根 CA 证书，请先签发根证书。", {}

    if not os.path.exists(existing_key_path):
        return False, f"密钥文件不存在: {existing_key_path}", {}

    ts = _now_compact()

    # 根据算法确定参数
    if algorithm == "SM2":
        sign_ext = "sm_signing_cert"
        enc_ext = "sm_encryption_cert"
        md_flag = "-sm3"
    else:
        sign_ext = "signing_cert"
        enc_ext = "encryption_cert"
        md_flag = "-sha256"

    ext = sign_ext if cert_type == "signing" else enc_ext

    csr_file = os.path.join(pki_dir, f"tmp-renew-{cert_type}-{ts}.csr")
    conf_file = os.path.join(pki_dir, f"tmp-renew-{cert_type}-{ts}.cnf")
    cert_tmp = os.path.join(pki_dir, f"tmp-renew-{cert_type}-{ts}.crt")

    write_req_conf(conf_file, dn)

    # 用已有密钥生成 CSR
    cmd = (
        f'{OPENSSL_BIN} req -new {md_flag} -key "{existing_key_path}" '
        f'-config "{conf_file}" -out "{csr_file}"'
    )
    if not _run_ok(cmd):
        return False, f"CSR 生成失败（续期）", {}

    # CA 签发
    cmd = (
        f'{OPENSSL_BIN} ca -batch -config "{ca_conf}" '
        f'-extensions {ext} -days {days} -in "{csr_file}" '
        f'-out "{cert_tmp}" -notext'
    )
    if not _run_ok(cmd):
        return False, f"CA 签发失败（续期）", {}

    serial = get_cert_serial(cert_tmp)

    # 移动到最终位置
    cert_final = os.path.join(pki_dir, "active-certificates", f"{serial}.cer.pem")
    key_final = os.path.join(pki_dir, "active-keys", f"{serial}.key.pem")
    os.makedirs(os.path.dirname(cert_final), exist_ok=True)
    os.makedirs(os.path.dirname(key_final), exist_ok=True)
    os.rename(cert_tmp, cert_final)

    # 续期场景：复制原密钥到对应位置
    with open(existing_key_path, "rb") as src:
        with open(key_final, "wb") as dst:
            dst.write(src.read())

    start, end = get_cert_dates(cert_final)
    with open(cert_final) as f:
        cert_pem = f.read()
    with open(key_final) as f:
        key_pem = f.read()

    return True, "", {
        "serial": serial,
        "type": cert_type,
        "cert_file": cert_final,
        "key_file": key_final,
        "cert_pem": cert_pem,
        "key_pem": key_pem,
        "issue_date": start,
        "expiry_date": end,
    }


def rekey_single_cert(
    dn: str,
    days: int,
    cert_type: str,
    algorithm: str = "ECDSA-P256",
) -> tuple[bool, str, dict]:
    """
    生成全新密钥对并签发单张证书（密钥更新）。
    返回 (是否成功, 错误信息, 信息字典)。
    """
    pki_dir = str(PKI_DIR)
    root_cert = os.path.join(pki_dir, "root.crt")
    ca_conf = os.path.join(pki_dir, "ca.cnf")

    if not os.path.exists(root_cert):
        return False, "未找到根 CA 证书，请先签发根证书。", {}

    ts = _now_compact()

    # 根据算法确定参数
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

    ext = sign_ext if cert_type == "signing" else enc_ext

    key_file = os.path.join(pki_dir, f"tmp-rekey-{cert_type}-{ts}.key")
    csr_file = os.path.join(pki_dir, f"tmp-rekey-{cert_type}-{ts}.csr")
    conf_file = os.path.join(pki_dir, f"tmp-rekey-{cert_type}-{ts}.cnf")
    cert_tmp = os.path.join(pki_dir, f"tmp-rekey-{cert_type}-{ts}.crt")

    write_req_conf(conf_file, dn)

    # 生成新密钥
    cmd = f'{OPENSSL_BIN} ecparam -name {curve} -genkey -noout -out "{key_file}"'
    if not _run_ok(cmd):
        return False, f"密钥生成失败（更新）", {}

    # 生成 CSR
    cmd = (
        f'{OPENSSL_BIN} req -new {md_flag} -key "{key_file}" '
        f'-config "{conf_file}" -out "{csr_file}"'
    )
    if not _run_ok(cmd):
        return False, f"CSR 生成失败（更新）", {}

    # CA 签发
    cmd = (
        f'{OPENSSL_BIN} ca -batch -config "{ca_conf}" '
        f'-extensions {ext} -days {days} -in "{csr_file}" '
        f'-out "{cert_tmp}" -notext'
    )
    if not _run_ok(cmd):
        return False, f"CA 签发失败（更新）", {}

    serial = get_cert_serial(cert_tmp)

    # 移动到最终位置
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

    return True, "", {
        "serial": serial,
        "type": cert_type,
        "cert_file": cert_final,
        "key_file": key_final,
        "cert_pem": cert_pem,
        "key_pem": key_pem,
        "issue_date": start,
        "expiry_date": end,
    }


def issue_intermediate_ca(
    parent_cert_path: str,
    parent_key_path: str,
    dn: str,
    days: int = 1825,
    algorithm: str = "ECDSA-P256",
    pathlen: int = 1,
) -> tuple[bool, str, dict]:
    """
    由上级 CA 签发中间 CA 证书。
    使用 openssl x509 -req 直接签发，不依赖 ca 索引数据库。
    pathlen: 中间 CA 可以再签发几级子 CA（0 表示不可再签发下级 CA）。
    返回 (是否成功, 错误信息, 信息字典)。
    """
    pki_dir = str(PKI_DIR)

    if not os.path.exists(parent_cert_path):
        return False, f"上级 CA 证书不存在: {parent_cert_path}", {}
    if not os.path.exists(parent_key_path):
        return False, f"上级 CA 私钥不存在: {parent_key_path}", {}

    ts = _now_compact()

    # 确定曲线和哈希
    if algorithm == "SM2":
        md_flag = "-sm3"
        curve = "SM2"
    else:
        md_flag = "-sha256"
        curve = "prime256v1"

    ica_key = os.path.join(pki_dir, f"intermediate-ca-{ts}.key")
    ica_csr = os.path.join(pki_dir, f"intermediate-ca-{ts}.csr")
    ica_conf = os.path.join(pki_dir, f"intermediate-ca-{ts}.cnf")
    ica_cert_tmp = os.path.join(pki_dir, f"intermediate-ca-{ts}.crt")

    write_req_conf(ica_conf, dn)

    # 生成中间 CA 的密钥对
    ok, err = generate_keypair(ica_key, algorithm)
    if not ok:
        return False, f"中间 CA 密钥生成失败: {err}", {}

    # 生成 CSR
    cmd = (
        f'{OPENSSL_BIN} req -new {md_flag} -key "{ica_key}" '
        f'-config "{ica_conf}" -out "{ica_csr}"'
    )
    if not _run_ok(cmd):
        return False, "中间 CA CSR 生成失败", {}

    # 由上级 CA 直接签发（openssl x509 -req 方式，不依赖 ca 索引）
    ext_content = (
        f"basicConstraints=critical,CA:TRUE,pathlen:{pathlen}\n"
        "keyUsage=critical,digitalSignature,nonRepudiation,keyCertSign,cRLSign\n"
    )
    ext_file = os.path.join(pki_dir, f"intermediate-ca-{ts}.ext")
    with open(ext_file, "w") as f:
        f.write(ext_content)

    cmd = (
        f'{OPENSSL_BIN} x509 -req {md_flag} '
        f'-in "{ica_csr}" -CA "{parent_cert_path}" -CAkey "{parent_key_path}" '
        f'-days {days} -CAcreateserial '
        f'-extfile "{ext_file}" '
        f'-out "{ica_cert_tmp}"'
    )
    if not _run_ok(cmd):
        return False, "中间 CA 签发失败（上级 CA 签名错误）", {}

    serial = get_cert_serial(ica_cert_tmp)

    # 移动到最终位置
    cert_final = os.path.join(pki_dir, "active-certificates", f"{serial}.cer.pem")
    key_final = os.path.join(pki_dir, "active-keys", f"{serial}.key.pem")
    os.makedirs(os.path.dirname(cert_final), exist_ok=True)
    os.makedirs(os.path.dirname(key_final), exist_ok=True)
    os.rename(ica_cert_tmp, cert_final)
    os.rename(ica_key, key_final)

    start, end = get_cert_dates(cert_final)
    subject = get_cert_subject(cert_final)
    parent_serial = get_cert_serial(parent_cert_path)
    parent_subject = get_cert_subject(parent_cert_path)

    with open(cert_final) as f:
        cert_pem = f.read()
    with open(key_final) as f:
        key_pem = f.read()

    return True, "", {
        "serial": serial,
        "subject": subject,
        "algorithm": algorithm,
        "issue_date": start,
        "expiry_date": end,
        "days": days,
        "cert_pem": cert_pem,
        "key_pem": key_pem,
        "cert_file": cert_final,
        "key_file": key_final,
        "parent_serial": parent_serial,
        "parent_subject": parent_subject,
        "pathlen": pathlen,
    }


def issue_user_cert_by_ca(
    ca_cert_path: str,
    ca_key_path: str,
    dn: str,
    days: int = 365,
    algorithm: str = "ECDSA-P256",
) -> tuple[bool, str, dict]:
    """
    由指定 CA（根 CA 或中间 CA）签发用户双证书。
    使用 openssl x509 -req 方式，不依赖 ca 索引。
    返回 (是否成功, 错误信息, 信息字典)。
    """
    pki_dir = str(PKI_DIR)

    if not os.path.exists(ca_cert_path):
        return False, f"CA 证书不存在: {ca_cert_path}", {}
    if not os.path.exists(ca_key_path):
        return False, f"CA 私钥不存在: {ca_key_path}", {}

    ts = _now_compact()
    results = {}

    if algorithm == "SM2":
        md_flag = "-sm3"
        curve = "SM2"
    else:
        md_flag = "-sha256"
        curve = "prime256v1"

    for cert_type in ["signing", "encryption"]:
        key_file = os.path.join(pki_dir, f"tmp-{cert_type}-{ts}.key")
        csr_file = os.path.join(pki_dir, f"tmp-{cert_type}-{ts}.csr")
        conf_file = os.path.join(pki_dir, f"tmp-{cert_type}-{ts}.cnf")
        cert_tmp = os.path.join(pki_dir, f"tmp-{cert_type}-{ts}.crt")
        ext_file = os.path.join(pki_dir, f"tmp-{cert_type}-{ts}.ext")

        write_req_conf(conf_file, dn)

        # 生成密钥
        cmd = f'{OPENSSL_BIN} ecparam -name {curve} -genkey -noout -out "{key_file}"'
        if not _run_ok(cmd):
            return False, f"{cert_type} 密钥生成失败", {}

        # 生成 CSR
        cmd = (
            f'{OPENSSL_BIN} req -new {md_flag} -key "{key_file}" '
            f'-config "{conf_file}" -out "{csr_file}"'
        )
        if not _run_ok(cmd):
            return False, f"{cert_type} CSR 生成失败", {}

        # 写入扩展
        if cert_type == "signing":
            ext = "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,nonRepudiation\nextendedKeyUsage=clientAuth,serverAuth\n"
        else:
            ext = "basicConstraints=CA:FALSE\nkeyUsage=keyAgreement,keyEncipherment,dataEncipherment\nextendedKeyUsage=clientAuth,serverAuth\n"
        with open(ext_file, "w") as f:
            f.write(ext)

        # 由指定 CA 签发
        cmd = (
            f'{OPENSSL_BIN} x509 -req {md_flag} '
            f'-in "{csr_file}" -CA "{ca_cert_path}" -CAkey "{ca_key_path}" '
            f'-days {days} -CAcreateserial '
            f'-extfile "{ext_file}" '
            f'-out "{cert_tmp}"'
        )
        if not _run_ok(cmd):
            return False, f"{cert_type} 签发失败", {}

        serial = get_cert_serial(cert_tmp)

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


def verify_cert_chain(cert_path: str, ca_cert_path: str) -> tuple[bool, str]:
    """
    验证证书链：检查 cert 是否由 ca 签发。
    返回 (是否通过, 输出信息)。
    """
    cmd = (
        f'{OPENSSL_BIN} verify -CAfile "{ca_cert_path}" "{cert_path}"'
    )
    rc, out, err = _run(cmd)
    combined = out + "\n" + err
    return rc == 0, combined


def export_chain_pem(cert_files: list[str]) -> str:
    """
    将多个证书 PEM 文件拼接为证书链（从叶子到根）。
    cert_files: 证书文件路径列表，从端实体到根 CA。
    返回拼接后的 PEM 字符串。
    """
    chain_parts = []
    for cf in cert_files:
        if os.path.exists(cf):
            with open(cf) as f:
                chain_parts.append(f.read().strip())
    return "\n".join(chain_parts)


def build_dn(cn: str, ou: str = "", o: str = "", email: str = "",
             st: str = "", l: str = "", c: str = "") -> str:
    """构建 OpenSSL 格式的 DN 字符串。"""
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
    """将 OpenSSL DN 字符串解析为字典。"""
    result = {}
    for part in dn.split("/"):
        if "=" in part:
            key, _, value = part.partition("=")
            result[key.strip()] = value.strip()
    return result


# ── OCSP 在线证书状态协议 ──────────────────────────────────────────

def generate_ocsp_response(cert_path: str, ca_cert_path: str, ca_key_path: str,
                           index_path: str, output_path: str) -> tuple[bool, str, str]:
    """
    生成 OCSP 响应（DER 格式）。
    使用 openssl ocsp 命令，基于 CA 索引签发 OCSP 响应。
    返回 (是否成功, OCSP状态文本, 错误信息)。
    成功时 output_path 保存 DER 格式的 OCSP 响应。
    """
    if not os.path.exists(cert_path):
        return False, "", f"证书文件不存在: {cert_path}"
    if not os.path.exists(ca_cert_path):
        return False, "", f"CA 证书不存在: {ca_cert_path}"
    if not os.path.exists(ca_key_path):
        return False, "", f"CA 私钥不存在: {ca_key_path}"
    if not os.path.exists(index_path):
        return False, "", f"CA 索引文件不存在: {index_path}"

    cmd = (
        f'{OPENSSL_BIN} ocsp -index "{index_path}" '
        f'-CA "{ca_cert_path}" -issuer "{ca_cert_path}" '
        f'-rsigner "{ca_cert_path}" -rkey "{ca_key_path}" '
        f'-cert "{cert_path}" '
        f'-respout "{output_path}" -text '
        f'-no-CAfile -no-CApath'
    )

    rc, out, err = _run(cmd)
    if rc != 0:
        return False, out + "\n" + err, f"OCSP 响应生成失败: {err or out}"

    # 从输出中提取状态
    status_text = out + "\n" + err
    return True, status_text, ""


def get_ocsp_status(cert_path: str, ca_cert_path: str, ca_key_path: str,
                    index_path: str) -> tuple[bool, str, str]:
    """
    查询证书的 OCSP 状态（仅查询，不生成响应文件）。
    返回 (是否成功, 状态文本, 错误信息)。
    """
    if not os.path.exists(cert_path):
        return False, "", f"证书文件不存在: {cert_path}"
    if not os.path.exists(ca_cert_path):
        return False, "", f"CA 证书不存在: {ca_cert_path}"
    if not os.path.exists(ca_key_path):
        return False, "", f"CA 私钥不存在: {ca_key_path}"
    if not os.path.exists(index_path):
        return False, "", f"CA 索引文件不存在: {index_path}"

    cmd = (
        f'{OPENSSL_BIN} ocsp -index "{index_path}" '
        f'-CA "{ca_cert_path}" -issuer "{ca_cert_path}" '
        f'-rsigner "{ca_cert_path}" -rkey "{ca_key_path}" '
        f'-cert "{cert_path}" -text '
        f'-no-CAfile -no-CApath'
    )

    rc, out, err = _run(cmd)
    if rc != 0:
        return False, out + "\n" + err, f"OCSP 查询失败: {err or out}"

    status_text = out + "\n" + err
    return True, status_text, ""


def ocsp_status_to_summary(status_text: str) -> dict:
    """将 OCSP 状态文本解析为结构化摘要。"""
    text = status_text.lower()
    if "good" in text:
        status = "good"
        desc = "证书状态正常（未被吊销）"
    elif "revoked" in text:
        status = "revoked"
        desc = "证书已被吊销"
    elif "unknown" in text:
        status = "unknown"
        desc = "证书状态未知（不在 CA 索引中）"
    else:
        status = "error"
        desc = "无法解析 OCSP 状态"

    return {"status": status, "description": desc, "raw": status_text}


def ocsp_response_to_base64(der_path: str) -> str:
    """
    将 DER 格式的 OCSP 响应转为 Base64（用于 OCSP 装订）。
    返回 Base64 编码的字符串。
    """
    import base64
    if not os.path.exists(der_path):
        return ""
    with open(der_path, "rb") as f:
        return base64.b64encode(f.read()).decode("ascii")


def get_ocsp_stapling_response(cert_path: str) -> tuple[bool, str, str, str]:
    """
    为证书生成 OCSP 装订响应。
    返回 (是否成功, Base64编码的OCSP响应, 状态文本, 错误信息)。
    """
    pki_dir = str(PKI_DIR)
    ca_cert = os.path.join(pki_dir, "root.crt")
    ca_key = os.path.join(pki_dir, "root-private.key")
    index = os.path.join(pki_dir, "ca", "index.txt")
    resp_der = os.path.join(pki_dir, "ocsp-temp.der")

    if not os.path.exists(ca_cert):
        return False, "", "", "根 CA 证书不存在"
    if not os.path.exists(ca_key):
        return False, "", "", "根 CA 私钥不存在"
    if not os.path.exists(index):
        return False, "", "", "CA 索引文件不存在"

    ok, status_text, err = generate_ocsp_response(
        cert_path=cert_path,
        ca_cert_path=ca_cert,
        ca_key_path=ca_key,
        index_path=index,
        output_path=resp_der,
    )

    if not ok:
        return False, "", status_text, err

    b64 = ocsp_response_to_base64(resp_der)
    return True, b64, status_text, ""
