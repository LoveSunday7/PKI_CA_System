"""
PKI/CA 系统 SQLite 数据库模型与操作。
"""

import sqlite3
import os
from datetime import datetime, timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "data" / "pki_ca.db"


def get_connection() -> sqlite3.Connection:
    """获取数据库连接（配置行工厂模式）。"""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db() -> None:
    """初始化数据库表结构。"""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS root_ca (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            serial_number TEXT NOT NULL UNIQUE,
            subject_dn TEXT NOT NULL,
            algorithm TEXT NOT NULL DEFAULT 'ECDSA-P256',
            cert_pem TEXT NOT NULL,
            key_pem TEXT NOT NULL,
            issue_date TEXT NOT NULL,
            expiry_date TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS certificates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            serial_number TEXT NOT NULL UNIQUE,
            group_id TEXT,
            subject_dn TEXT NOT NULL,
            issuer_dn TEXT NOT NULL,
            cert_type TEXT NOT NULL CHECK(cert_type IN ('signing', 'encryption')),
            algorithm TEXT NOT NULL DEFAULT 'ECDSA-P256',
            cert_pem TEXT NOT NULL,
            key_pem TEXT NOT NULL,
            cert_file_path TEXT NOT NULL,
            key_file_path TEXT NOT NULL,
            issue_date TEXT NOT NULL,
            expiry_date TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'revoked')),
            revoke_date TEXT,
            revoke_reason TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS crls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            issue_date TEXT NOT NULL,
            next_update TEXT NOT NULL,
            crl_pem TEXT NOT NULL,
            revoked_count INTEGER DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_certs_serial ON certificates(serial_number);
        CREATE INDEX IF NOT EXISTS idx_certs_status ON certificates(status);
        CREATE INDEX IF NOT EXISTS idx_certs_group ON certificates(group_id);
        CREATE INDEX IF NOT EXISTS idx_certs_type ON certificates(cert_type);
    """)

    conn.commit()
    conn.close()


# ── 根 CA 操作 ──────────────────────────────────────────────────────

def save_root_ca(info: dict) -> int:
    """保存根 CA 信息，返回插入记录的主键 ID。"""
    conn = get_connection()
    cursor = conn.cursor()

    # 将当前活跃的根 CA 标记为已取代
    cursor.execute("UPDATE root_ca SET status = 'superseded' WHERE status = 'active'")

    cursor.execute("""
        INSERT INTO root_ca (serial_number, subject_dn, algorithm, cert_pem, key_pem,
                             issue_date, expiry_date, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'active')
    """, (
        info["serial"],
        info["subject"],
        info.get("algorithm", "ECDSA-P256"),
        info["cert_pem"],
        info["key_pem"],
        info["issue_date"],
        info["expiry_date"],
    ))

    conn.commit()
    row_id = cursor.lastrowid
    conn.close()
    return row_id


def get_active_root_ca() -> dict | None:
    """获取当前活跃的根 CA。"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM root_ca WHERE status = 'active' ORDER BY created_at DESC LIMIT 1")
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_root_ca_history() -> list[dict]:
    """获取所有根 CA 历史记录，按创建时间倒序排列。"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM root_ca ORDER BY created_at DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ── 证书操作 ────────────────────────────────────────────────────────

def save_certificate(info: dict, cert_type: str, group_id: str, issuer_dn: str) -> int:
    """保存用户证书，返回插入记录的主键 ID。"""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO certificates (serial_number, group_id, subject_dn, issuer_dn,
                                  cert_type, algorithm, cert_pem, key_pem,
                                  cert_file_path, key_file_path, issue_date, expiry_date, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')
    """, (
        info["serial"],
        group_id,
        info.get("dn", ""),
        issuer_dn,
        cert_type,
        info.get("algorithm", "ECDSA-P256"),
        info["cert_pem"],
        info["key_pem"],
        info["cert_file"],
        info["key_file"],
        info["issue_date"],
        info["expiry_date"],
    ))

    conn.commit()
    row_id = cursor.lastrowid
    conn.close()
    return row_id


def get_certificates(status: str = None, cert_type: str = None) -> list[dict]:
    """按状态和/或类型筛选证书列表。"""
    conn = get_connection()
    cursor = conn.cursor()

    query = "SELECT * FROM certificates WHERE 1=1"
    params = []

    if status:
        query += " AND status = ?"
        params.append(status)
    if cert_type:
        query += " AND cert_type = ?"
        params.append(cert_type)

    query += " ORDER BY created_at DESC"
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_certificate_by_serial(serial: str) -> dict | None:
    """按序列号查询证书。"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM certificates WHERE serial_number = ?", (serial,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def revoke_certificate_in_db(serial: str, reason: str = "unspecified") -> bool:
    """在数据库中标记证书为已吊销状态。"""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT group_id FROM certificates WHERE serial_number = ?", (serial,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return False

    group_id = row["group_id"]
    revoke_time = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")

    # 吊销同组所有证书（双证书：签名 + 加密证书一起吊销）
    cursor.execute("""
        UPDATE certificates
        SET status = 'revoked', revoke_date = ?, revoke_reason = ?
        WHERE group_id = ? AND status = 'active'
    """, (revoke_time, reason, group_id))

    revoked_count = cursor.rowcount
    conn.commit()
    conn.close()
    return revoked_count > 0


def get_revoked_certificates() -> list[dict]:
    """获取所有已吊销证书。"""
    return get_certificates(status="revoked")


def get_hold_certificates() -> list[dict]:
    """获取所有被暂扣 (certificateHold) 的证书。"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM certificates WHERE status = 'revoked' AND revoke_reason = 'certificateHold'"
        " ORDER BY created_at DESC"
    )
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def restore_certificate_in_db(serial: str) -> dict | None:
    """
    将暂扣的证书恢复为活跃状态（仅对 certificateHold 吊销类型有效）。
    返回恢复后的证书信息，失败返回 None。
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM certificates WHERE serial_number = ? AND status = 'revoked' AND revoke_reason = 'certificateHold'",
        (serial,),
    )
    cert = cursor.fetchone()
    if not cert:
        conn.close()
        return None

    cursor.execute(
        "UPDATE certificates SET status = 'active', revoke_date = NULL, revoke_reason = NULL WHERE serial_number = ?",
        (serial,),
    )
    conn.commit()
    conn.close()
    return dict(cert)


def get_expiring_certificates(within_days: int = 30) -> list[dict]:
    """获取即将过期的活跃证书（指定天数内）。"""
    conn = get_connection()
    cursor = conn.cursor()

    # 查询所有活跃证书，在 Python 层面筛选即将过期的
    cursor.execute(
        "SELECT * FROM certificates WHERE status = 'active' ORDER BY expiry_date ASC"
    )
    rows = cursor.fetchall()
    conn.close()

    now = datetime.now()
    threshold = now + timedelta(days=within_days)
    expiring = []
    for r in rows:
        cert = dict(r)
        try:
            # 解析 OpenSSL 日期格式: "Jul  2 03:00:27 2026 GMT"
            expiry_str = cert["expiry_date"]
            expiry_dt = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry_dt - now).days
            if 0 <= days_left <= within_days:
                cert["_days_left"] = days_left
                expiring.append(cert)
        except (ValueError, KeyError):
            continue

    return expiring


def get_cert_remaining_days(expiry_date: str) -> int:
    """根据过期日期字符串计算剩余天数。"""
    try:
        now = datetime.now()
        expiry_dt = datetime.strptime(expiry_date, "%b %d %H:%M:%S %Y %Z")
        return (expiry_dt - now).days
    except (ValueError, KeyError):
        return -999


# ── CRL 操作 ────────────────────────────────────────────────────────

def save_crl(info: dict) -> int:
    """保存 CRL 信息，返回插入记录的主键 ID。"""
    conn = get_connection()
    cursor = conn.cursor()

    next_update = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
    issue_date = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")

    cursor.execute("""
        INSERT INTO crls (issue_date, next_update, crl_pem, revoked_count)
        VALUES (?, ?, ?, ?)
    """, (
        issue_date,
        next_update,
        info["crl_pem"],
        info.get("revoked_count", 0),
    ))

    conn.commit()
    row_id = cursor.lastrowid
    conn.close()
    return row_id


def get_latest_crl() -> dict | None:
    """获取最新的 CRL 记录。"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM crls ORDER BY created_at DESC LIMIT 1")
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_statistics() -> dict:
    """获取证书统计信息。"""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as cnt FROM certificates WHERE status = 'active'")
    active = cursor.fetchone()["cnt"]

    cursor.execute("SELECT COUNT(*) as cnt FROM certificates WHERE status = 'revoked'")
    revoked = cursor.fetchone()["cnt"]

    cursor.execute("SELECT COUNT(*) as cnt FROM certificates WHERE status = 'active' AND cert_type = 'signing'")
    active_signing = cursor.fetchone()["cnt"]

    cursor.execute("SELECT COUNT(*) as cnt FROM certificates WHERE status = 'active' AND cert_type = 'encryption'")
    active_encryption = cursor.fetchone()["cnt"]

    cursor.execute("SELECT * FROM root_ca WHERE status = 'active' ORDER BY created_at DESC LIMIT 1")
    has_root = cursor.fetchone() is not None

    conn.close()
    return {
        "has_root_ca": has_root,
        "active_certificates": active,
        "revoked_certificates": revoked,
        "active_signing": active_signing,
        "active_encryption": active_encryption,
        "total_certificates": active + revoked,
    }


# 导入时自动初始化数据库
init_db()
