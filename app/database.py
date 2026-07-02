"""
SQLite database models and operations for PKI/CA system.
"""

import sqlite3
import os
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "data" / "pki_ca.db"


def get_connection() -> sqlite3.Connection:
    """Get a database connection with row factory."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db() -> None:
    """Initialize database tables."""
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


# ── Root CA operations ──────────────────────────────────────────────

def save_root_ca(info: dict) -> int:
    """Save root CA information. Returns inserted id."""
    conn = get_connection()
    cursor = conn.cursor()

    # Deactivate any existing active root CAs
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
    """Get the active root CA."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM root_ca WHERE status = 'active' ORDER BY created_at DESC LIMIT 1")
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_root_ca_history() -> list[dict]:
    """Get all root CAs ordered by creation date."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM root_ca ORDER BY created_at DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ── Certificate operations ──────────────────────────────────────────

def save_certificate(info: dict, cert_type: str, group_id: str, issuer_dn: str) -> int:
    """Save a user certificate. Returns inserted id."""
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
    """Get certificates filtered by status and/or type."""
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
    """Get a certificate by its serial number."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM certificates WHERE serial_number = ?", (serial,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def revoke_certificate_in_db(serial: str, reason: str = "unspecified") -> bool:
    """Mark a certificate as revoked in the database."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT group_id FROM certificates WHERE serial_number = ?", (serial,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return False

    group_id = row["group_id"]
    revoke_time = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")

    # Revoke all certificates in the same group (dual cert: signing + encryption)
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
    """Get all revoked certificates."""
    return get_certificates(status="revoked")


# ── CRL operations ──────────────────────────────────────────────────

def save_crl(info: dict) -> int:
    """Save CRL information. Returns inserted id."""
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
    """Get the most recent CRL."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM crls ORDER BY created_at DESC LIMIT 1")
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_statistics() -> dict:
    """Get certificate statistics."""
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


# Initialize database on import
init_db()
