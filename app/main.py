"""
PKI/CA System — FastAPI Backend
Digital Certificate Lifecycle Management
"""

import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from app import crypto_utils, database

app = FastAPI(
    title="PKI/CA System",
    description="数字证书生命周期管理系统 (Digital Certificate Lifecycle Management)",
    version="1.0.0",
)

BASE_DIR = Path(__file__).resolve().parent

# ── Request/Response Models ─────────────────────────────────────────

class IssueRootRequest(BaseModel):
    cn: str = Field(default="PKI Root CA", description="Common Name")
    ou: str = Field(default="PKI实验室", description="Organizational Unit")
    o: str = Field(default="实训CA中心", description="Organization")
    email: str = Field(default="ca@example.edu", description="Email")
    st: str = Field(default="山东", description="State/Province")
    l: str = Field(default="济南", description="Locality/City")
    c: str = Field(default="CN", description="Country")
    days: int = Field(default=3650, ge=1, le=36500, description="Validity in days")
    algorithm: str = Field(default="ECDSA-P256", description="Algorithm: ECDSA-P256 or SM2")


class IssueUserRequest(BaseModel):
    cn: str = Field(..., description="Common Name (required)")
    ou: str = Field(default="", description="Organizational Unit")
    o: str = Field(default="", description="Organization")
    email: str = Field(default="", description="Email")
    st: str = Field(default="", description="State/Province")
    l: str = Field(default="", description="Locality/City")
    c: str = Field(default="", description="Country")
    days: int = Field(default=365, ge=1, le=36500, description="Validity in days")
    algorithm: str = Field(default="ECDSA-P256", description="Algorithm: ECDSA-P256 or SM2")


class RevokeRequest(BaseModel):
    serial: str = Field(..., description="Certificate serial number")
    reason: str = Field(default="unspecified", description="Revocation reason")


class IssueCRLRequest(BaseModel):
    days: int = Field(default=7, ge=1, le=365, description="CRL validity in days")


# ── Static files & Frontend ─────────────────────────────────────────

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


@app.get("/")
async def index():
    """Serve the main web application."""
    return FileResponse(str(BASE_DIR / "static" / "index.html"))


# ── System endpoints ────────────────────────────────────────────────

@app.get("/api/status")
async def system_status():
    """Get overall system status."""
    try:
        stats = database.get_statistics()
        root = database.get_active_root_ca()
        return {
            "status": "ok",
            "root_ca": {
                "exists": stats["has_root_ca"],
                "serial": root["serial_number"] if root else None,
                "subject": root["subject_dn"] if root else None,
                "algorithm": root["algorithm"] if root else None,
                "expiry": root["expiry_date"] if root else None,
            } if root else None,
            "statistics": {
                "active_certificates": stats["active_certificates"],
                "revoked_certificates": stats["revoked_certificates"],
                "active_signing": stats["active_signing"],
                "active_encryption": stats["active_encryption"],
                "total": stats["total_certificates"],
            },
            "openssl": crypto_utils._capture(f"{crypto_utils.OPENSSL_BIN} version"),
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ── Root CA endpoints ───────────────────────────────────────────────

@app.post("/api/ca/issue")
async def issue_root_ca(req: IssueRootRequest):
    """Issue (self-sign) a root CA certificate."""
    try:
        dn = crypto_utils.build_dn(
            cn=req.cn, ou=req.ou, o=req.o, email=req.email,
            st=req.st, l=req.l, c=req.c,
        )

        ok, err, info = crypto_utils.issue_root_ca(
            dn=dn, days=req.days, algorithm=req.algorithm,
        )

        if not ok:
            raise HTTPException(status_code=400, detail=err)

        # Save to database
        database.save_root_ca(info)

        return {
            "status": "ok",
            "message": "Root CA certificate issued successfully.",
            "data": {
                "serial": info["serial"],
                "subject": info["subject"],
                "algorithm": info["algorithm"],
                "issue_date": info["issue_date"],
                "expiry_date": info["expiry_date"],
                "days": info["days"],
            },
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/ca/info")
async def get_root_ca_info():
    """Get current root CA information."""
    root = database.get_active_root_ca()
    if not root:
        return {"status": "ok", "root_ca": None, "message": "No root CA found."}

    return {
        "status": "ok",
        "root_ca": {
            "serial": root["serial_number"],
            "subject": root["subject_dn"],
            "algorithm": root["algorithm"],
            "issue_date": root["issue_date"],
            "expiry_date": root["expiry_date"],
            "status": root["status"],
            "cert_pem": root["cert_pem"],
        },
    }


# ── Certificate endpoints ───────────────────────────────────────────

@app.post("/api/certificates/issue")
async def issue_certificate(req: IssueUserRequest):
    """Issue user certificates (signing + encryption dual certificate)."""
    try:
        # Check root CA exists
        root = database.get_active_root_ca()
        if not root:
            raise HTTPException(status_code=400, detail="Root CA not found. Please issue a root CA first.")

        dn = crypto_utils.build_dn(
            cn=req.cn, ou=req.ou, o=req.o, email=req.email,
            st=req.st, l=req.l, c=req.c,
        )

        ok, err, result = crypto_utils.issue_user_cert(
            dn=dn, days=req.days, algorithm=req.algorithm,
        )

        if not ok:
            raise HTTPException(status_code=400, detail=err)

        # Generate group ID for dual cert pair
        group_id = f"{crypto_utils._now_compact()}{uuid.uuid4().hex[:4]}"
        issuer_dn = root["subject_dn"]

        saved_certs = []
        for cert_type in ["signing", "encryption"]:
            cert_info = result[cert_type].copy()
            cert_info["dn"] = dn
            cert_info["algorithm"] = req.algorithm
            cert_id = database.save_certificate(cert_info, cert_type, group_id, issuer_dn)
            saved_certs.append({
                "id": cert_id,
                "serial": cert_info["serial"],
                "type": cert_type,
                "subject_dn": dn,
                "issue_date": cert_info["issue_date"],
                "expiry_date": cert_info["expiry_date"],
            })

        return {
            "status": "ok",
            "message": "User certificates issued successfully.",
            "data": {
                "group_id": group_id,
                "certificates": saved_certs,
                "algorithm": req.algorithm,
                "days": req.days,
            },
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/certificates")
async def list_certificates(
    status: str = Query(default=None, description="Filter: active or revoked"),
    cert_type: str = Query(default=None, description="Filter: signing or encryption"),
):
    """List certificates with optional filters."""
    certs = database.get_certificates(status=status, cert_type=cert_type)
    return {
        "status": "ok",
        "count": len(certs),
        "certificates": [
            {
                "id": c["id"],
                "serial": c["serial_number"],
                "group_id": c["group_id"],
                "subject_dn": c["subject_dn"],
                "issuer_dn": c["issuer_dn"],
                "type": c["cert_type"],
                "algorithm": c["algorithm"],
                "issue_date": c["issue_date"],
                "expiry_date": c["expiry_date"],
                "status": c["status"],
                "revoke_date": c["revoke_date"],
                "revoke_reason": c["revoke_reason"],
                "created_at": c["created_at"],
            }
            for c in certs
        ],
    }


@app.get("/api/certificates/{serial}")
async def get_certificate_detail(serial: str):
    """Get detailed information for a specific certificate."""
    cert = database.get_certificate_by_serial(serial)
    if not cert:
        raise HTTPException(status_code=404, detail=f"Certificate {serial} not found.")

    return {
        "status": "ok",
        "certificate": {
            "id": cert["id"],
            "serial": cert["serial_number"],
            "group_id": cert["group_id"],
            "subject_dn": cert["subject_dn"],
            "issuer_dn": cert["issuer_dn"],
            "type": cert["cert_type"],
            "algorithm": cert["algorithm"],
            "cert_pem": cert["cert_pem"],
            "key_pem": cert["key_pem"],
            "issue_date": cert["issue_date"],
            "expiry_date": cert["expiry_date"],
            "status": cert["status"],
            "revoke_date": cert["revoke_date"],
            "revoke_reason": cert["revoke_reason"],
        },
    }


@app.get("/api/certificates/{serial}/download")
async def download_certificate(serial: str, file_type: str = Query(default="cert", description="cert or key")):
    """Download certificate or key PEM file."""
    cert = database.get_certificate_by_serial(serial)
    if not cert:
        raise HTTPException(status_code=404, detail=f"Certificate {serial} not found.")

    if file_type == "cert":
        content = cert["cert_pem"]
        filename = f"{serial}.cer.pem"
    elif file_type == "key":
        content = cert["key_pem"]
        filename = f"{serial}.key.pem"
    else:
        raise HTTPException(status_code=400, detail="file_type must be 'cert' or 'key'")

    return JSONResponse({"status": "ok", "filename": filename, "content": content})


# ── Revocation endpoints ────────────────────────────────────────────

@app.post("/api/certificates/revoke")
async def revoke_certificate(req: RevokeRequest):
    """Revoke a certificate (and its paired certificate in the same group)."""
    try:
        cert = database.get_certificate_by_serial(req.serial)
        if not cert:
            raise HTTPException(status_code=404, detail=f"Certificate {req.serial} not found.")

        if cert["status"] == "revoked":
            raise HTTPException(status_code=400, detail="Certificate is already revoked.")

        # Revoke via OpenSSL (gather group serials)
        group_certs = database.get_certificates()
        group_serials = [
            c["serial_number"]
            for c in group_certs
            if c["group_id"] == cert["group_id"] and c["status"] == "active"
        ]

        revoked_serials = []
        for serial in group_serials:
            ok, err, info = crypto_utils.revoke_certificate(serial, req.reason)
            # OpenSSL revoke may fail if cert not in CA dir; we still update DB
            # The CA command revokes from the CA index, which uses the .pem file
            revoked_serials.append({"serial": serial, "success": ok, "error": err if not ok else None})

        # Update database
        database.revoke_certificate_in_db(req.serial, req.reason)

        return {
            "status": "ok",
            "message": f"Certificate group revoked. {len(revoked_serials)} certificate(s) affected.",
            "data": {
                "revoked_serials": revoked_serials,
                "reason": req.reason,
                "group_id": cert["group_id"],
            },
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── CRL endpoints ───────────────────────────────────────────────────

@app.post("/api/crl/issue")
async def issue_crl(req: IssueCRLRequest):
    """Issue a Certificate Revocation List."""
    try:
        ok, err, info = crypto_utils.issue_crl(days=req.days)
        if not ok:
            raise HTTPException(status_code=400, detail=err)

        database.save_crl(info)

        return {
            "status": "ok",
            "message": "CRL issued successfully.",
            "data": {
                "revoked_count": info["revoked_count"],
                "days": info["days"],
                "crl_text": info.get("crl_text", ""),
                "archive_file": info["archive_file"],
            },
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/crl/info")
async def get_crl_info():
    """Get current CRL information."""
    db_crl = database.get_latest_crl()
    file_crl = crypto_utils.get_crl_info()

    return {
        "status": "ok",
        "database_crl": {
            "issue_date": db_crl["issue_date"],
            "next_update": db_crl["next_update"],
            "revoked_count": db_crl["revoked_count"],
        } if db_crl else None,
        "file_crl": file_crl,
    }


# ── Certificate detail (for certificate info page) ──────────────────

@app.get("/api/certificates/{serial}/pem")
async def get_certificate_pem(serial: str):
    """Get certificate and key PEM data for download."""
    cert = database.get_certificate_by_serial(serial)
    if not cert:
        raise HTTPException(status_code=404, detail=f"Certificate {serial} not found.")

    return {
        "status": "ok",
        "serial": serial,
        "cert_pem": cert["cert_pem"],
        "key_pem": cert["key_pem"],
        "cert_filename": f"{serial}.cer.pem",
        "key_filename": f"{serial}.key.pem",
    }


# ── Statistics ──────────────────────────────────────────────────────

@app.get("/api/statistics")
async def statistics():
    """Get certificate statistics."""
    return {
        "status": "ok",
        "statistics": database.get_statistics(),
    }
