"""
PKI/CA 系统 — FastAPI 后端服务
数字证书生命周期管理
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

# ── 请求/响应模型 ─────────────────────────────────────────────────

class IssueRootRequest(BaseModel):
    cn: str = Field(default="PKI Root CA", description="通用名称 (Common Name)")
    ou: str = Field(default="PKI实验室", description="组织单位 (Organizational Unit)")
    o: str = Field(default="实训CA中心", description="组织 (Organization)")
    email: str = Field(default="ca@example.edu", description="电子邮箱")
    st: str = Field(default="山东", description="省份 (State/Province)")
    l: str = Field(default="济南", description="城市 (Locality/City)")
    c: str = Field(default="CN", description="国家 (Country)")
    days: int = Field(default=3650, ge=1, le=36500, description="有效天数")
    algorithm: str = Field(default="ECDSA-P256", description="算法：ECDSA-P256 或 SM2")


class IssueUserRequest(BaseModel):
    cn: str = Field(..., description="通用名称，必填 (Common Name)")
    ou: str = Field(default="", description="组织单位 (Organizational Unit)")
    o: str = Field(default="", description="组织 (Organization)")
    email: str = Field(default="", description="电子邮箱")
    st: str = Field(default="", description="省份 (State/Province)")
    l: str = Field(default="", description="城市 (Locality/City)")
    c: str = Field(default="", description="国家 (Country)")
    days: int = Field(default=365, ge=1, le=36500, description="有效天数")
    algorithm: str = Field(default="ECDSA-P256", description="算法：ECDSA-P256 或 SM2")


class RevokeRequest(BaseModel):
    serial: str = Field(..., description="证书序列号")
    reason: str = Field(default="unspecified", description="吊销原因")


class IssueCRLRequest(BaseModel):
    days: int = Field(default=7, ge=1, le=365, description="CRL 有效天数")


# ── 静态文件与前端页面 ───────────────────────────────────────────

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


@app.get("/")
async def index():
    """提供主 Web 应用页面。"""
    return FileResponse(str(BASE_DIR / "static" / "index.html"))


# ── 系统状态端点 ─────────────────────────────────────────────────

@app.get("/api/status")
async def system_status():
    """获取系统整体状态。"""
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


# ── 根 CA 端点 ───────────────────────────────────────────────────

@app.post("/api/ca/issue")
async def issue_root_ca(req: IssueRootRequest):
    """签发（自签名）根 CA 证书。"""
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

        # 保存到数据库
        database.save_root_ca(info)

        return {
            "status": "ok",
            "message": "根 CA 证书签发成功。",
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
    """获取当前根 CA 证书信息。"""
    root = database.get_active_root_ca()
    if not root:
        return {"status": "ok", "root_ca": None, "message": "未找到根 CA 证书。"}

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


# ── 证书端点 ─────────────────────────────────────────────────────

@app.post("/api/certificates/issue")
async def issue_certificate(req: IssueUserRequest):
    """签发用户证书（签名 + 加密双证书）。"""
    try:
        # 检查根 CA 是否存在
        root = database.get_active_root_ca()
        if not root:
            raise HTTPException(status_code=400, detail="未找到根 CA 证书，请先签发根证书。")

        dn = crypto_utils.build_dn(
            cn=req.cn, ou=req.ou, o=req.o, email=req.email,
            st=req.st, l=req.l, c=req.c,
        )

        ok, err, result = crypto_utils.issue_user_cert(
            dn=dn, days=req.days, algorithm=req.algorithm,
        )

        if not ok:
            raise HTTPException(status_code=400, detail=err)

        # 为双证书对生成组 ID
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
            "message": "用户证书签发成功。",
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
    status: str = Query(default=None, description="按状态筛选：active 或 revoked"),
    cert_type: str = Query(default=None, description="按类型筛选：signing 或 encryption"),
):
    """列出证书，支持按状态和类型筛选。"""
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
    """获取指定证书的详细信息。"""
    cert = database.get_certificate_by_serial(serial)
    if not cert:
        raise HTTPException(status_code=404, detail=f"证书 {serial} 未找到。")

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
async def download_certificate(serial: str, file_type: str = Query(default="cert", description="下载类型：cert 或 key")):
    """下载证书或密钥 PEM 文件。"""
    cert = database.get_certificate_by_serial(serial)
    if not cert:
        raise HTTPException(status_code=404, detail=f"证书 {serial} 未找到。")

    if file_type == "cert":
        content = cert["cert_pem"]
        filename = f"{serial}.cer.pem"
    elif file_type == "key":
        content = cert["key_pem"]
        filename = f"{serial}.key.pem"
    else:
        raise HTTPException(status_code=400, detail="file_type 参数必须为 'cert' 或 'key'")

    return JSONResponse({"status": "ok", "filename": filename, "content": content})


# ── 吊销端点 ─────────────────────────────────────────────────────

@app.post("/api/certificates/revoke")
async def revoke_certificate(req: RevokeRequest):
    """吊销证书（同时吊销同组的配对证书）。"""
    try:
        cert = database.get_certificate_by_serial(req.serial)
        if not cert:
            raise HTTPException(status_code=404, detail=f"证书 {req.serial} 未找到。")

        if cert["status"] == "revoked":
            raise HTTPException(status_code=400, detail="该证书已被吊销。")

        # 通过 OpenSSL 吊销（收集同组所有序列号）
        group_certs = database.get_certificates()
        group_serials = [
            c["serial_number"]
            for c in group_certs
            if c["group_id"] == cert["group_id"] and c["status"] == "active"
        ]

        revoked_serials = []
        for serial in group_serials:
            ok, err, info = crypto_utils.revoke_certificate(serial, req.reason)
            # OpenSSL 吊销可能因证书不在 CA 目录而失败，但仍然更新数据库
            revoked_serials.append({"serial": serial, "success": ok, "error": err if not ok else None})

        # 更新数据库
        database.revoke_certificate_in_db(req.serial, req.reason)

        return {
            "status": "ok",
            "message": f"证书组已吊销，共 {len(revoked_serials)} 张证书受影响。",
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


# ── CRL 端点 ─────────────────────────────────────────────────────

@app.post("/api/crl/issue")
async def issue_crl(req: IssueCRLRequest):
    """签发证书吊销列表 (CRL)。"""
    try:
        ok, err, info = crypto_utils.issue_crl(days=req.days)
        if not ok:
            raise HTTPException(status_code=400, detail=err)

        database.save_crl(info)

        return {
            "status": "ok",
            "message": "CRL 签发成功。",
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
    """获取当前 CRL 信息。"""
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


# ── 证书 PEM 下载端点 ────────────────────────────────────────────

@app.get("/api/certificates/{serial}/pem")
async def get_certificate_pem(serial: str):
    """获取证书和密钥的 PEM 数据，用于下载。"""
    cert = database.get_certificate_by_serial(serial)
    if not cert:
        raise HTTPException(status_code=404, detail=f"证书 {serial} 未找到。")

    return {
        "status": "ok",
        "serial": serial,
        "cert_pem": cert["cert_pem"],
        "key_pem": cert["key_pem"],
        "cert_filename": f"{serial}.cer.pem",
        "key_filename": f"{serial}.key.pem",
    }


# ── 统计端点 ─────────────────────────────────────────────────────

@app.get("/api/statistics")
async def statistics():
    """获取证书统计信息。"""
    return {
        "status": "ok",
        "statistics": database.get_statistics(),
    }
