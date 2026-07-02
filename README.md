# PKI/CA 数字证书管理系统

基于 FastAPI + SQLite 的 PKI/CA 数字证书生命周期管理 Web 系统，支持根证书签发、用户双证书签发、证书注销和 CRL 管理。

## 项目结构

```
PKI_CA_System/
├── run.sh                    # 启动脚本
├── app/
│   ├── __init__.py
│   ├── main.py               # FastAPI 应用（16 个 API 端点）
│   ├── database.py           # SQLite 数据库模型与操作
│   ├── crypto_utils.py       # OpenSSL 加密操作（ECDSA / SM2）
│   └── static/
│       └── index.html        # Web 前端界面
├── data/                     # 运行时数据（证书文件、数据库）
│   └── pki/
│       ├── ca/               # CA 索引与序列号
│       ├── active-certificates/
│       ├── active-keys/
│       ├── revoked-certificates/
│       └── revoked-keys/
└── .venv/                    # Python 虚拟环境
```

## 快速开始

### 环境要求

- Python 3.10+
- OpenSSL 3.x（支持 SM2/SM3 国密算法）

### 安装依赖

```bash
cd PKI_CA_System
python -m venv .venv
source .venv/bin/activate
pip install fastapi uvicorn cryptography jinja2 aiofiles
```

### 启动服务

```bash
./run.sh          # 默认端口 8000
./run.sh 9000     # 自定义端口
```

### 访问地址

- **Web 管理界面**: http://127.0.0.1:8000
- **API 文档 (Swagger)**: http://127.0.0.1:8000/docs
- **API 文档 (ReDoc)**: http://127.0.0.1:8000/redoc

## 功能概览

| 功能模块 | 描述 |
|----------|------|
| 🏛️ 根证书签发 | 自签名根 CA 证书，支持 ECDSA P-256 和 SM2 国密算法 |
| 👤 用户证书签发 | 双证书模式，同时签发签名证书和加密证书 |
| 🗑️ 证书注销 | 按序列号吊销证书，自动处理同组双证书 |
| 📛 CRL 管理 | 生成和查看证书吊销列表 |

## API 端点

### 系统状态

| 方法 | 路径 | 描述 |
|------|------|------|
| GET | `/api/status` | 获取系统运行状态与统计信息 |
| GET | `/api/statistics` | 获取证书统计数据 |

### 根 CA 管理

| 方法 | 路径 | 描述 |
|------|------|------|
| POST | `/api/ca/issue` | 签发自签名根 CA 证书 |
| GET | `/api/ca/info` | 获取当前根 CA 证书信息 |

### 证书管理

| 方法 | 路径 | 描述 |
|------|------|------|
| POST | `/api/certificates/issue` | 签发用户双证书（签名+加密） |
| GET | `/api/certificates` | 证书列表（支持按状态/类型筛选） |
| GET | `/api/certificates/{serial}` | 证书详情 |
| POST | `/api/certificates/revoke` | 吊销证书（含同组双证书） |
| GET | `/api/certificates/{serial}/pem` | 获取证书和密钥 PEM 数据 |
| GET | `/api/certificates/{serial}/download` | 下载证书或密钥 PEM 文件 |

### CRL 管理

| 方法 | 路径 | 描述 |
|------|------|------|
| POST | `/api/crl/issue` | 签发证书吊销列表 |
| GET | `/api/crl/info` | 获取当前 CRL 信息 |

## 支持的算法

| 算法 | 密钥类型 | 哈希算法 | 说明 |
|------|----------|----------|------|
| ECDSA P-256 | prime256v1 | SHA-256 | 默认推荐，兼容性好 |
| SM2 | SM2 | SM3 | 国密标准，需 OpenSSL 支持 |

## 数据库表结构

### root_ca — 根 CA 证书

| 字段 | 类型 | 说明 |
|------|------|------|
| serial_number | TEXT | 证书序列号（唯一） |
| subject_dn | TEXT | 主题可分辨名称 |
| algorithm | TEXT | 算法 (ECDSA-P256 / SM2) |
| cert_pem | TEXT | 证书 PEM 内容 |
| key_pem | TEXT | 私钥 PEM 内容 |
| issue_date | TEXT | 签发日期 |
| expiry_date | TEXT | 过期日期 |
| status | TEXT | 状态 (active / superseded) |

### certificates — 用户证书

| 字段 | 类型 | 说明 |
|------|------|------|
| serial_number | TEXT | 证书序列号（唯一） |
| group_id | TEXT | 双证书组 ID |
| subject_dn | TEXT | 主题 DN |
| issuer_dn | TEXT | 签发者 DN |
| cert_type | TEXT | 证书类型 (signing / encryption) |
| status | TEXT | 状态 (active / revoked) |
| revoke_date | TEXT | 吊销日期 |
| revoke_reason | TEXT | 吊销原因 |

### crls — 证书吊销列表

| 字段 | 类型 | 说明 |
|------|------|------|
| issue_date | TEXT | 签发日期 |
| next_update | TEXT | 下次更新日期 |
| crl_pem | TEXT | CRL PEM 内容 |
| revoked_count | INTEGER | 已吊销证书数量 |

## 证书吊销原因

| 原因值 | 中文描述 |
|--------|----------|
| unspecified | 未指定 |
| keyCompromise | 密钥泄露 |
| cACompromise | CA 泄露 |
| affiliationChanged | 隶属变更 |
| superseded | 已被取代 |
| cessationOfOperation | 停止使用 |
| certificateHold | 证书暂扣 |

## 技术栈

- **后端框架**: FastAPI (Python)
- **数据库**: SQLite (WAL 模式)
- **加密引擎**: OpenSSL CLI
- **前端**: 原生 HTML/CSS/JavaScript（无框架依赖）
- **运行环境**: Python 虚拟环境 (.venv)

## 参考资料

- demo 目录中提供了原始 C/S 架构的 C 语言参考实现
- 基于国密标准的 PKI/CA 技术体系文档见 `demo/PkiDemo_C/`
