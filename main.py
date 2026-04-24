"""
卡密管理系统 —— 纯国内游戏加速版（SOCKS5 Mixed 架构）
技术栈：FastAPI + SQLAlchemy + SQLite + Jinja2

架构说明（与底层 3x-ui 对接方式）：
    下层：3x-ui 面板创建一个 `mixed` 协议入站（端口 28888，纯明文，SOCKS5/HTTP 二合一）。
    中层：本服务通过 /panel/api/inbounds/addClient 把用户（user/pass）同步进入站。
    上层：客户端（小火箭等）通过 GET /sub?username=&password= 拉到一条 socks5:// 节点 URI，
           也可直接在客户端手动按「服务器/端口/账号/密码」填入。

启动方式：
    uvicorn main:app --host 0.0.0.0 --port 8000

关键环境变量：
    ADMIN_TOKEN            管理员 Token（默认 fanxiaoyu6F@，生产必改！）
    BASE_URL               服务公网地址（默认 http://localhost:8000）
    SOCKS_SERVER_HOST      SOCKS5 节点公网地址（默认 106.14.137.59）
    SOCKS_SERVER_PORT      SOCKS5 节点端口（默认 28888）
    SOCKS_NODE_NAME        节点名称（默认 风度防封专线）
    XUI_*                  3x-ui 面板对接参数
    XUI_SOCKS_INBOUND_ID   mixed 入站 ID（默认 3）
"""

import os
import json
import uuid
import hashlib
import logging
import secrets
import string
import base64
import threading
from typing import Optional
from datetime import datetime, timedelta
from urllib.parse import quote as _urlquote

import requests
from fastapi import FastAPI, Depends, HTTPException, Header, Request, UploadFile, File, Form
from fastapi.exceptions import RequestValidationError
from fastapi.responses import (
    HTMLResponse,
    RedirectResponse,
    JSONResponse,
    PlainTextResponse,
    FileResponse,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from sqlalchemy import update, text, inspect
from sqlalchemy.orm import Session

import models
from database import engine, get_db

logger = logging.getLogger("cardkey")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")


# ══════════════════════════════════════════════════════════════════════
# 启动时的轻量级数据库迁移
# ----------------------------------------------------------------------
# SQLAlchemy 的 create_all 不会为已存在的表补字段。
# 升级后新增了 `ss_password` 字段（用于承载「用户明文登录密码」，
# 在 SOCKS5 架构里它就是用户连接代理所用的 pass），
# 这里幂等地给老库补上该列，避免启动报错。
# ══════════════════════════════════════════════════════════════════════

models.Base.metadata.create_all(bind=engine)


def _ensure_schema_migrations() -> None:
    inspector = inspect(engine)
    if "users" not in inspector.get_table_names():
        return
    existing_cols = {c["name"] for c in inspector.get_columns("users")}
    with engine.begin() as conn:
        if "ss_password" not in existing_cols:
            conn.execute(text("ALTER TABLE users ADD COLUMN ss_password VARCHAR(128)"))
            logger.info("[DB 迁移] users 表已补 ss_password 列")


_ensure_schema_migrations()


app = FastAPI(title="卡密管理系统（SOCKS5）", version="3.1.0")
templates = Jinja2Templates(directory="templates")

# ── 静态资源挂载（证书 / 配置文件 下载） ────────────────────────────────
# 目录结构：
#   static/cert/Shadowrocket.crt    —— 小火箭 MITM 根证书
#   static/config/default.conf      —— 默认分流配置
# 前端会用 <a href="/static/config/default.conf" download> 之类的链接直接拉取。
# 确保证书 / 配置子目录存在（必须在 mount 之前，否则首次启动时 static/ 不存在会导致 mount 跳过）
os.makedirs("static/cert", exist_ok=True)
os.makedirs("static/config", exist_ok=True)

app.mount("/static", StaticFiles(directory="static"), name="static")


# ══════════════════════════════════════════════════════════════════════
# Pydantic 校验错误汉化（给前端的 422 统一中文提示）
# ══════════════════════════════════════════════════════════════════════

_VALIDATION_MSG_MAP = {
    "field required":                       "此字段为必填项",
    "value is not a valid integer":         "请输入有效的整数",
    "value is not a valid":                 "格式不正确",
    "ensure this value has at least":       "长度不足，最少",
    "ensure this value has at most":        "长度超限，最多",
    "string does not match regex":          "格式不符合要求",
    "none is not an allowed value":         "该字段不能为空",
    "characters":                           "个字符",
    "extra fields not permitted":           "不允许传入额外字段",
    "str type expected":                    "请输入字符串类型",
    "int type expected":                    "请输入整数类型",
}


def _translate_validation_msg(msg: str) -> str:
    for en, zh in _VALIDATION_MSG_MAP.items():
        if en in msg:
            msg = msg.replace(en, zh)
    return msg


@app.exception_handler(RequestValidationError)
async def _validation_exception_handler(request: Request, exc: RequestValidationError):
    parts = []
    for err in exc.errors():
        loc_parts = [str(x) for x in err.get("loc", []) if x not in ("body", "query")]
        loc_str   = " → ".join(loc_parts) if loc_parts else ""
        msg       = _translate_validation_msg(err.get("msg", "参数格式有误"))
        parts.append(f"{loc_str}：{msg}" if loc_str else msg)
    detail = "；".join(parts) if parts else "请求参数格式有误，请检查后重试"
    return JSONResponse(status_code=422, content={"detail": detail})


# ══════════════════════════════════════════════════════════════════════
# 全局配置
# ══════════════════════════════════════════════════════════════════════

ADMIN_TOKEN         = os.getenv("ADMIN_TOKEN", "fanxiaoyu6F@")
BASE_URL            = os.getenv("BASE_URL", "http://localhost:8000")
ADMIN_SESSION_TOKEN = secrets.token_urlsafe(32)

# ── SOCKS5 节点对外参数（下发给客户端 / 生成 socks5:// URI） ───────────
SOCKS_SERVER_HOST = os.getenv("SOCKS_SERVER_HOST", "106.14.137.59").strip()
SOCKS_SERVER_PORT = int(os.getenv("SOCKS_SERVER_PORT", "28888"))
SOCKS_NODE_NAME   = os.getenv("SOCKS_NODE_NAME", "风度防封专线").strip()
SOCKS_TLS_ENABLED = os.getenv("SOCKS_TLS", "1") != "0"

# ══════════════════════════════════════════════════════════════════════
# ★★★ 3x-ui 面板对接配置（mixed 协议 / SOCKS5+HTTP） ★★★
# ----------------------------------------------------------------------
# 本系统与 3x-ui 在同机部署时，走 127.0.0.1 内网最稳最快。
#
# XUI_SOCKS_INBOUND_ID 的查看方式：
#   进入 3x-ui → 入站列表 → 找到「协议=mixed、端口=28888」的那条 →
#   行首的数字 ID 即为该值。默认 3。
# ══════════════════════════════════════════════════════════════════════
XUI_HOST             = os.getenv("XUI_HOST",      "http://127.0.0.1:2053").rstrip("/")
XUI_USERNAME         = os.getenv("XUI_USERNAME",  "admin")
XUI_PASSWORD         = os.getenv("XUI_PASSWORD",  "admin")
XUI_SOCKS_INBOUND_ID = int(os.getenv("XUI_SOCKS_INBOUND_ID", "3"))
XUI_VERIFY_SSL       = os.getenv("XUI_VERIFY_SSL",  "1") != "0"
XUI_WEB_BASE_PATH    = os.getenv("XUI_WEB_BASE_PATH", "").strip().strip("/")
XUI_ENABLED          = os.getenv("XUI_ENABLED", "1") != "0"


# ══════════════════════════════════════════════════════════════════════
# 工具函数
# ══════════════════════════════════════════════════════════════════════

def _hash_password(password: str) -> str:
    """SHA-256 密码哈希（固定盐，抗彩虹表）。"""
    salt = "cardkey-salt-2024"
    return hashlib.sha256(f"{salt}{password}".encode()).hexdigest()


def _runtime_base_url(request: Optional[Request] = None) -> str:
    """优先使用当前请求的 Host/Proto 生成公网地址；兜底 BASE_URL。"""
    if request:
        forwarded_proto = request.headers.get("x-forwarded-proto")
        forwarded_host  = request.headers.get("x-forwarded-host")
        host  = forwarded_host or request.headers.get("host")
        proto = (forwarded_proto or request.url.scheme or "http").split(",")[0].strip()
        if host:
            return f"{proto}://{host.split(',')[0].strip()}".rstrip("/")
    return BASE_URL.rstrip("/")


def _generate_key_string() -> str:
    """生成 VIP-XXXX-XXXX-XXXX 形式的随机卡密。"""
    charset = string.ascii_uppercase + string.digits
    segs = ["".join(secrets.choice(charset) for _ in range(4)) for _ in range(3)]
    return "VIP-" + "-".join(segs)


def _build_socks5_uri(username: str, password: str) -> str:
    """
    构造标准的 SOCKS5 一键导入 URI（小火箭 / Clash / V2rayN 全兼容）：

        socks5://BASE64("账号:密码")@HOST:PORT#节点名

    - BASE64 采用 url-safe 编码并去掉填充等号，避免 `/` `+` `=` 破坏 URL
    - 节点名里的中文按 RFC3986 做 URL 编码
    - **不携带任何 TLS / 加密参数**（纯明文 SOCKS5，用于国内游戏直连加速）
    """
    if not username or not password:
        return ""
    raw = f"{username}:{password}".encode("utf-8")
    b64 = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    name_q = _urlquote(SOCKS_NODE_NAME, safe="")
    return f"socks5://{b64}@{SOCKS_SERVER_HOST}:{SOCKS_SERVER_PORT}#{name_q}"


def _build_proxy_payload(username: str, password: str) -> dict:
    """统一的 SOCKS5 参数返回体（注册/续期/查询 成功时都用它）。"""
    return {
        "type":      "socks5",
        "host":      SOCKS_SERVER_HOST,
        "port":      SOCKS_SERVER_PORT,
        "tls":       "TLS（自签名证书）" if SOCKS_TLS_ENABLED else "无（明文）",
        "node_name": SOCKS_NODE_NAME,
        "username":  username,
        "password":  password,
        "socks5_uri": _build_socks5_uri(username, password),
    }


def _get_user_or_401(username: str, password: str, db: Session) -> models.User:
    """验证用户名+密码，失败统一 401（中文）。"""
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user or user.password_hash != _hash_password(password):
        raise HTTPException(status_code=401, detail="账号或密码错误，请检查后重试！")
    return user


# ══════════════════════════════════════════════════════════════════════
# 3x-ui 面板 API 客户端（mixed / SOCKS5 专用）
# ----------------------------------------------------------------------
# 对接接口（带 webBasePath 前缀时请把前缀追加进 XUI_WEB_BASE_PATH）：
#   POST  /login                                                    登录
#   POST  /panel/api/inbounds/addClient                             新增客户端
#   POST  /panel/api/inbounds/updateClient/{clientKey}              更新客户端
#   POST  /panel/api/inbounds/{inboundId}/delClient/{clientKey}     删除客户端
#
# mixed 协议下客户端的 JSON 结构（与 vmess/vless/trojan/ss 完全不同）：
#   {"user": "账号", "pass": "明文密码"}
#
# 因此与 3x-ui 对接的 Payload 形如：
#   {"id": 3, "settings": "{\"clients\": [{\"user\": \"xxx\", \"pass\": \"yyy\"}]}"}
#
# clientKey（用于 update/del 的 URL 路径）在 mixed 协议下就是 `user` 字段。
# ══════════════════════════════════════════════════════════════════════

class XUIError(RuntimeError):
    """3x-ui 面板交互错误。"""


class XUIClient:
    """线程安全的 3x-ui 面板轻量客户端（mixed / SOCKS5 版）。"""

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        inbound_id: int,
        verify_ssl: bool = True,
        web_base_path: str = "",
        timeout: float = 3.0,
    ):
        self.host          = host.rstrip("/")
        self.username      = username
        self.password      = password
        self.inbound_id    = inbound_id
        self.verify_ssl    = verify_ssl
        self.web_base_path = web_base_path.strip().strip("/")
        self.timeout       = timeout

        self._session      = requests.Session()
        self._lock         = threading.Lock()
        self._logged_in    = False

    def _url(self, path: str) -> str:
        prefix = f"/{self.web_base_path}" if self.web_base_path else ""
        return f"{self.host}{prefix}{path}"

    def login(self) -> None:
        resp = self._session.post(
            self._url("/login"),
            data={"username": self.username, "password": self.password},
            timeout=self.timeout,
            verify=self.verify_ssl,
        )
        try:
            data = resp.json()
        except Exception:
            raise XUIError(f"3x-ui 登录响应非 JSON: HTTP {resp.status_code} {resp.text[:200]}")
        if not data.get("success"):
            raise XUIError(f"3x-ui 登录失败: {data.get('msg') or data}")
        self._logged_in = True
        logger.info("[3x-ui] 登录成功 -> %s", self.host)

    def _ensure_login(self) -> None:
        if not self._logged_in:
            self.login()

    def _post(self, path: str, *, json_body=None, data=None) -> dict:
        """通用 POST，带一次自动重登。"""
        with self._lock:
            self._ensure_login()
            for attempt in (1, 2):
                resp = self._session.post(
                    self._url(path),
                    json=json_body,
                    data=data,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                )
                if resp.status_code in (401, 403) or "login" in resp.url.lower():
                    if attempt == 1:
                        self._logged_in = False
                        self.login()
                        continue
                try:
                    body = resp.json()
                except Exception:
                    raise XUIError(f"3x-ui 响应非 JSON: HTTP {resp.status_code} {resp.text[:200]}")
                if not body.get("success"):
                    raise XUIError(f"3x-ui 接口失败: {body.get('msg') or body}")
                return body

    @staticmethod
    def _build_socks_client_obj(user: str, password: str) -> dict:
        """mixed 协议的客户端对象：只需要 user / pass 两个字段。"""
        return {"user": user, "pass": password}

    def add_client(self, *, user: str, password: str) -> dict:
        """把新用户写入 mixed 入站（SOCKS5/HTTP 帐号密码鉴权）。"""
        payload = {
            "id": self.inbound_id,
            "settings": json.dumps(
                {"clients": [self._build_socks_client_obj(user, password)]},
                ensure_ascii=False,
            ),
        }
        return self._post("/panel/api/inbounds/addClient", json_body=payload)

    def update_client(self, *, client_key: str, user: str, password: str) -> dict:
        """按 clientKey（= 原用户名）更新 mixed 入站中的账号密码。"""
        payload = {
            "id": self.inbound_id,
            "settings": json.dumps(
                {"clients": [self._build_socks_client_obj(user, password)]},
                ensure_ascii=False,
            ),
        }
        return self._post(f"/panel/api/inbounds/updateClient/{client_key}", json_body=payload)

    def del_client(self, *, client_key: str) -> dict:
        """从 mixed 入站删除账号（封禁 / 到期时调用）。"""
        return self._post(f"/panel/api/inbounds/{self.inbound_id}/delClient/{client_key}")


_xui_client: Optional[XUIClient] = None


def get_xui() -> XUIClient:
    global _xui_client
    if _xui_client is None:
        _xui_client = XUIClient(
            host=XUI_HOST,
            username=XUI_USERNAME,
            password=XUI_PASSWORD,
            inbound_id=XUI_SOCKS_INBOUND_ID,
            verify_ssl=XUI_VERIFY_SSL,
            web_base_path=XUI_WEB_BASE_PATH,
        )
    return _xui_client


def _resolve_socks_password(user: "models.User") -> str:
    """
    获取用户的 SOCKS5 连接密码。
    优先 `user.ss_password`（注册/续期时写入的明文密码）；
    老数据兜底 `device_id`，保证升级后不丢连接。
    """
    return user.ss_password or user.device_id


# ══════════════════════════════════════════════════════════════════════
# 3x-ui 同步（异步化）
# ----------------------------------------------------------------------
# 【重要】以前同步实现是阻塞式：主请求里直接调 requests.post，
# 一旦 3x-ui 不可达 / TCP 连接卡住，会把整个 /api/register 请求
# 阻塞几十秒，浏览器超时就会提示「网络连接失败」，但其实卡密已经入库。
# 现在全部改为后台线程执行：主流程立刻返回，同步失败仅在服务日志里告警，
# 绝不阻塞用户。
#
# 注意：传给后台线程的必须是「字段快照（dict）」，不能是 ORM 对象，
# 因为 Session 在响应返回后会关闭，跨线程访问懒加载属性会炸。
# ══════════════════════════════════════════════════════════════════════

def _user_snapshot(user: "models.User") -> dict:
    return {
        "username":    user.username,
        "socks_pwd":   _resolve_socks_password(user),
    }


def _sync_xui_upsert_now(username: str, socks_pwd: str) -> None:
    """在调用线程里真正执行同步，供前台/后台两种方式复用。"""
    if not XUI_ENABLED:
        logger.info("[3x-ui] 已禁用同步（XUI_ENABLED=0），跳过 upsert：%s", username)
        return
    if not socks_pwd:
        logger.warning("[3x-ui] 用户缺少连接密码，跳过同步：%s", username)
        return
    try:
        xui = get_xui()
        try:
            xui.update_client(client_key=username, user=username, password=socks_pwd)
            logger.info("[3x-ui] 已更新 SOCKS 客户端：%s", username)
        except XUIError as e:
            logger.info("[3x-ui] 更新失败改为新增 (%s)：%s", e, username)
            xui.add_client(user=username, password=socks_pwd)
            logger.info("[3x-ui] 已新增 SOCKS 客户端：%s", username)
    except Exception as e:
        logger.warning("[3x-ui] upsert 同步失败（已忽略，主流程继续）：%s | %s", username, e)


def _sync_xui_remove_now(username: str) -> None:
    """在调用线程里真正执行删除。"""
    if not XUI_ENABLED:
        return
    try:
        xui = get_xui()
        xui.del_client(client_key=username)
        logger.info("[3x-ui] 已删除 SOCKS 客户端：%s", username)
    except Exception as e:
        logger.warning("[3x-ui] 删除客户端失败（已忽略）：%s | %s", username, e)


def _sync_xui_upsert(user: "models.User") -> None:
    """把 3x-ui upsert 丢到后台线程，不阻塞 HTTP 响应。"""
    snap = _user_snapshot(user)
    threading.Thread(
        target=_sync_xui_upsert_now,
        args=(snap["username"], snap["socks_pwd"]),
        name=f"xui-upsert-{snap['username']}",
        daemon=True,
    ).start()


def _sync_xui_remove(user: "models.User") -> None:
    """把 3x-ui 删除丢到后台线程，不阻塞 HTTP 响应。"""
    username = user.username
    threading.Thread(
        target=_sync_xui_remove_now,
        args=(username,),
        name=f"xui-remove-{username}",
        daemon=True,
    ).start()


# ══════════════════════════════════════════════════════════════════════
# 管理员鉴权依赖
# ══════════════════════════════════════════════════════════════════════

def verify_admin(request: Request, x_admin_token: Optional[str] = Header(default=None)):
    if x_admin_token and secrets.compare_digest(x_admin_token, ADMIN_TOKEN):
        return
    session_cookie = request.cookies.get("admin_session")
    if session_cookie and secrets.compare_digest(session_cookie, ADMIN_SESSION_TOKEN):
        return
    raise HTTPException(status_code=401, detail="管理员未登录或登录已失效")


# ══════════════════════════════════════════════════════════════════════
# Pydantic 请求模型
# ══════════════════════════════════════════════════════════════════════

class GenerateKeysRequest(BaseModel):
    count: int = Field(..., ge=1, le=500)
    duration_days: int = Field(..., ge=1)

class AccountRegisterRequest(BaseModel):
    username: str   = Field(..., min_length=1, description="账号（任意字符，含手机号）")
    password: str   = Field(..., min_length=1, description="密码（任意字符）")
    key_string: str = Field(..., min_length=1, description="卡密（普通字符串，可含连字符）")

class RechargeRequest(BaseModel):
    username: str   = Field(..., min_length=1, description="账号（任意字符）")
    password: str   = Field(..., min_length=1, description="密码（任意字符）")
    key_string: str = Field(..., min_length=1, description="卡密（普通字符串，可含连字符）")

class QueryRequest(BaseModel):
    username: str          = Field(..., min_length=1, description="要查询的账号")
    password: Optional[str] = Field(default=None, description="选填：校验通过则返回 SOCKS5 一键导入链接")

class BanUserRequest(BaseModel):
    device_id: str

class AdminLoginRequest(BaseModel):
    admin_token: str

class AdjustUserTimeRequest(BaseModel):
    device_id: str   = Field(..., description="用户设备 ID")
    delta_days: int  = Field(..., ge=-3650, le=3650, description="调整天数，正数加时，负数减时")

class DeleteFileRequest(BaseModel):
    category: str  = Field(..., description="文件分类：cert 或 config")
    filename: str  = Field(..., description="文件名")


# ══════════════════════════════════════════════════════════════════════
# 健康检查（前端 / 运维用来诊断「服务是否在跑」）
# ══════════════════════════════════════════════════════════════════════

@app.get("/api/health", tags=["系统"])
def api_health():
    return {
        "ok": True,
        "service": "cardkey",
        "server_time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S") + " UTC",
        "xui_enabled": XUI_ENABLED,
        "socks_host": SOCKS_SERVER_HOST,
        "socks_port": SOCKS_SERVER_PORT,
    }


# ══════════════════════════════════════════════════════════════════════
# 前端页面路由
# ══════════════════════════════════════════════════════════════════════

@app.get("/", response_class=HTMLResponse, tags=["页面"])
async def page_index(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "base_url":    _runtime_base_url(request),
            "server_host": SOCKS_SERVER_HOST,
            "server_port": SOCKS_SERVER_PORT,
            "node_name":   SOCKS_NODE_NAME,
            "tls_enabled": SOCKS_TLS_ENABLED,
        },
    )


@app.get("/admin", response_class=HTMLResponse, tags=["页面"])
async def page_admin_login(request: Request):
    session_cookie = request.cookies.get("admin_session") or ""
    if secrets.compare_digest(session_cookie, ADMIN_SESSION_TOKEN):
        return RedirectResponse(url="/admin/dashboard", status_code=302)
    return templates.TemplateResponse(
        request=request, name="admin_login.html", context={"error": None}
    )


@app.post("/admin/login", tags=["页面"])
async def page_admin_do_login(req: AdminLoginRequest):
    if secrets.compare_digest(req.admin_token.strip(), ADMIN_TOKEN):
        response = JSONResponse({"success": True, "redirect": "/admin/dashboard"})
        response.set_cookie(
            key="admin_session",
            value=ADMIN_SESSION_TOKEN,
            max_age=8 * 60 * 60,
            httponly=True,
            samesite="lax",
        )
        return response
    return JSONResponse({"detail": "管理员 Token 错误，请重试"}, status_code=401)


@app.post("/admin/logout", tags=["页面"])
async def page_admin_logout():
    response = RedirectResponse(url="/admin", status_code=303)
    response.delete_cookie("admin_session")
    return response


@app.get("/admin/dashboard", response_class=HTMLResponse, tags=["页面"])
async def page_admin_dashboard(request: Request, _: None = Depends(verify_admin)):
    return templates.TemplateResponse(
        request=request, name="admin.html", context={}
    )


# ══════════════════════════════════════════════════════════════════════
# 管理员接口
# ══════════════════════════════════════════════════════════════════════

@app.post("/admin/generate_keys", tags=["管理员"])
def admin_generate_keys(
    req: GenerateKeysRequest,
    db: Session = Depends(get_db),
    _: None = Depends(verify_admin),
):
    """批量生成卡密。"""
    generated = []
    for _ in range(req.count):
        for _ in range(10):
            key_str = _generate_key_string()
            if not db.query(models.Key).filter(models.Key.key_string == key_str).first():
                break
        else:
            continue
        db.add(models.Key(key_string=key_str, duration_days=req.duration_days))
        generated.append(key_str)
    db.commit()
    return {"success": True, "generated": len(generated), "duration_days": req.duration_days, "keys": generated}


@app.get("/admin/list_keys", tags=["管理员"])
def admin_list_keys(db: Session = Depends(get_db), _: None = Depends(verify_admin)):
    keys = db.query(models.Key).order_by(models.Key.created_at.desc()).all()
    return {
        "total": len(keys),
        "keys": [
            {
                "id": k.id,
                "key_string": k.key_string,
                "duration_days": k.duration_days,
                "is_used": k.is_used,
                "created_at": k.created_at.strftime("%Y-%m-%d %H:%M:%S") if k.created_at else None,
            }
            for k in keys
        ],
    }


@app.get("/admin/list_users", tags=["管理员"])
def admin_list_users(
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    db: Session = Depends(get_db),
    _: None = Depends(verify_admin),
):
    def _parse_dt(v: str, label: str) -> datetime:
        try:
            return datetime.fromisoformat(v)
        except Exception:
            raise HTTPException(status_code=400, detail=f"时间格式错误（{label}），请使用 YYYY-MM-DDTHH:MM 格式")

    q = db.query(models.User)
    start_dt = _parse_dt(start_time, "start_time") if start_time else None
    end_dt   = _parse_dt(end_time, "end_time") if end_time else None
    if start_dt and end_dt and end_dt < start_dt:
        raise HTTPException(status_code=400, detail="结束时间不能早于开始时间")
    if start_dt:
        q = q.filter(models.User.created_at >= start_dt)
    if end_dt:
        q = q.filter(models.User.created_at <= end_dt)

    users = q.order_by(models.User.created_at.desc()).all()
    now = datetime.utcnow()
    changed = False
    result = []
    for u in users:
        if u.status == "active" and u.expire_time < now:
            u.status = "expired"
            changed = True
        result.append({
            "id": u.id,
            "username": u.username,
            "device_id": u.device_id,
            "last_key": u.last_key,
            "expire_time": u.expire_time.strftime("%Y-%m-%d %H:%M:%S") if u.expire_time else None,
            "status": u.status,
            "created_at": u.created_at.strftime("%Y-%m-%d %H:%M:%S") if u.created_at else None,
        })
    if changed:
        db.commit()
    return {"total": len(result), "users": result}


@app.post("/admin/adjust_user_time", tags=["管理员"])
def admin_adjust_user_time(
    req: AdjustUserTimeRequest,
    db: Session = Depends(get_db),
    _: None = Depends(verify_admin),
):
    user = db.query(models.User).filter(models.User.device_id == req.device_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")

    now = datetime.utcnow()
    if req.delta_days >= 0:
        base_time = user.expire_time if user.expire_time > now else now
        user.expire_time = base_time + timedelta(days=req.delta_days)
    else:
        user.expire_time = user.expire_time + timedelta(days=req.delta_days)

    if user.status != "banned":
        user.status = "active" if user.expire_time > now else "expired"

    db.commit()
    db.refresh(user)

    if user.status == "active":
        _sync_xui_upsert(user)
    else:
        _sync_xui_remove(user)

    return {
        "success": True,
        "message": f"已调整 {req.delta_days} 天，当前状态：{user.status}",
        "device_id": user.device_id,
        "expire_time": user.expire_time.strftime("%Y-%m-%d %H:%M:%S"),
        "status": user.status,
    }


@app.post("/admin/ban_user", tags=["管理员"])
def admin_ban_user(req: BanUserRequest, db: Session = Depends(get_db), _: None = Depends(verify_admin)):
    user = db.query(models.User).filter(models.User.device_id == req.device_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    user.status = "banned"
    db.commit()
    _sync_xui_remove(user)
    return {"success": True, "message": f"用户 {user.username} 已封禁"}


@app.post("/admin/unban_user", tags=["管理员"])
def admin_unban_user(req: BanUserRequest, db: Session = Depends(get_db), _: None = Depends(verify_admin)):
    user = db.query(models.User).filter(models.User.device_id == req.device_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    now = datetime.utcnow()
    user.status = "active" if user.expire_time > now else "expired"
    db.commit()
    if user.status == "active":
        _sync_xui_upsert(user)
    return {"success": True, "message": f"用户 {user.username} 已解封，状态：{user.status}"}


# ══════════════════════════════════════════════════════════════════════
# 管理员文件管理接口（证书 / 配置 上传 / 删除）
# ══════════════════════════════════════════════════════════════════════

@app.get("/admin/list_files", tags=["管理员"])
def admin_list_files(_: None = Depends(verify_admin)):
    """列出 static/cert 和 static/config 目录下的文件。"""
    result = {}
    for category in ("cert", "config"):
        dirpath = os.path.join("static", category)
        files = []
        if os.path.isdir(dirpath):
            for fname in sorted(os.listdir(dirpath)):
                fpath = os.path.join(dirpath, fname)
                if os.path.isfile(fpath):
                    stat = os.stat(fpath)
                    files.append({
                        "filename": fname,
                        "size": stat.st_size,
                        "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                    })
        result[category] = files
    return result


@app.post("/admin/upload_file", tags=["管理员"])
async def admin_upload_file(
    category: str = Form(..., description="cert 或 config"),
    file: UploadFile = File(...),
    _: None = Depends(verify_admin),
):
    """上传（或覆盖）文件到 static/cert 或 static/config 目录。"""
    if category not in ("cert", "config"):
        raise HTTPException(status_code=400, detail="category 仅允许 cert 或 config")
    if not file.filename:
        raise HTTPException(status_code=400, detail="文件名不能为空")
    safe_name = os.path.basename(file.filename)
    if not safe_name:
        raise HTTPException(status_code=400, detail="无效的文件名")
    dirpath = os.path.join("static", category)
    os.makedirs(dirpath, exist_ok=True)
    filepath = os.path.join(dirpath, safe_name)
    content = await file.read()
    with open(filepath, "wb") as f:
        f.write(content)
    logger.info("[文件管理] 已上传 %s/%s（%d 字节）", category, safe_name, len(content))
    return {
        "success": True,
        "message": f"已上传 {safe_name} → {category}/",
        "filename": safe_name,
        "size": len(content),
    }


@app.post("/admin/delete_file", tags=["管理员"])
def admin_delete_file(req: DeleteFileRequest, _: None = Depends(verify_admin)):
    """删除 static/cert 或 static/config 下的指定文件。"""
    if req.category not in ("cert", "config"):
        raise HTTPException(status_code=400, detail="category 仅允许 cert 或 config")
    safe_name = os.path.basename(req.filename)
    filepath = os.path.join("static", req.category, safe_name)
    if not os.path.isfile(filepath):
        raise HTTPException(status_code=404, detail=f"文件不存在：{safe_name}")
    os.remove(filepath)
    logger.info("[文件管理] 已删除 %s/%s", req.category, safe_name)
    return {"success": True, "message": f"已删除 {req.category}/{safe_name}"}


# ══════════════════════════════════════════════════════════════════════
# 用户端接口
# ══════════════════════════════════════════════════════════════════════

@app.post("/api/register", tags=["用户端"])
def api_register(req: AccountRegisterRequest, db: Session = Depends(get_db)):
    """
    账号注册。
    流程：幂等回放检查 → 原子锁卡 → 用户名唯一性检查 → 写库 → 同步到 3x-ui → 返回 SOCKS5 参数

    ★ 幂等回放检查的意义 ★
    手机端弱网场景下，常出现「后端已入库但前端 fetch 超时/被中断」的情况，
    用户再点一次就会撞上「卡密已使用」。这里在走锁卡逻辑之前先做一次
    「同账号+同密码+同卡密」的匹配：匹配上就直接返回成功（再补一次 3x-ui 同步），
    用户端体验上就等同于「重试自愈」。
    """
    key_string = req.key_string.strip().upper()

    # ── 幂等回放：上一次请求可能已成功，本次是重试 ────────────────────
    existing = db.query(models.User).filter(models.User.username == req.username).first()
    if (
        existing
        and existing.password_hash == _hash_password(req.password)
        and (existing.last_key or "").upper() == key_string
    ):
        # 已是该用户之前用本卡密注册的结果，直接幂等返回
        key_obj = db.query(models.Key).filter(models.Key.key_string == key_string).first()
        # 补一次 3x-ui 同步（上一次可能因面板偶发抖动失败）
        _sync_xui_upsert(existing)
        return {
            "success": True,
            "username": existing.username,
            "duration_days": key_obj.duration_days if key_obj else 0,
            "expire_time": existing.expire_time.strftime("%Y-%m-%d %H:%M:%S") + " UTC",
            "proxy": _build_proxy_payload(existing.username, req.password),
            "replayed": True,
        }

    # 原子锁卡：防并发重复激活
    stmt = (
        update(models.Key)
        .where(models.Key.key_string == key_string)
        .where(models.Key.is_used == False)  # noqa: E712
        .values(is_used=True)
        .execution_options(synchronize_session="fetch")
    )
    result = db.execute(stmt)
    db.commit()

    if result.rowcount == 0:
        key_obj = db.query(models.Key).filter(models.Key.key_string == key_string).first()
        if not key_obj:
            raise HTTPException(status_code=404, detail="卡密不存在，请核对后重试！")
        raise HTTPException(status_code=409, detail="该卡密已被使用，请勿重复激活！")

    # 用户名唯一性检查
    if db.query(models.User).filter(models.User.username == req.username).first():
        # 注册失败时回滚卡密，避免误作废
        db.execute(
            update(models.Key)
            .where(models.Key.key_string == key_string)
            .values(is_used=False)
            .execution_options(synchronize_session="fetch")
        )
        db.commit()
        raise HTTPException(status_code=409, detail="该账号名已被注册，请换一个")

    key_obj     = db.query(models.Key).filter(models.Key.key_string == key_string).first()
    expire_time = datetime.utcnow() + timedelta(days=key_obj.duration_days)
    device_id   = uuid.uuid4().hex

    user = models.User(
        username      = req.username,
        password_hash = _hash_password(req.password),
        ss_password   = req.password,   # 连接 SOCKS5 时用的明文密码
        device_id     = device_id,
        last_key      = key_string,
        expire_time   = expire_time,
        status        = "active",
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    _sync_xui_upsert(user)

    return {
        "success": True,
        "username": req.username,
        "duration_days": key_obj.duration_days,
        "expire_time": expire_time.strftime("%Y-%m-%d %H:%M:%S") + " UTC",
        "proxy": _build_proxy_payload(req.username, req.password),
    }


@app.post("/api/recharge", tags=["用户端"])
def api_recharge(req: RechargeRequest, db: Session = Depends(get_db)):
    """卡密续期。叠加到期时间；过期账号从当前时间重新起算。"""
    user = _get_user_or_401(req.username, req.password, db)

    if user.status == "banned":
        raise HTTPException(status_code=403, detail="账号已被封禁，请联系客服")

    key_string = req.key_string.strip().upper()

    # ── 幂等回放：上次续期可能已入库但响应未回到前端 ──────────────────
    # 判据：该用户的 last_key 正好就是当前卡密，且卡密在库里显示已用。
    # 此时直接回放上次续期的结果（不做第二次叠加），避免用户重复被扣时长。
    if (user.last_key or "").upper() == key_string:
        key_obj = db.query(models.Key).filter(models.Key.key_string == key_string).first()
        if key_obj and key_obj.is_used:
            _sync_xui_upsert(user)
            return {
                "success": True,
                "username": user.username,
                "added_days": key_obj.duration_days,
                "expire_time": user.expire_time.strftime("%Y-%m-%d %H:%M:%S") + " UTC",
                "proxy": _build_proxy_payload(user.username, req.password),
                "replayed": True,
            }

    stmt = (
        update(models.Key)
        .where(models.Key.key_string == key_string)
        .where(models.Key.is_used == False)  # noqa: E712
        .values(is_used=True)
        .execution_options(synchronize_session="fetch")
    )
    result = db.execute(stmt)
    db.commit()

    if result.rowcount == 0:
        key_obj = db.query(models.Key).filter(models.Key.key_string == key_string).first()
        if not key_obj:
            raise HTTPException(status_code=404, detail="续期卡密不存在，请核对后重试！")
        raise HTTPException(status_code=409, detail="该续期卡密已被使用，请勿重复操作！")

    key_obj    = db.query(models.Key).filter(models.Key.key_string == key_string).first()
    now        = datetime.utcnow()
    base_time  = user.expire_time if user.expire_time > now else now
    new_expire = base_time + timedelta(days=key_obj.duration_days)

    user.expire_time = new_expire
    user.last_key    = key_string
    user.status      = "active"
    # 老数据迁移兜底：如果用户表里还没写明文密码，这次趁机补上
    if not user.ss_password:
        user.ss_password = req.password
    db.commit()
    db.refresh(user)

    _sync_xui_upsert(user)

    return {
        "success": True,
        "username": user.username,
        "added_days": key_obj.duration_days,
        "expire_time": new_expire.strftime("%Y-%m-%d %H:%M:%S") + " UTC",
        "proxy": _build_proxy_payload(user.username, req.password),
    }


@app.post("/api/query", tags=["用户端"])
def api_query(req: QueryRequest, db: Session = Depends(get_db)):
    """
    账号状态查询。
    - 只给 username：仅返回状态（不泄露 SOCKS5 配置）
    - 同时给 password 且校验通过：额外返回 SOCKS5 一键导入参数
    """
    user = db.query(models.User).filter(models.User.username == req.username).first()
    if not user:
        raise HTTPException(status_code=404, detail="查无此账号信息，请确认账号是否正确！")

    now = datetime.utcnow()
    if user.status == "active" and user.expire_time < now:
        user.status = "expired"
        db.commit()

    days_left = max(0, (user.expire_time - now).days) if user.expire_time > now else 0

    resp = {
        "username": user.username,
        "status": user.status,
        "expire_time": user.expire_time.strftime("%Y-%m-%d %H:%M:%S") + " UTC",
        "days_left": days_left,
    }

    if req.password and user.status == "active":
        if user.password_hash == _hash_password(req.password):
            resp["proxy"] = _build_proxy_payload(user.username, req.password)

    return resp


# ══════════════════════════════════════════════════════════════════════
# 配置文件 / 证书 下载接口
# ----------------------------------------------------------------------
# 前端底部三个按钮（下载配置 / 下载证书 / 导入节点）之二会落到这里。
# 设计：优先返回 static/ 目录下的文件；若用户部署时只放了项目根目录下的
# FD.conf / Shadowrocket20260422150506.crt，这里也能兜底找到，保证「能下」。
# ══════════════════════════════════════════════════════════════════════

def _find_first_existing(paths: list[str]) -> Optional[str]:
    for p in paths:
        if p and os.path.isfile(p):
            return p
    return None


@app.get("/download/config", tags=["用户端"])
def download_config():
    """下载 Shadowrocket 默认配置文件（.conf）。"""
    path = _find_first_existing([
        "static/config/FD.conf",
        "static/config/default.conf",
        "FD.conf",
    ])
    if not path:
        raise HTTPException(status_code=404, detail="配置文件未部署，请联系管理员")
    return FileResponse(
        path,
        media_type="application/octet-stream",
        filename="FengDu.conf",
    )


@app.get("/download/cert", tags=["用户端"])
def download_cert():
    """下载 Shadowrocket MITM 根证书（.crt）。iOS 需在「设置 → 通用 → VPN 与设备管理」信任该证书。"""
    path = _find_first_existing([
        "static/cert/Shadowrocket.crt",
        "Shadowrocket20260422150506.crt",
    ])
    if not path:
        raise HTTPException(status_code=404, detail="证书文件未部署，请联系管理员")
    return FileResponse(
        path,
        media_type="application/x-x509-ca-cert",
        filename="Shadowrocket.crt",
    )


# ══════════════════════════════════════════════════════════════════════
# SOCKS5 订阅分发接口（供 shadowrocket://add/sub/<url> 调用）
# ----------------------------------------------------------------------
# 客户端以 GET /sub?username=xxx&password=yyy 拉取，服务端校验通过后
# 直接 PlainTextResponse 返回一条 socks5:// URI，小火箭会自动识别并导入。
# ══════════════════════════════════════════════════════════════════════

@app.get("/sub", tags=["用户端"], response_class=PlainTextResponse)
def get_subscription(
    username: str = "",
    password: str = "",
    db: Session = Depends(get_db),
):
    # ── 参数基本校验 ───────────────────────────────────────────────
    if not username or not password:
        raise HTTPException(status_code=400, detail="缺少账号或密码参数，请重新获取订阅链接")

    # ── 账号密码校验 ───────────────────────────────────────────────
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user or user.password_hash != _hash_password(password):
        raise HTTPException(status_code=401, detail="账号或密码错误，请检查后重试！")

    # ── 封禁校验 ──────────────────────────────────────────────────
    if user.status == "banned":
        raise HTTPException(status_code=403, detail="该账号已被封禁，请联系客服处理！")

    # ── 卡密有效期校验 ────────────────────────────────────────────
    now = datetime.utcnow()
    if user.expire_time < now:
        if user.status != "expired":
            user.status = "expired"
            db.commit()
        raise HTTPException(status_code=403, detail="该账号的卡密已过期，请充值续期后再试！")

    # 状态修复：过期态 → 活跃
    if user.status != "active":
        user.status = "active"
        db.commit()

    # ── 返回纯明文 socks5:// URI ──────────────────────────────────
    socks_uri = _build_socks5_uri(user.username, password)
    safe_un = "".join(c if (c.isalnum() or c in "-_.") else "_" for c in user.username)
    return PlainTextResponse(
        content=socks_uri,
        headers={
            "Content-Disposition": f'attachment; filename="FengDu-{safe_un}.conf"',
            "Profile-Update-Interval": "24",
        },
    )


# ── 直接 python main.py 启动时的入口 ──────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
