"""
数据库模型定义

字段宽松策略（解决前端 "expected pattern" / 邮箱格式误拦截问题）：
  - username / account：允许任意字符（手机号、字母、数字、常规符号均可），
                        数据库字段长度给到 32 位留足冗余
  - password_hash    ：存 SHA-256 十六进制，固定 64 位（明文密码本身任意字符，无正则）
  - ss_password      ：存原始明文密码，用于构造 SOCKS5 `socks5://` 一键导入链接，
                        以及向 3x-ui 面板同步时作为客户端的 SOCKS5 连接密码
  - key_string       ：卡密含连字符（如 VIP-NTYW-PO67-CD3P），当作普通字符串存储，
                        不做任何正则约束，业务层仅用「查库是否存在且未使用」来判定有效性

表 A: keys  —— 卡密表
表 B: users —— 用户账号表（用户名 + 密码注册，卡密充值）
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime
from database import Base


class Key(Base):
    """
    卡密表：存储所有已生成的卡密，每张只能使用一次。
    卡密字符串允许带连字符（如 VIP-NTYW-PO67-CD3P），按普通字符串存储，
    后端无任何格式正则限制，仅通过 (key_string, is_used=False) 原子更新来激活。
    """
    __tablename__ = "keys"

    id            = Column(Integer, primary_key=True, index=True)
    key_string    = Column(String(64), unique=True, index=True, nullable=False,
                           comment="卡密字符串（普通字符串，允许连字符等任意字符）")
    duration_days = Column(Integer, nullable=False, comment="有效天数")
    is_used       = Column(Boolean, default=False, nullable=False, comment="是否已使用")
    created_at    = Column(DateTime, default=datetime.utcnow, comment="生成时间（UTC）")


class User(Base):
    """
    用户账号表。
    - username      : 任意字符账号（支持手机号 / 字母 / 数字 / 常规符号）
    - password_hash : 登录密码的 SHA-256，原始密码任意字符
    - ss_password   : 原始明文密码（用于生成 socks5:// URI 与同步到 3x-ui mixed 入站）
    - device_id     : 订阅 Token（UUID），保留用于日志/管理员定位，不再作为代理密码
    - expire_time   : 订阅到期时间，随卡密充值自动顺延
    - status        : active / expired / banned
    """
    __tablename__ = "users"

    id            = Column(Integer, primary_key=True, index=True)
    username      = Column(String(64), unique=True, index=True, nullable=False,
                           comment="账号（任意字符，含手机号）")
    password_hash = Column(String(64), nullable=False,
                           comment="密码 SHA-256 哈希（原文任意字符）")
    ss_password   = Column(String(128), nullable=True,
                           comment="SOCKS5 连接密码（= 用户注册时的明文密码）")
    device_id     = Column(String(64), unique=True, index=True, nullable=False,
                           comment="用户唯一 Token（UUID，管理员定位用，不是代理密码）")
    last_key      = Column(String(64), nullable=True, comment="最近一次使用的卡密")
    expire_time   = Column(DateTime, nullable=False, comment="订阅到期时间（UTC）")
    status        = Column(String(16), default="active", nullable=False,
                           comment="active / expired / banned")
    created_at    = Column(DateTime, default=datetime.utcnow, comment="注册时间（UTC）")
