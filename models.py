"""
数据库模型定义

表 A: admins —— 后台管理员表（super / agent）
表 B: keys   —— 卡密表，记录生成者、使用者和使用时间
表 C: users  —— 用户账号表，记录来源管理员和一人一端口 socks_port
"""

from datetime import datetime
from database import Base
from sqlalchemy import Column, String, DateTime, Boolean, Integer


class Admin(Base):
    """后台管理员账号。"""
    __tablename__ = "admins"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(128), unique=True, index=True, nullable=False, comment="后台登录账号")
    password_hash = Column(String(64), nullable=False, comment="后台登录密码哈希")
    role = Column(String(16), default="agent", nullable=False, comment="super / agent")
    status = Column(String(16), default="pending", nullable=False, comment="pending / active / rejected / disabled")
    note = Column(String(255), nullable=True, comment="申请备注/联系方式")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, comment="申请/创建时间 UTC")
    approved_at = Column(DateTime, nullable=True, comment="审核通过时间 UTC")
    approved_by_admin_id = Column(Integer, nullable=True, comment="审核人管理员 ID")


class Key(Base):
    """卡密表：每张只能使用一次，并记录由谁生成、谁使用、何时使用。"""
    __tablename__ = "keys"

    id = Column(Integer, primary_key=True, index=True)
    key_string = Column(String(64), unique=True, index=True, nullable=False,
                        comment="卡密字符串（普通字符串，允许连字符等任意字符）")
    duration_days = Column(Integer, nullable=False, comment="有效天数")
    is_used = Column(Boolean, default=False, nullable=False, comment="是否已使用")
    created_at = Column(DateTime, default=datetime.utcnow, comment="生成时间 UTC")

    created_by_admin_id = Column(Integer, nullable=True, index=True, comment="生成该卡密的管理员 ID")
    used_by_username = Column(String(64), nullable=True, index=True, comment="使用该卡密的会员账号")
    used_at = Column(DateTime, nullable=True, comment="卡密使用时间 UTC")


class User(Base):
    """用户账号表。"""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, index=True, nullable=False,
                      comment="账号（任意字符，含手机号）")
    password_hash = Column(String(64), nullable=False,
                           comment="密码 SHA-256 哈希（原文任意字符）")
    ss_password = Column(String(128), nullable=True,
                         comment="SOCKS5 连接密码（= 用户注册时的明文密码）")
    device_id = Column(String(64), unique=True, index=True, nullable=False,
                       comment="用户唯一 Token（UUID，管理员定位用，不是代理密码）")
    last_key = Column(String(64), nullable=True, comment="最近一次使用的卡密")
    expire_time = Column(DateTime, nullable=False, comment="订阅到期时间 UTC")
    status = Column(String(16), default="active", nullable=False,
                    comment="active / expired / banned")
    created_at = Column(DateTime, default=datetime.utcnow, comment="注册时间 UTC")
    socks_port = Column(Integer, nullable=True, index=True, comment="一人一端口 SOCKS5 端口")
    source_admin_id = Column(Integer, nullable=True, index=True, comment="来源管理员 ID（使用的卡密归属）")
