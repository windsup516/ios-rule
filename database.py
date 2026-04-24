"""
数据库连接配置模块
使用 SQLAlchemy 连接 SQLite，极简配置，方便迁移和备份（只需复制 .db 文件）
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# SQLite 数据库文件路径，生产环境可改为绝对路径
SQLALCHEMY_DATABASE_URL = "sqlite:///./cardkey.db"

# check_same_thread=False 允许多线程访问（FastAPI 多线程场景必须设置）
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    # 开启 WAL 模式提升 SQLite 并发读写性能
    echo=False,
)

# 会话工厂：autocommit=False 保证事务手动提交，autoflush=False 避免提前刷写
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# 所有模型的基类
Base = declarative_base()


def get_db():
    """
    FastAPI 依赖注入函数，为每个请求提供独立的数据库会话，
    请求结束后自动关闭，防止连接泄漏。
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
