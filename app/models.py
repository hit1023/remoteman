import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from .database import Base


def utcnow():
    return datetime.datetime.utcnow()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    created_at = Column(DateTime, default=utcnow)


class Credential(Base):
    __tablename__ = "credentials"

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    auth_type = Column(String, nullable=False, default="key")  # "key" | "password"
    secret_encrypted = Column(Text, nullable=False)  # 秘密鍵本文 or パスワード(暗号化済み)
    passphrase_encrypted = Column(Text, nullable=True)  # 秘密鍵のパスフレーズ(暗号化済み、任意)
    created_at = Column(DateTime, default=utcnow)

    servers = relationship("Server", back_populates="credential")


class Server(Base):
    __tablename__ = "servers"

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    host = Column(String, nullable=False)
    ssh_port = Column(Integer, nullable=False, default=22)
    ssh_user = Column(String, nullable=False)
    credential_id = Column(Integer, ForeignKey("credentials.id"), nullable=True)
    proxy_jump_id = Column(Integer, ForeignKey("servers.id"), nullable=True)
    enabled = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, default=utcnow)

    credential = relationship("Credential", back_populates="servers")
    proxy_jump = relationship("Server", remote_side=[id])


class AccessLog(Base):
    __tablename__ = "access_logs"

    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime, default=utcnow, index=True)
    username = Column(String, nullable=False)
    server_id = Column(Integer, ForeignKey("servers.id"), nullable=True)
    server_name = Column(String, nullable=False)
    client_ip = Column(String, nullable=False)
    success = Column(Boolean, nullable=False, default=True)
    detail = Column(String, nullable=True)


class LoginLog(Base):
    __tablename__ = "login_logs"

    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime, default=utcnow, index=True)
    username = Column(String, nullable=False)
    client_ip = Column(String, nullable=False)
    success = Column(Boolean, nullable=False, default=True)
    detail = Column(String, nullable=True)
