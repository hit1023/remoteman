from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


# ---------- auth ----------
class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


# ---------- users ----------
class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    created_at: datetime


class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=8, max_length=200)


class PasswordChange(BaseModel):
    password: str = Field(min_length=8, max_length=200)


# ---------- credentials ----------
class CredentialCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    auth_type: Literal["key", "password"] = "key"
    secret: str = Field(min_length=1)
    passphrase: Optional[str] = None


class CredentialUpdate(BaseModel):
    name: Optional[str] = None
    auth_type: Optional[Literal["key", "password"]] = None
    secret: Optional[str] = None  # 指定時のみ上書き
    passphrase: Optional[str] = None


class CredentialOut(BaseModel):
    id: int
    name: str
    auth_type: str
    created_at: datetime


# ---------- servers ----------
class ServerCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    host: str
    ssh_port: int = 22
    ssh_user: str
    credential_id: Optional[int] = None
    enabled: bool = True


class ServerUpdate(BaseModel):
    name: Optional[str] = None
    host: Optional[str] = None
    ssh_port: Optional[int] = None
    ssh_user: Optional[str] = None
    credential_id: Optional[int] = None
    enabled: Optional[bool] = None


class ServerOut(BaseModel):
    id: int
    name: str
    host: str
    ssh_port: int
    ssh_user: str
    credential_id: Optional[int] = None
    credential_name: Optional[str] = None
    enabled: bool
    created_at: datetime
