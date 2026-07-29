import logging
import os
import socket
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from . import auth, console, crypto, models, schemas
from .database import Base, SessionLocal, engine, get_db

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("remoteman")

Base.metadata.create_all(bind=engine)


def _ensure_initial_admin() -> None:
    db = SessionLocal()
    try:
        if db.query(models.User).count() > 0:
            return
        username = os.getenv("ADMIN_USERNAME", "admin")
        password = os.getenv("ADMIN_PASSWORD")
        if not password:
            logger.warning(
                "ADMIN_PASSWORDが未設定のため初期管理者を作成できません。.envを設定してコンテナを再作成してください。"
            )
            return
        user = models.User(username=username, password_hash=auth.hash_password(password))
        db.add(user)
        db.commit()
        logger.info("初期管理者ユーザー '%s' を作成しました", username)
    finally:
        db.close()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    _ensure_initial_admin()
    yield


app = FastAPI(title="remoteman", lifespan=lifespan)
app.include_router(console.router)


# ============================================================
# auth
# ============================================================
@app.post("/api/auth/login", response_model=schemas.TokenResponse)
def login(payload: schemas.LoginRequest, db: Session = Depends(get_db)):
    if auth.is_locked_out(payload.username):
        raise HTTPException(
            status_code=429,
            detail=f"ログイン試行回数が上限を超えました。{auth.LOCKOUT_MINUTES}分待ってから再試行してください。",
        )
    user = db.query(models.User).filter(models.User.username == payload.username).first()
    if user is None or not auth.verify_password(payload.password, user.password_hash):
        auth.record_failed_attempt(payload.username)
        raise HTTPException(status_code=401, detail="ユーザー名またはパスワードが違います")
    auth.clear_failed_attempts(payload.username)
    token = auth.create_access_token(user.username)
    return schemas.TokenResponse(access_token=token)


@app.get("/api/auth/me", response_model=schemas.UserOut)
def me(current_user: models.User = Depends(auth.get_current_user)):
    return current_user


# ============================================================
# users
# ============================================================
@app.get("/api/users", response_model=list[schemas.UserOut])
def list_users(
    db: Session = Depends(get_db),
    _current_user: models.User = Depends(auth.get_current_user),
):
    return db.query(models.User).order_by(models.User.id).all()


@app.post("/api/users", response_model=schemas.UserOut, status_code=201)
def create_user(
    payload: schemas.UserCreate,
    db: Session = Depends(get_db),
    _current_user: models.User = Depends(auth.get_current_user),
):
    if db.query(models.User).filter(models.User.username == payload.username).first():
        raise HTTPException(status_code=400, detail="そのユーザー名は既に使用されています")
    user = models.User(username=payload.username, password_hash=auth.hash_password(payload.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.put("/api/users/{user_id}/password", response_model=schemas.UserOut)
def change_password(
    user_id: int,
    payload: schemas.PasswordChange,
    db: Session = Depends(get_db),
    _current_user: models.User = Depends(auth.get_current_user),
):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="ユーザーが見つかりません")
    user.password_hash = auth.hash_password(payload.password)
    db.commit()
    db.refresh(user)
    return user


@app.delete("/api/users/{user_id}", status_code=204)
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    if db.query(models.User).count() <= 1:
        raise HTTPException(status_code=400, detail="最後の1人のユーザーは削除できません")
    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="自分自身は削除できません")
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="ユーザーが見つかりません")
    db.delete(user)
    db.commit()


# ============================================================
# credentials
# ============================================================
def _credential_out(credential: models.Credential) -> schemas.CredentialOut:
    return schemas.CredentialOut(
        id=credential.id,
        name=credential.name,
        auth_type=credential.auth_type,
        created_at=credential.created_at,
    )


@app.get("/api/credentials", response_model=list[schemas.CredentialOut])
def list_credentials(
    db: Session = Depends(get_db),
    _current_user: models.User = Depends(auth.get_current_user),
):
    credentials = db.query(models.Credential).order_by(models.Credential.id).all()
    return [_credential_out(c) for c in credentials]


@app.post("/api/credentials", response_model=schemas.CredentialOut, status_code=201)
def create_credential(
    payload: schemas.CredentialCreate,
    db: Session = Depends(get_db),
    _current_user: models.User = Depends(auth.get_current_user),
):
    credential = models.Credential(
        name=payload.name,
        auth_type=payload.auth_type,
        secret_encrypted=crypto.encrypt(payload.secret),
        passphrase_encrypted=crypto.encrypt(payload.passphrase),
    )
    db.add(credential)
    db.commit()
    db.refresh(credential)
    return _credential_out(credential)


@app.put("/api/credentials/{credential_id}", response_model=schemas.CredentialOut)
def update_credential(
    credential_id: int,
    payload: schemas.CredentialUpdate,
    db: Session = Depends(get_db),
    _current_user: models.User = Depends(auth.get_current_user),
):
    credential = db.query(models.Credential).filter(models.Credential.id == credential_id).first()
    if credential is None:
        raise HTTPException(status_code=404, detail="認証情報が見つかりません")

    data = payload.model_dump(exclude_unset=True)
    if "secret" in data:
        secret = data.pop("secret")
        if secret:
            credential.secret_encrypted = crypto.encrypt(secret)
    if "passphrase" in data:
        passphrase = data.pop("passphrase")
        if passphrase:
            credential.passphrase_encrypted = crypto.encrypt(passphrase)
    for key, value in data.items():
        setattr(credential, key, value)

    db.commit()
    db.refresh(credential)
    return _credential_out(credential)


@app.delete("/api/credentials/{credential_id}", status_code=204)
def delete_credential(
    credential_id: int,
    db: Session = Depends(get_db),
    _current_user: models.User = Depends(auth.get_current_user),
):
    credential = db.query(models.Credential).filter(models.Credential.id == credential_id).first()
    if credential is None:
        raise HTTPException(status_code=404, detail="認証情報が見つかりません")
    using_servers = db.query(models.Server).filter(models.Server.credential_id == credential_id).all()
    if using_servers:
        names = "、".join(s.name for s in using_servers)
        raise HTTPException(
            status_code=400,
            detail=f"この認証情報は次のサーバーで使用されているため削除できません: {names}",
        )
    db.delete(credential)
    db.commit()


# ============================================================
# servers
# ============================================================
def _server_out(server: models.Server) -> schemas.ServerOut:
    return schemas.ServerOut(
        id=server.id,
        name=server.name,
        host=server.host,
        ssh_port=server.ssh_port,
        ssh_user=server.ssh_user,
        credential_id=server.credential_id,
        credential_name=server.credential.name if server.credential else None,
        enabled=server.enabled,
        created_at=server.created_at,
    )


@app.get("/api/servers", response_model=list[schemas.ServerOut])
def list_servers(
    db: Session = Depends(get_db),
    _current_user: models.User = Depends(auth.get_current_user),
):
    servers = db.query(models.Server).order_by(models.Server.name).all()
    return [_server_out(s) for s in servers]


def _check_credential_exists(db: Session, credential_id: Optional[int]) -> None:
    if credential_id is None:
        return
    if db.query(models.Credential).filter(models.Credential.id == credential_id).first() is None:
        raise HTTPException(status_code=404, detail="指定した認証情報が見つかりません")


@app.post("/api/servers", response_model=schemas.ServerOut, status_code=201)
def create_server(
    payload: schemas.ServerCreate,
    db: Session = Depends(get_db),
    _current_user: models.User = Depends(auth.get_current_user),
):
    _check_credential_exists(db, payload.credential_id)
    server = models.Server(
        name=payload.name,
        host=payload.host,
        ssh_port=payload.ssh_port,
        ssh_user=payload.ssh_user,
        credential_id=payload.credential_id,
        enabled=payload.enabled,
    )
    db.add(server)
    db.commit()
    db.refresh(server)
    return _server_out(server)


@app.put("/api/servers/{server_id}", response_model=schemas.ServerOut)
def update_server(
    server_id: int,
    payload: schemas.ServerUpdate,
    db: Session = Depends(get_db),
    _current_user: models.User = Depends(auth.get_current_user),
):
    server = db.query(models.Server).filter(models.Server.id == server_id).first()
    if server is None:
        raise HTTPException(status_code=404, detail="サーバーが見つかりません")

    data = payload.model_dump(exclude_unset=True)
    if "credential_id" in data:
        _check_credential_exists(db, data["credential_id"])
    for key, value in data.items():
        setattr(server, key, value)

    db.commit()
    db.refresh(server)
    return _server_out(server)


@app.delete("/api/servers/{server_id}", status_code=204)
def delete_server(
    server_id: int,
    db: Session = Depends(get_db),
    _current_user: models.User = Depends(auth.get_current_user),
):
    server = db.query(models.Server).filter(models.Server.id == server_id).first()
    if server is None:
        raise HTTPException(status_code=404, detail="サーバーが見つかりません")
    db.delete(server)
    db.commit()


@app.get("/api/servers/{server_id}/status")
def check_status(
    server_id: int,
    db: Session = Depends(get_db),
    _current_user: models.User = Depends(auth.get_current_user),
):
    server = db.query(models.Server).filter(models.Server.id == server_id).first()
    if server is None:
        raise HTTPException(status_code=404, detail="サーバーが見つかりません")
    return {"online": _tcp_ping(server.host, server.ssh_port or 22)}


def _tcp_ping(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


# ============================================================
# static webui (SPA) — 必ずAPIルートの後に登録すること
# ============================================================
app.mount("/", StaticFiles(directory="/webui", html=True), name="webui")
