from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from . import auth, crypto, models, schemas
from .database import get_db
from .ssh_config_parser import parse_ssh_config

router = APIRouter()


@router.post("/api/import/ssh-config/parse", response_model=schemas.SshConfigParseResponse)
def parse_config(
    payload: schemas.SshConfigParseRequest,
    _current_user: models.User = Depends(auth.get_current_user),
):
    parsed = parse_ssh_config(payload.config_text)
    hosts = [
        schemas.ParsedHostOut(
            alias=h.alias,
            hostname=h.hostname or h.alias,
            port=h.port,
            user=h.user,
            identity_file=h.identity_file,
            proxy_jump_alias=h.proxy_jump_alias,
        )
        for h in parsed
    ]
    identity_files = sorted({h.identity_file for h in parsed if h.identity_file})
    return schemas.SshConfigParseResponse(hosts=hosts, identity_files=identity_files)


@router.post("/api/import/ssh-config/apply", response_model=schemas.SshConfigImportResult)
def apply_import(
    payload: schemas.SshConfigImportRequest,
    db: Session = Depends(get_db),
    _current_user: models.User = Depends(auth.get_current_user),
):
    # 1. 新規認証情報を作成し、identity_fileパス -> credential_id のマッピングを作る
    credential_by_identity_file: dict[str, int] = {}
    created_credentials = 0
    for cred_in in payload.credentials:
        credential = models.Credential(
            name=cred_in.name,
            auth_type=cred_in.auth_type,
            secret_encrypted=crypto.encrypt(cred_in.secret),
            passphrase_encrypted=crypto.encrypt(cred_in.passphrase),
        )
        db.add(credential)
        db.flush()
        credential_by_identity_file[cred_in.identity_file] = credential.id
        created_credentials += 1

    # 2. サーバーを作成(この時点ではproxy_jumpは未設定)
    alias_to_server_id: dict[str, int] = {}
    skipped: list[str] = []
    created_servers = 0
    pending_proxy_jump: list[tuple[int, str]] = []  # (server_id, proxy_jump_alias)

    existing_names = {s.name for s in db.query(models.Server.name).all()}

    for host_in in payload.hosts:
        if host_in.name in existing_names:
            skipped.append(f"{host_in.alias}(同名のサーバー「{host_in.name}」が既に存在します)")
            continue

        credential_id = host_in.credential_id
        if credential_id is None and host_in.identity_file:
            credential_id = credential_by_identity_file.get(host_in.identity_file)

        server = models.Server(
            name=host_in.name,
            host=host_in.host,
            ssh_port=host_in.ssh_port,
            ssh_user=host_in.ssh_user,
            credential_id=credential_id,
            enabled=True,
        )
        db.add(server)
        db.flush()
        alias_to_server_id[host_in.alias] = server.id
        existing_names.add(host_in.name)
        created_servers += 1
        if host_in.proxy_jump_alias:
            pending_proxy_jump.append((server.id, host_in.proxy_jump_alias))

    # 3. 踏み台の紐付け(今回インポートした中、または既存サーバーの中からエイリアス名で解決)
    for server_id, jump_alias in pending_proxy_jump:
        target_id = alias_to_server_id.get(jump_alias)
        if target_id is None:
            existing = db.query(models.Server).filter(models.Server.name == jump_alias).first()
            target_id = existing.id if existing else None
        if target_id is None or target_id == server_id:
            continue
        server = db.query(models.Server).filter(models.Server.id == server_id).first()
        server.proxy_jump_id = target_id

    db.commit()
    return schemas.SshConfigImportResult(
        created_servers=created_servers,
        created_credentials=created_credentials,
        skipped=skipped,
    )
