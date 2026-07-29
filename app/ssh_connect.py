import paramiko
from sqlalchemy.orm import Session

from . import crypto, models, ssh_key

MAX_CHAIN_DEPTH = 8


class ChainError(Exception):
    """踏み台(ProxyJump)チェーンの構築に失敗した場合の例外。"""


def build_chain(server: models.Server) -> list[models.Server]:
    """server自身とそのproxy_jump祖先を、接続順(踏み台→…→対象サーバー)に並べて返す。"""
    chain: list[models.Server] = []
    visited: set[int] = set()
    current: models.Server | None = server
    while current is not None:
        if current.id in visited:
            raise ChainError("踏み台(ProxyJump)の設定が循環しています")
        visited.add(current.id)
        chain.append(current)
        if len(chain) > MAX_CHAIN_DEPTH:
            raise ChainError(f"踏み台の多段接続が深すぎます(上限{MAX_CHAIN_DEPTH}段)")
        current = current.proxy_jump
    chain.reverse()
    return chain


def validate_chain(server: models.Server) -> None:
    """接続前にチェーン全体の設定(有効/認証情報)を検証する。接続はしない。"""
    chain = build_chain(server)
    for hop in chain:
        if not hop.enabled:
            raise ChainError(f"「{hop.name}」は無効化されています")
        if hop.credential is None:
            raise ChainError(f"「{hop.name}」に認証情報が設定されていません")


def _connect_hop(hop: models.Server, sock, timeout: int) -> paramiko.SSHClient:
    credential = hop.credential
    if credential is None:
        raise ChainError(f"「{hop.name}」に認証情報が設定されていません")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_kwargs = dict(
        hostname=hop.host,
        port=hop.ssh_port or 22,
        username=hop.ssh_user,
        timeout=timeout,
        banner_timeout=timeout,
        auth_timeout=timeout,
    )
    if sock is not None:
        connect_kwargs["sock"] = sock

    secret = crypto.decrypt(credential.secret_encrypted)
    if credential.auth_type == "key":
        if not secret:
            raise ChainError(f"「{hop.name}」の秘密鍵が登録されていません")
        passphrase = crypto.decrypt(credential.passphrase_encrypted)
        connect_kwargs["pkey"] = ssh_key.load_private_key(secret, passphrase)
    else:
        if not secret:
            raise ChainError(f"「{hop.name}」のSSHパスワードが登録されていません")
        connect_kwargs["password"] = secret

    try:
        client.connect(**connect_kwargs)
    except ChainError:
        raise
    except Exception as e:
        raise ChainError(f"「{hop.name}」へのSSH接続に失敗しました: {e}") from e
    return client


def open_chain(server: models.Server, timeout: int = 10) -> list[paramiko.SSHClient]:
    """serverと踏み台(ProxyJump)祖先すべてに順番に接続する。

    戻り値は接続順(踏み台が先頭、目的のサーバーが末尾)のSSHClientリスト。
    通信を維持するため、使い終わるまで全てのクライアントを保持し続けること
    (中間ホップを閉じるとトンネルが切れる)。呼び出し側は使用後、
    末尾から順(reversed)にclose()すること。
    """
    chain = build_chain(server)
    clients: list[paramiko.SSHClient] = []
    sock = None
    try:
        for i, hop in enumerate(chain):
            client = _connect_hop(hop, sock, timeout)
            clients.append(client)
            if i < len(chain) - 1:
                next_hop = chain[i + 1]
                transport = client.get_transport()
                sock = transport.open_channel(
                    "direct-tcpip",
                    (next_hop.host, next_hop.ssh_port or 22),
                    (hop.host, 0),
                )
    except Exception:
        for c in reversed(clients):
            try:
                c.close()
            except Exception:
                pass
        raise
    return clients


def close_chain(clients: list[paramiko.SSHClient]) -> None:
    for c in reversed(clients):
        try:
            c.close()
        except Exception:
            pass
