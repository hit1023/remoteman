import asyncio
import json
import logging
import secrets
import threading
import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session

from . import auth, models, ssh_connect
from .database import SessionLocal, get_db

logger = logging.getLogger("remoteman.console")

router = APIRouter()

# ワンタイムチケット方式(WebSocketはAuthorizationヘッダーを付けられないため、
# 通常のBearer認証で短命チケットを発行し、それをクエリパラメータで渡す)
TICKET_TTL_SECONDS = 30
_tickets: dict[str, dict] = {}


def _create_ticket(server_id: int, username: str) -> str:
    now = time.time()
    for key in [k for k, v in _tickets.items() if v["expires"] < now]:
        _tickets.pop(key, None)
    ticket = secrets.token_urlsafe(32)
    _tickets[ticket] = {"server_id": server_id, "username": username, "expires": now + TICKET_TTL_SECONDS}
    return ticket


def _consume_ticket(ticket: str, server_id: int) -> Optional[str]:
    data = _tickets.pop(ticket, None)
    if data is None:
        return None
    if data["expires"] < time.time() or data["server_id"] != server_id:
        return None
    return data["username"]


def _client_ip(websocket: WebSocket) -> str:
    forwarded = websocket.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = websocket.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    return websocket.client.host if websocket.client else "unknown"


def _record_access_log(
    username: str,
    server_id: Optional[int],
    server_name: str,
    client_ip: str,
    success: bool,
    detail: Optional[str] = None,
) -> None:
    db = SessionLocal()
    try:
        log = models.AccessLog(
            username=username,
            server_id=server_id,
            server_name=server_name,
            client_ip=client_ip,
            success=success,
            detail=detail,
        )
        db.add(log)
        db.commit()
    finally:
        db.close()


@router.post("/api/servers/{server_id}/console-ticket")
def create_console_ticket(
    server_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    server = db.query(models.Server).filter(models.Server.id == server_id).first()
    if server is None:
        raise HTTPException(status_code=404, detail="サーバーが見つかりません")
    if not server.enabled:
        raise HTTPException(status_code=400, detail="このサーバーは無効化されています")
    try:
        ssh_connect.validate_chain(server)
    except ssh_connect.ChainError as e:
        raise HTTPException(status_code=400, detail=str(e))
    ticket = _create_ticket(server_id, current_user.username)
    return {"ticket": ticket}


async def _send_error(websocket: WebSocket, message: str) -> None:
    await websocket.send_text(json.dumps({"type": "error", "message": message}))


@router.websocket("/ws/console/{server_id}")
async def console_websocket(websocket: WebSocket, server_id: int, ticket: str = Query(...)):
    await websocket.accept()
    client_ip = _client_ip(websocket)

    username = _consume_ticket(ticket, server_id)
    if username is None:
        await _send_error(websocket, "接続が無効です(チケットの期限切れの可能性があります)。もう一度開き直してください。")
        await websocket.close()
        return

    db = SessionLocal()
    try:
        server = db.query(models.Server).filter(models.Server.id == server_id).first()
        if server is None or server.credential is None:
            _record_access_log(
                username, server_id, server.name if server else f"#{server_id}", client_ip,
                False, "サーバーまたは認証情報が見つかりません",
            )
            await _send_error(websocket, "サーバーまたは認証情報が見つかりません")
            await websocket.close()
            return
        host, server_name = server.host, server.name
        try:
            clients = ssh_connect.open_chain(server)
        except ssh_connect.ChainError as e:
            _record_access_log(username, server_id, server_name, client_ip, False, str(e))
            await _send_error(websocket, str(e))
            await websocket.close()
            return
    finally:
        db.close()

    client = clients[-1]
    try:
        channel = client.get_transport().open_session()
        channel.get_pty(term="xterm-256color", width=80, height=24)
        channel.invoke_shell()
        channel.settimeout(0.0)
    except Exception as e:
        ssh_connect.close_chain(clients)
        _record_access_log(username, server_id, server_name, client_ip, False, f"SSH接続に失敗しました: {e}")
        await _send_error(websocket, f"SSH接続に失敗しました: {e}")
        await websocket.close()
        return

    _record_access_log(username, server_id, server_name, client_ip, True)
    logger.info("コンソール接続開始: %s (サーバー: %s, ユーザー: %s, 経由数: %d)", host, server_name, username, len(clients) - 1)

    loop = asyncio.get_event_loop()
    stop_event = threading.Event()

    def reader() -> None:
        while not stop_event.is_set():
            try:
                if channel.recv_ready():
                    data = channel.recv(4096)
                    if not data:
                        break
                    asyncio.run_coroutine_threadsafe(websocket.send_bytes(data), loop)
                elif channel.closed:
                    break
                else:
                    time.sleep(0.02)
            except Exception:
                break
        stop_event.set()

    reader_thread = threading.Thread(target=reader, daemon=True)
    reader_thread.start()

    try:
        while not stop_event.is_set():
            message = await websocket.receive()
            if message.get("type") == "websocket.disconnect":
                break
            text = message.get("text")
            data = message.get("bytes")
            if text is not None:
                control = None
                try:
                    parsed = json.loads(text)
                    if isinstance(parsed, dict) and parsed.get("remoteman_console_control") == "resize":
                        control = parsed
                except ValueError:
                    pass
                if control is not None:
                    try:
                        channel.resize_pty(width=int(control["cols"]), height=int(control["rows"]))
                    except Exception:
                        pass
                else:
                    # 通常のキー入力(制御メッセージ以外のテキストはそのままターミナルへ)
                    channel.send(text)
            elif data is not None:
                channel.send(data)
    except WebSocketDisconnect:
        pass
    except Exception:
        logger.exception("コンソールWebSocket処理中にエラーが発生しました")
    finally:
        stop_event.set()
        try:
            channel.close()
        except Exception:
            pass
        ssh_connect.close_chain(clients)
        logger.info("コンソール接続終了: %s (サーバー: %s)", host, server_name)
