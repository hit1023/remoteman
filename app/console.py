import asyncio
import json
import logging
import os
import re
import secrets
import threading
import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from sqlalchemy.orm import Session

from . import auth, models, ssh_connect
from .database import SessionLocal, get_db
from .netutil import get_client_ip

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


# ---------------------------------------------------------------------------
# 再開可能セッション: WebSocketが切れてもSSHチャネルを一定時間保持し、
# 画面スリープ/回線切替(スマホ)後に同じシェルへ再接続できる(出力はリングバッファで再生)。
# ---------------------------------------------------------------------------
KEEPALIVE_SECONDS = int(os.environ.get("SESSION_KEEPALIVE_SECONDS", "900"))
BUFFER_LIMIT = 256 * 1024


class ShellSession:
    def __init__(self, sid: str, username: str, server_id: int, server_name: str, host: str, clients, channel, loop):
        self.sid = sid
        self.username = username
        self.server_id = server_id
        self.server_name = server_name
        self.host = host
        self.clients = clients
        self.channel = channel
        self.loop = loop
        self.lock = threading.Lock()
        self.buffer = bytearray()
        self.ws: Optional[WebSocket] = None
        self.detached_at: Optional[float] = time.time()
        self.closed = False
        threading.Thread(target=self._reader, daemon=True).start()

    def _push(self, data: bytes) -> None:
        with self.lock:
            self.buffer += data
            if len(self.buffer) > BUFFER_LIMIT:
                del self.buffer[: len(self.buffer) - BUFFER_LIMIT]
            ws = self.ws
            if ws is not None:
                asyncio.run_coroutine_threadsafe(self._safe_send(ws, data), self.loop)

    @staticmethod
    async def _safe_send(ws: WebSocket, data: bytes) -> None:
        try:
            await ws.send_bytes(data)
        except Exception:
            pass

    def _reader(self) -> None:
        ch = self.channel
        while not self.closed:
            try:
                if ch.recv_ready():
                    data = ch.recv(4096)
                    if not data:
                        break
                    self._push(data)
                elif ch.closed or ch.exit_status_ready():
                    break
                else:
                    time.sleep(0.02)
            except Exception:
                break
        self.close(notify=True)

    def attach(self, ws: WebSocket) -> bytes:
        with self.lock:
            old = self.ws
            self.ws = ws
            self.detached_at = None
            snapshot = bytes(self.buffer)
        if old is not None:
            asyncio.run_coroutine_threadsafe(_close_quietly(old), self.loop)
        return snapshot

    def detach(self, ws: WebSocket) -> None:
        with self.lock:
            if self.ws is ws:
                self.ws = None
                self.detached_at = time.time()

    def close(self, notify: bool = False) -> None:
        if self.closed:
            return
        self.closed = True
        with self.lock:
            ws = self.ws
        if notify and ws is not None:
            asyncio.run_coroutine_threadsafe(_end_quietly(ws), self.loop)
        try:
            self.channel.close()
        except Exception:
            pass
        ssh_connect.close_chain(self.clients)
        _sessions.pop(self.sid, None)
        logger.info("コンソール接続終了: %s (サーバー: %s)", self.host, self.server_name)


async def _end_quietly(ws: WebSocket) -> None:
    try:
        await ws.send_text(json.dumps({"type": "ended"}))
        await ws.close()
    except Exception:
        pass


async def _close_quietly(ws: WebSocket) -> None:
    try:
        await ws.close()
    except Exception:
        pass


_sessions: dict[str, ShellSession] = {}
_reaper_started = False


def _reaper() -> None:
    while True:
        time.sleep(30)
        now = time.time()
        for s in list(_sessions.values()):
            if s.closed or (s.detached_at is not None and now - s.detached_at > KEEPALIVE_SECONDS):
                s.close()


def _ensure_reaper() -> None:
    global _reaper_started
    if not _reaper_started:
        _reaper_started = True
        threading.Thread(target=_reaper, daemon=True).start()


@router.websocket("/ws/console/{server_id}")
async def console_websocket(websocket: WebSocket, server_id: int, ticket: str = Query(...), session: Optional[str] = Query(None)):
    await websocket.accept()
    client_ip = get_client_ip(websocket)
    _ensure_reaper()

    username = _consume_ticket(ticket, server_id)
    if username is None:
        await _send_error(websocket, "接続が無効です(チケットの期限切れの可能性があります)。もう一度開き直してください。")
        await websocket.close()
        return

    sess: Optional[ShellSession] = None
    resumed = False
    if session:
        cand = _sessions.get(session)
        if cand is not None and not cand.closed and cand.username == username and cand.server_id == server_id:
            sess, resumed = cand, True

    if sess is None:
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

        try:
            channel = clients[-1].get_transport().open_session()
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
        sess = ShellSession(secrets.token_urlsafe(16), username, server_id, server_name, host, clients, channel, asyncio.get_event_loop())
        _sessions[sess.sid] = sess
    else:
        _record_access_log(username, server_id, sess.server_name, client_ip, True, "セッション再開")

    snapshot = sess.attach(websocket)
    await websocket.send_text(json.dumps({"type": "session", "id": sess.sid, "resumed": resumed}))
    if resumed and snapshot:
        await websocket.send_bytes(snapshot)

    channel = sess.channel
    try:
        while not sess.closed:
            message = await websocket.receive()
            if message.get("type") == "websocket.disconnect":
                break
            text = message.get("text")
            data = message.get("bytes")
            if text is not None:
                control = None
                try:
                    parsed = json.loads(text)
                    if isinstance(parsed, dict) and parsed.get("remoteman_console_control"):
                        control = parsed
                except ValueError:
                    pass
                if control is not None:
                    kind = control.get("remoteman_console_control")
                    if kind == "resize":
                        try:
                            channel.resize_pty(width=int(control["cols"]), height=int(control["rows"]))
                        except Exception:
                            pass
                    elif kind == "close":  # ユーザーがタブを明示的に閉じた: セッションも終了
                        sess.close()
                        break
                else:
                    channel.send(text)
            elif data is not None:
                channel.send(data)
    except WebSocketDisconnect:
        pass
    except Exception:
        logger.exception("コンソールWebSocket処理中にエラーが発生しました")
    finally:
        sess.detach(websocket)  # 切れても KEEPALIVE_SECONDS の間はシェルを保持


# ---------------------------------------------------------------------------
# AI アシスト(任意): 自然文→コマンド候補 / 端末出力の解説。Cloudflare Workers AI を使う。
# CF_ACCOUNT_ID / CF_API_TOKEN が未設定なら無効。コマンドは提案のみで自動実行しない。
# ---------------------------------------------------------------------------
CF_ACCOUNT_ID = os.environ.get("CF_ACCOUNT_ID", "")
CF_API_TOKEN = os.environ.get("CF_API_TOKEN", "")
AI_MODEL = os.environ.get("AI_MODEL", "@cf/meta/llama-3.3-70b-instruct-fp8-fast")


class AiRequest(BaseModel):
    mode: str  # "command" | "explain"
    text: str
    server_name: str = ""


@router.get("/api/ai/status")
def ai_status(current_user: models.User = Depends(auth.get_current_user)):
    return {"enabled": bool(CF_ACCOUNT_ID and CF_API_TOKEN)}


@router.post("/api/ai/assist")
def ai_assist(req: AiRequest, current_user: models.User = Depends(auth.get_current_user)):
    if not (CF_ACCOUNT_ID and CF_API_TOKEN):
        raise HTTPException(status_code=503, detail="AIアシストが設定されていません")
    text = req.text.strip()[:6000]
    if not text:
        raise HTTPException(status_code=400, detail="入力が空です")
    if req.mode == "command":
        system = (
            "あなたはLinuxシェルの熟練者。ユーザーの依頼を実行する bash の1行コマンドを提案する。"
            "必ずJSONのみを返す: {\"command\": \"...\", \"explain\": \"日本語で1文の説明\", \"danger\": true|false}。"
            "データ削除・上書き・再起動・権限変更・ネットワーク遮断など破壊的/不可逆なら danger を true にする。"
            "コードブロックや前置きは書かない。"
        )
        user = f"サーバー: {req.server_name or '不明'}\n依頼: {text}"
    elif req.mode == "explain":
        system = (
            "あなたはLinux/インフラの熟練者。ターミナルの直近出力を読み、日本語で簡潔に(最大8行)、"
            "何が起きているか・エラーなら原因と次に打つべきコマンドを説明する。"
        )
        user = f"サーバー: {req.server_name or '不明'}\n--- 端末出力 ---\n{text}"
    else:
        raise HTTPException(status_code=400, detail="mode が不正です")

    import urllib.request

    try:
        body = json.dumps({"messages": [{"role": "system", "content": system}, {"role": "user", "content": user}], "max_tokens": 600}).encode()
        rq = urllib.request.Request(
            f"https://api.cloudflare.com/client/v4/accounts/{CF_ACCOUNT_ID}/ai/run/{AI_MODEL}",
            data=body, method="POST",
            headers={"Authorization": f"Bearer {CF_API_TOKEN}", "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(rq, timeout=30) as resp:
            out = (json.loads(resp.read()).get("result") or {}).get("response", "")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"AI呼び出しに失敗しました: {e}")

    if req.mode == "explain":
        return {"explain": out.strip() if isinstance(out, str) else json.dumps(out, ensure_ascii=False)}
    if isinstance(out, dict):  # JSON を返すモデルは既にパース済みの dict を返すことがある
        data = out
    else:
        m = re.search(r"\{.*\}", str(out), re.S)
        try:
            data = json.loads(m.group(0)) if m else {}
        except ValueError:
            data = {}
    cmd = str(data.get("command", "")).strip().replace("\n", " ")
    if not cmd:
        raise HTTPException(status_code=502, detail="コマンドを生成できませんでした")
    danger = bool(data.get("danger")) or bool(re.search(r"\brm\s+-[a-zA-Z]*r|\bmkfs|\bdd\s+if=|:\(\)\s*\{|\b(shutdown|reboot|halt|poweroff)\b|>\s*/dev/sd|chmod\s+-R\s+777|\bdrop\s+(table|database)", cmd, re.I))
    return {"command": cmd, "explain": str(data.get("explain", "")), "danger": danger}
