"""AIアシスト: 自然文→コマンド提案 / 端末出力の解説。LLMは設定画面から選択できる。

対応プロバイダー:
  - cloudflare: Cloudflare AI Gateway 経由の Workers AI(アカウントID + APIトークン + ゲートウェイID)【メイン】
  - anthropic : Claude(Anthropic API)。「AI Gateway経由」にするとゲートウェイを通す
  - openai    : OpenAI互換(OpenAI / xAI Grok / Gemini互換 / Ollama / LM Studio など、ベースURL指定)
APIキーは暗号化(Fernet)してDBへ保存し、画面・APIへ平文で返さない。
コマンドは提案のみで自動実行しない。
"""
import json
import os
import re
import urllib.error
import urllib.request
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from . import auth, crypto, models
from .database import get_db

router = APIRouter()

PROVIDERS = ("cloudflare", "anthropic", "openai")
CONFIG_KEY = "ai_config"
DEFAULT_MODELS = {
    "cloudflare": "@cf/meta/llama-3.3-70b-instruct-fp8-fast",
    "anthropic": "claude-haiku-5-5",
    "openai": "gpt-4o-mini",
}
DEFAULT_OPENAI_BASE = "https://api.openai.com/v1"


def _load(db: Session) -> dict:
    row = db.query(models.AppSetting).filter(models.AppSetting.key == CONFIG_KEY).first()
    try:
        data = json.loads(row.value) if row else {}
    except ValueError:
        data = {}
    data.setdefault("provider", "")
    data.setdefault("providers", {})
    return data


def _save(db: Session, data: dict) -> None:
    row = db.query(models.AppSetting).filter(models.AppSetting.key == CONFIG_KEY).first()
    payload = json.dumps(data, ensure_ascii=False)
    if row:
        row.value = payload
    else:
        db.add(models.AppSetting(key=CONFIG_KEY, value=payload))
    db.commit()


def _effective(db: Session) -> dict:
    """DB設定 + 環境変数(従来のCF_*)のフォールバックを合成した実効設定を返す。"""
    data = _load(db)
    prov = data["providers"]
    cf = dict(prov.get("cloudflare", {}))
    if not cf.get("account_id") and os.environ.get("CF_ACCOUNT_ID"):
        cf["account_id"] = os.environ["CF_ACCOUNT_ID"]
    if not cf.get("token_enc") and os.environ.get("CF_API_TOKEN"):
        cf["token_enc"] = crypto.encrypt(os.environ["CF_API_TOKEN"])
    if not cf.get("model") and os.environ.get("AI_MODEL"):
        cf["model"] = os.environ["AI_MODEL"]
    if not cf.get("gateway_id") and os.environ.get("CF_GATEWAY_ID"):
        cf["gateway_id"] = os.environ["CF_GATEWAY_ID"]
    prov["cloudflare"] = cf
    active = data.get("provider") or ("cloudflare" if cf.get("account_id") and cf.get("token_enc") else "")
    return {"provider": active, "providers": prov}


def _configured(cfg: dict, provider: str) -> bool:
    p = cfg["providers"].get(provider, {})
    if provider == "cloudflare":
        return bool(p.get("account_id") and p.get("token_enc"))
    if provider == "anthropic":
        return bool(p.get("key_enc"))
    if provider == "openai":
        # ローカルLLM(Ollama等)はキー不要。ベースURLが指定されていれば有効
        return bool(p.get("key_enc") or p.get("base_url"))
    return False


def _gateway_base(cfg: dict) -> str:
    cf = cfg["providers"].get("cloudflare", {})
    if not (cf.get("account_id") and cf.get("gateway_id")):
        raise HTTPException(status_code=400, detail="AI Gateway経由にはCloudflareのアカウントIDとゲートウェイIDの設定が必要です")
    return f"https://gateway.ai.cloudflare.com/v1/{cf['account_id']}/{cf['gateway_id']}"


def _post(url: str, headers: dict, body: dict, timeout: int = 40) -> dict:
    rq = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                headers={"Content-Type": "application/json", "User-Agent": "remoteman/1.0", **headers})
    try:
        with urllib.request.urlopen(rq, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:300]
        raise HTTPException(status_code=502, detail=f"LLMがエラーを返しました({e.code}): {detail}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"LLM呼び出しに失敗しました: {e}")


def call_llm(cfg: dict, system: str, user: str, max_tokens: int = 600):
    provider = cfg["provider"]
    if not provider or not _configured(cfg, provider):
        raise HTTPException(status_code=503, detail="AIアシストが設定されていません(設定タブで選択してください)")
    p = cfg["providers"][provider]
    model = p.get("model") or DEFAULT_MODELS[provider]
    if provider == "cloudflare":
        headers = {"Authorization": f"Bearer {crypto.decrypt(p['token_enc'])}"}
        # AI Gateway経由(ログ/キャッシュ/レート制限/分析)。認証ありゲートウェイでもCFのAPIトークンだけで通る
        url = f"https://api.cloudflare.com/client/v4/accounts/{p['account_id']}/ai/run/{model}"
        if p.get("gateway_id"):
            headers["cf-aig-gateway-id"] = p["gateway_id"]
        res = _post(
            url,
            headers,
            {"messages": [{"role": "system", "content": system}, {"role": "user", "content": user}], "max_tokens": max_tokens},
        )
        return (res.get("result") or {}).get("response", "")
    if provider == "anthropic":
        url = (_gateway_base(cfg) + "/anthropic/v1/messages") if p.get("via_gateway") else "https://api.anthropic.com/v1/messages"
        res = _post(
            url,
            {"x-api-key": crypto.decrypt(p["key_enc"]) or "", "anthropic-version": "2023-06-01"},
            {"model": model, "max_tokens": max_tokens, "system": system, "messages": [{"role": "user", "content": user}]},
        )
        return "".join(b.get("text", "") for b in res.get("content", []) if b.get("type") == "text")
    # openai 互換
    base = (_gateway_base(cfg) + "/openai") if p.get("via_gateway") else (p.get("base_url") or DEFAULT_OPENAI_BASE).rstrip("/")
    headers = {}
    key = crypto.decrypt(p.get("key_enc")) if p.get("key_enc") else None
    if key:
        headers["Authorization"] = f"Bearer {key}"
    res = _post(
        f"{base}/chat/completions", headers,
        {"model": model, "max_tokens": max_tokens,
         "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]},
    )
    return ((res.get("choices") or [{}])[0].get("message") or {}).get("content", "")


# ---------------------------------------------------------------- 設定API
class ProviderIn(BaseModel):
    model: Optional[str] = None
    account_id: Optional[str] = None   # cloudflare
    gateway_id: Optional[str] = None   # cloudflare AI Gateway ID
    via_gateway: Optional[bool] = None # anthropic/openai をAI Gateway経由にする
    base_url: Optional[str] = None     # openai互換
    api_key: Optional[str] = None      # 空文字/未指定なら既存値を維持。"__clear__"で削除


class ConfigIn(BaseModel):
    provider: str
    providers: dict[str, ProviderIn] = {}


@router.get("/api/ai/config")
def get_config(db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_user)):
    cfg = _effective(db)
    out = {"provider": cfg["provider"], "defaults": DEFAULT_MODELS, "providers": {}}
    for name in PROVIDERS:
        p = cfg["providers"].get(name, {})
        out["providers"][name] = {
            "model": p.get("model", ""),
            "account_id": p.get("account_id", ""),
            "gateway_id": p.get("gateway_id", ""),
            "via_gateway": bool(p.get("via_gateway")),
            "base_url": p.get("base_url", ""),
            "has_key": bool(p.get("token_enc") or p.get("key_enc")),
            "configured": _configured(cfg, name),
        }
    return out


@router.put("/api/ai/config")
def put_config(body: ConfigIn, db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_user)):
    if body.provider and body.provider not in PROVIDERS:
        raise HTTPException(status_code=400, detail="provider が不正です")
    data = _load(db)
    data["provider"] = body.provider
    for name, pin in body.providers.items():
        if name not in PROVIDERS:
            continue
        cur = data["providers"].setdefault(name, {})
        if pin.model is not None:
            cur["model"] = pin.model.strip()
        if name == "cloudflare" and pin.account_id is not None:
            cur["account_id"] = pin.account_id.strip()
        if name == "cloudflare" and pin.gateway_id is not None:
            cur["gateway_id"] = pin.gateway_id.strip()
        if name in ("anthropic", "openai") and pin.via_gateway is not None:
            cur["via_gateway"] = pin.via_gateway
        if name == "openai" and pin.base_url is not None:
            url = pin.base_url.strip()
            if url and not re.match(r"^https?://", url):
                raise HTTPException(status_code=400, detail="ベースURLは http(s):// で始めてください")
            cur["base_url"] = url
        if pin.api_key:
            field = "token_enc" if name == "cloudflare" else "key_enc"
            if pin.api_key == "__clear__":
                cur.pop(field, None)
            else:
                cur[field] = crypto.encrypt(pin.api_key.strip())
    _save(db, data)
    return {"ok": True}


@router.get("/api/ai/status")
def ai_status(db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_user)):
    cfg = _effective(db)
    return {"enabled": bool(cfg["provider"] and _configured(cfg, cfg["provider"])), "provider": cfg["provider"]}


@router.post("/api/ai/test")
def ai_test(db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_user)):
    out = call_llm(_effective(db), "あなたは接続テスト用のアシスタントです。", "「接続OK」とだけ日本語で返してください。", 40)
    return {"reply": str(out).strip()[:200]}


# ---------------------------------------------------------------- アシスト本体
class AiRequest(BaseModel):
    mode: str  # "command" | "explain"
    text: str
    server_name: str = ""


@router.post("/api/ai/assist")
def ai_assist(req: AiRequest, db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_user)):
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

    out = call_llm(_effective(db), system, user)
    if req.mode == "explain":
        return {"explain": out.strip() if isinstance(out, str) else json.dumps(out, ensure_ascii=False)}
    if isinstance(out, dict):  # JSONを返すモデルは既にパース済みのdictで返すことがある
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
    danger = bool(data.get("danger")) or bool(re.search(
        r"\brm\s+-[a-zA-Z]*r|\bmkfs|\bdd\s+if=|:\(\)\s*\{|\b(shutdown|reboot|halt|poweroff)\b|>\s*/dev/sd|chmod\s+-R\s+777|\bdrop\s+(table|database)",
        cmd, re.I))
    return {"command": cmd, "explain": str(data.get("explain", "")), "danger": danger}
