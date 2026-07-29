import os
from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken


@lru_cache(maxsize=1)
def _fernet() -> Fernet:
    key = os.environ.get("APP_SECRET_KEY")
    if not key:
        raise RuntimeError(
            "APP_SECRET_KEYが設定されていません。.envを確認してください"
            "（生成コマンド: python3 -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\"）"
        )
    return Fernet(key.encode())


def encrypt(value: str | None) -> str | None:
    if value is None or value == "":
        return None
    return _fernet().encrypt(value.encode()).decode()


def decrypt(value: str | None) -> str | None:
    if value is None or value == "":
        return None
    try:
        return _fernet().decrypt(value.encode()).decode()
    except InvalidToken as e:
        raise RuntimeError("認証情報の復号に失敗しました(APP_SECRET_KEYが変更された可能性があります)") from e
