import io

import paramiko


def load_private_key(key_text: str, passphrase: str | None):
    key_classes = (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey, paramiko.DSSKey)
    last_error: Exception | None = None
    for key_cls in key_classes:
        try:
            return key_cls.from_private_key(io.StringIO(key_text), password=passphrase)
        except paramiko.SSHException as e:
            last_error = e
            continue
    raise ValueError(f"秘密鍵の形式を認識できませんでした: {last_error}")
