import re
from dataclasses import dataclass, field
from typing import Optional

# ProxyCommandからジャンプ先エイリアスを取り出す代表的なパターン:
#   ProxyCommand ssh -CW %h:%p nuro-jump
#   ProxyCommand ssh -W %h:%p bastion
# "-W" は "-CW" のように他の単文字オプションと連結されることがあるため、
# フラグの厳密一致は行わず "%h:%p の次のトークン" をジャンプ先とみなす。
_PROXY_COMMAND_JUMP_RE = re.compile(r"%h:%p\s+(\S+)", re.IGNORECASE)

# Hostエイリアスにglob文字(* ?)が含まれる場合は、具体的な1台のホストを指す
# エントリではない(ワイルドカードの共通設定用)ため、取り込み対象から除外する。
_GLOB_CHARS = set("*?")


@dataclass
class ParsedHost:
    alias: str
    hostname: Optional[str] = None
    port: int = 22
    user: Optional[str] = None
    identity_file: Optional[str] = None
    proxy_jump_alias: Optional[str] = None


def _is_concrete_alias(alias: str) -> bool:
    return alias != "" and not any(c in _GLOB_CHARS for c in alias)


def parse_ssh_config(text: str) -> list[ParsedHost]:
    """~/.ssh/config のテキストをパースし、具体的なHostエントリのリストを返す。
    `Host *` のようなワイルドカードブロックや、複数エイリアスを持つ
    `Host a b c` のような行は(実運用でよくある1エイリアス1ブロックの形以外は)
    単純化のためスキップまたは先頭エイリアスのみ採用する。
    """
    hosts: list[ParsedHost] = []
    current: Optional[ParsedHost] = None

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        # "Key value" または "Key=value" の両方に対応
        m = re.match(r"^(\S+)\s*=?\s+(.+)$", line) or re.match(r"^(\S+)$", line)
        if not m:
            continue
        key = m.group(1).lower()
        value = m.group(2).strip() if m.lastindex and m.lastindex >= 2 else ""
        value = value.strip('"')

        if key == "host":
            aliases = value.split()
            alias = aliases[0] if aliases else ""
            if _is_concrete_alias(alias):
                current = ParsedHost(alias=alias)
                hosts.append(current)
            else:
                current = None  # ワイルドカード/複数指定ブロックは取り込み対象外
            continue

        if current is None:
            continue

        if key == "hostname":
            current.hostname = value
        elif key == "port":
            try:
                current.port = int(value)
            except ValueError:
                pass
        elif key == "user":
            current.user = value
        elif key == "identityfile":
            # 複数行あっても最初の1つのみ採用(remotemanの認証情報は1サーバー1つのため)
            if current.identity_file is None:
                current.identity_file = value
        elif key == "proxyjump":
            # `ProxyJump alias` はカンマ区切りで複数ホップを書けるが、
            # remotemanはHostごとに1段のみサポートするため先頭のみ採用する。
            current.proxy_jump_alias = value.split(",")[0].strip()
        elif key == "proxycommand":
            jump_match = _PROXY_COMMAND_JUMP_RE.search(value)
            if jump_match:
                current.proxy_jump_alias = jump_match.group(1)

    # hostnameが無い場合はエイリアス自体を接続先ホスト名として扱う(configの慣習に合わせる)
    for h in hosts:
        if not h.hostname:
            h.hostname = h.alias

    return hosts
