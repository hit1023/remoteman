from typing import Union

from fastapi import Request, WebSocket

Connection = Union[Request, WebSocket]


def get_client_ip(conn: Connection) -> str:
    forwarded = conn.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = conn.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    return conn.client.host if conn.client else "unknown"
