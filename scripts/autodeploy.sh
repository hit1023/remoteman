#!/usr/bin/env bash
# h-1 用の pull 型自動デプロイ（cron から実行）。origin/main に新しいコミットがあれば反映し、
# ヘルスチェックが通らなければ直前のコミットへ戻す。
# .env / data/ / docker-compose.override.yml は git 管理外なので影響しない。
set -euo pipefail
cd "$(dirname "$0")/.."
log() { echo "$(date '+%F %T') $*"; }
PORT=$(grep -E '^APP_PORT=' .env 2>/dev/null | cut -d= -f2 || true)
health() { for _ in $(seq 1 30); do curl -fsS -m 3 "http://localhost:${PORT:-8091}/" >/dev/null 2>&1 && return 0; sleep 2; done; return 1; }

git fetch -q origin main
OLD=$(git rev-parse HEAD); NEW=$(git rev-parse origin/main)
[ "$OLD" = "$NEW" ] && exit 0

log "deploy ${OLD:0:7} -> ${NEW:0:7}"
git reset -q --hard "$NEW"
docker compose up -d --build 2>&1 | tail -3
if health; then
  log "OK ${NEW:0:7}"; docker image prune -f >/dev/null 2>&1 || true
else
  log "NG health failed -> rollback to ${OLD:0:7}"
  git reset -q --hard "$OLD"; docker compose up -d --build 2>&1 | tail -3
  health && log "rolled back OK" || log "rollback also failed (要手動確認)"
  exit 1
fi
