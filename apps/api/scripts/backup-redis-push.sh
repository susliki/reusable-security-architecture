#!/bin/bash
# Pēc veiksmīga pg_dump izpildes, nosūtīt metadatus uz Redis
# Pievienot crontab: 0 2 * * * /opt/scripts/backup.sh && /opt/scripts/backup-redis-push.sh

BACKUP_FILE=$(ls -t /backups/pg_dump_*.sql.gz | head -1)
SIZE=$(stat -c%s "$BACKUP_FILE")
REDIS_CLI="docker exec redis redis-cli"

# TTL 172800s = 48h — ja backup nenotiek 48h, atslēga pazūd un portālā rādīs brīdinājumu
$REDIS_CLI SET backup:last "{\"timestamp\":\"$(date -u +%FT%TZ)\",\"sizeBytes\":$SIZE,\"durationSeconds\":0,\"dbName\":\"app\",\"location\":\"backup-host:/backups/\",\"status\":\"success\"}" EX 172800
