#!/bin/sh

FILENAME=backup_$(date +%Y-%m-%d)

mkdir $FILENAME

docker-compose -f $(pwd)/docker-compose.yaml down

docker run --rm -v signalbot_db:/data/db -v $(pwd)/$FILENAME:/backup alpine:latest tar czvf /backup/db.tar /data/db
docker run --rm -v signalbot_signald:/signald -v $(pwd)/$FILENAME:/backup alpine:latest tar czvf /backup/app.tar /signald

docker-compose -f $(pwd)/docker-compose.yaml up -d
