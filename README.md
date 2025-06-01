to run project use :
- `npm i` and `npm start` in frontend directory.
- `uv pip install -r pyproject.toml`, `uv run python src.main`
- run postgresql docker container 
```bash
docker run --hostname=a6a1dd1a8cab --mac-address=a6:be:85:01:cf:d2 --env=PG_MAJOR=17 --env=PG_VERSION=17.5-1.pgdg120+1 --env=POSTGRES_DB=suricata_alerts --env=LANG=en_US.utf8 --env=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/lib/postgresql/17/bin --env=GOSU_VERSION=1.17 --env=PGDATA=/var/lib/postgresql/data --env=POSTGRES_USER=postgres --env=POSTGRES_PASSWORD=postgres --volume=/var/lib/postgresql/data --network=bridge -p 5432:5432 --restart=no --runtime=runc -d postgres:latest
```
ln -s /var/run/suricata-command.socket /var/run/suricata/suricata-command.socket
