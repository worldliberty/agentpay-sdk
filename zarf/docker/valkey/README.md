# Local Valkey for development

`compose.yml` runs a single Valkey 8.1 node plus Redis Commander for local relay and cache
development. It is not a production deployment.

## Start / stop

```bash
docker compose -f zarf/docker/valkey/compose.yml up -d
docker compose -f zarf/docker/valkey/compose.yml down        # keep data
docker compose -f zarf/docker/valkey/compose.yml down -v     # drop the valkey_data volume
```

## Network exposure and credentials

- Both published ports are bound to loopback only: Valkey on `127.0.0.1:6379`, Redis Commander on
  `127.0.0.1:8081`. Nothing is reachable from other hosts on your network.
- Valkey requires a password (`requirepass` in `valkey.conf`). The development password is:

  ```text
  agentpay-dev-only
  ```

  Connection string for local clients:

  ```text
  redis://:agentpay-dev-only@127.0.0.1:6379/0
  ```

- The same value is wired into the compose healthcheck (`valkey-cli -a ...`) and into Redis
  Commander's `REDIS_HOSTS` (`label:host:port:db:password`). If you change it in `valkey.conf`,
  update both places in `compose.yml` as well.
- This password only protects a loopback-bound development instance. Do not reuse it anywhere
  else, and never point a production relay at this container.
