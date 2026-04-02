# Usage

## Regtest stack

### Build and run the retained services

```bash
$ cd mercurylayer
$ docker compose -f docker-compose-token-servers.yml up --build
```

### Initialize the regtest wallet

```bash
$ container_id=$(docker ps -qf "name=esplora-container")
$ wallet_name="esplora_wallet"
$ docker exec $container_id cli createwallet $wallet_name
$ address=$(docker exec $container_id cli getnewaddress $wallet_name)
$ docker exec $container_id cli generatetoaddress 101 "$address"
```

### Run the Rust integration suite

```bash
$ cd clients/tests/rust
$ RUSTUP_TOOLCHAIN=1.92.0 cargo test --test functional -- --ignored --test-threads=1
```

## Lockbox-only local stack

```bash
$ cd mercurylayer
$ docker compose -f docker-compose-lockbox.yml up --build
```

## Compose down

`docker compose -f docker-compose-token-servers.yml down -v` for the regtest stack

`docker compose -f docker-compose-lockbox.yml down -v` for the local lockbox stack
