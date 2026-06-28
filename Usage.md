# Usage

## Regtest stack

### Build and run the retained services

```bash
$ cd mercurylayer
$ docker compose -f docker-compose-token-servers.yml up --build
```

### Initialize the regtest wallet

```bash
$ bitcoin_cli="bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury"
$ docker exec mercurylayer-inquisition-1 $bitcoin_cli createwallet mercury_test || \
    docker exec mercurylayer-inquisition-1 $bitcoin_cli loadwallet mercury_test
$ address=$(docker exec mercurylayer-inquisition-1 $bitcoin_cli -rpcwallet=mercury_test getnewaddress)
$ docker exec mercurylayer-inquisition-1 $bitcoin_cli generatetoaddress 101 "$address"
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

### Run the lockbox compatibility suite

```bash
$ cd clients/tests/rust
$ RUSTUP_TOOLCHAIN=1.92.0 cargo test --test lockbox_compatibility -- --ignored --test-threads=1
```

## Compose down

`docker compose -f docker-compose-token-servers.yml down -v` for the regtest stack

`docker compose -f docker-compose-lockbox.yml down -v` for the local lockbox stack
