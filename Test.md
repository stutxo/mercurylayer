# Running Rust tests

1. `$ docker compose -f docker-compose-token-servers.yml up --build` to run Mercury and token-server-v2. This also starts a Bitcoin Inquisition regtest node.

2. Run the commands below to start the Bitcoin network.

```bash
$ bitcoin_cli="bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury"
$ docker exec mercurylayer-inquisition-1 $bitcoin_cli createwallet mercury_test || \
    docker exec mercurylayer-inquisition-1 $bitcoin_cli loadwallet mercury_test
$ address=$(docker exec mercurylayer-inquisition-1 $bitcoin_cli -rpcwallet=mercury_test getnewaddress)
$ docker exec mercurylayer-inquisition-1 $bitcoin_cli generatetoaddress 101 "$address"
```

3. `cd clients/tests/rust/` 

4. `RUSTUP_TOOLCHAIN=1.92.0 cargo test --test functional -- --ignored --test-threads=1`

# Running lockbox compatibility tests

1. `$ docker compose -f docker-compose-lockbox.yml up --build` to run the lockbox-only stack.

2. `cd clients/tests/rust/`

3. `RUSTUP_TOOLCHAIN=1.92.0 cargo test --test lockbox_compatibility -- --ignored --test-threads=1`

# Other Environments

The `docker compose -f docker-compose-token-servers.yml` file can be used to build a Mercury Layer test infrastructure with Lockbox, token-server-v2, Mercury, and Bitcoin Inquisition services.
The default values ​​of this file however must be changed.
