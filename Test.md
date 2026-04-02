# Running Rust tests

1. `$ docker compose -f docker-compose-token-servers.yml up --build` to run the Mercury and token servers. This also starts a Esplora node.

2. Run the commands below to start the Bitcoin network.

```bash
$ container_id=$(docker ps -qf "name=esplora-container")
$ wallet_name="esplora_wallet"
$ docker exec $container_id cli createwallet $wallet_name
$ address=$(docker exec $container_id cli getnewaddress $wallet_name)
$ docker exec $container_id cli generatetoaddress 101 "$address"
```

3. `cd clients/tests/rust/` 

4. `RUSTUP_TOOLCHAIN=1.92.0 cargo test --test functional -- --ignored --test-threads=1`

# Other Environments

The `docker compose -f docker-compose-token-servers.yml` file can be used to build a Mercury Layer infrastructure in test or production environments as it has all the necessary servers including Lockbox, Electrs/Esplora, Token, and Mercury.
The default values ​​of this file however must be changed.
