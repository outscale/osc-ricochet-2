#!/bin/bash

pkill ricochet
set -e
cargo build
cargo run -- ./ricochet-oapi-cli.json > /dev/null &
sleep 5

git clone https://github.com/outscale/oapi-cli
cd oapi-cli

CFLAGS="-fsanitize=address -O0 -g" make
./local-tests.sh "./oapi-cli" ""