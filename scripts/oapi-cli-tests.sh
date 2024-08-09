#!/bin/bash

shopt -s expand_aliases

cargo build
cargo run -- ./ricochet-oapi-cli.json > tmp  &
sleep 5

git clone https://github.com/outscale/oapi-cli
cd oapi-cli

CFLAGS="-fsanitize=address -O0 -g" make
set -eE
./local-tests.sh "./oapi-cli" ""

pkill ricochet-2