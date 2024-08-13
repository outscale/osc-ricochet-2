#!/bin/bash


git clone https://github.com/outscale/osc-sdk-c

pkill ricochet
set -e
cargo build
cargo run -- ./osc-sdk-c/ricocher-cfg.json &> /dev/null &
sleep 5

cd osc-sdk-c

make ricochet_preparation
./local-tests.sh ""