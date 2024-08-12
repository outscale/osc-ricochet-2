#!/bin/bash

pkill ricochet
set -e
cargo build
cargo run -- ./ricochet.json &> /dev/null  &
sleep 5

git clone https://github.com/outscale/osc-cli
cd osc-cli

./local_tests.sh ""

pkill ricochet