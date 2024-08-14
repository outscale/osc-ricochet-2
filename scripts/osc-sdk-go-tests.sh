#!/bin/bash

pkill ricochet
set -e
cargo build --profile 'sdks'
cargo run --profile 'sdks' -- ./ricochet.json &> /dev/null  &
sleep 5

git clone https://github.com/outscale/osc-sdk-go
cd osc-sdk-go

./local_tests.sh ""