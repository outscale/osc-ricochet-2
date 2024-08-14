#!/bin/bash

pkill ricochet
set -e
cargo build --profile 'sdks'
cargo run --profile 'sdks' -- ./ricochet.json &> /dev/null  &
sleep 5

git clone https://github.com/outscale/osc-sdk-python
cd osc-sdk-python

./local-tests.sh ""