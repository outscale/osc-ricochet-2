#!/bin/bash

pkill ricochet
set -e
cargo build --profile 'sdks'
cargo run --profile 'sdks' -- ./ricochet.json &> /dev/null  &
sleep 5

cd osc-sdk-java

./local_tests.sh ""