#!/usr/bin/env bash

set -e

function compose() {
    docker compose \
        --file compose.base.yaml \
        --file integration-tests/compose.yaml \
        --env-file integration-tests/.env \
        "$@"
}

if test "$1" == "down"; then
    compose down --volumes --remove-orphans
    exit "$?"
fi

if [ -z "$1" ]; then
    compose up test-client
else
    # If any command line arguments are supplied, these are pass on to the
    # `test-client`, i.e. calling `dart test --reporter=expanded "$@"`
    compose run \
            --rm \
            test-client \
            --disable-analytics \
            test --reporter=expanded \
            "$@"
fi
