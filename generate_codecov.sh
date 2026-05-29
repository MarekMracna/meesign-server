#!/bin/bash

# Prepare folder structure
mkdir -p coverage/reports
# NOTE: Needed to allow writing from volume-mapped dir in container in CI
chmod 777 coverage

# Run instrumented unit tests
RUSTFLAGS="-C instrument-coverage"                                              \
LLVM_PROFILE_FILE="coverage/unit_test_%m_%p.profraw"                            \
  cargo test --tests

# Run instrumented E2E tests
./run_integration_tests.sh
docker cp                                                                       \
       meesign-integration-tests-meesign-server-1:/usr/local/bin/meesign-server \
       ./coverage/meesign-server
./run_integration_tests.sh down

# Merge collected data
llvm-profdata merge -sparse coverage/unit_test*.profraw -o coverage/unit_tests.profdata
llvm-profdata merge -sparse coverage/e2e_test*.profraw  -o coverage/e2e_tests.profdata
llvm-profdata merge -sparse coverage/*.profraw          -o coverage/combined.profdata

# Export .lcov coverage info
function export_lcov() {
    llvm-cov export                                                             \
             --format=lcov                                                      \
             --ignore-filename-regex='/.cargo'                                  \
             --ignore-filename-regex='/rustc'                                   \
             --ignore-filename-regex='.*\/target\/.*'                           \
             "$@"
}

UNIT_TEST_OBJECT_FILES=$(                                                       \
    RUSTFLAGS="-C instrument-coverage"                                          \
    cargo test --tests --no-run --message-format=json                           \
        | jq -r "select(.profile.test == true) | .filenames[]"                  \
        | grep -v dSYM -                                                        \
)

UNIT_TEST_OBJECT_FLAGS=$(                                                       \
    for file in $UNIT_TEST_OBJECT_FILES;                                        \
    do                                                                          \
      printf "%s %s " --object $file;                                           \
    done                                                                        \
 )

export_lcov                                                                     \
    $UNIT_TEST_OBJECT_FLAGS                                                     \
    --instr-profile=coverage/unit_tests.profdata                                \
    > coverage/unit_tests.lcov

export_lcov                                                                     \
    --object coverage/meesign-server                                            \
    --instr-profile=coverage/e2e_tests.profdata                                 \
    --path-equivalence=/home/rust/src/src,$(pwd)/src                            \
    > coverage/e2e_tests.lcov

export_lcov                                                                     \
    $UNIT_TEST_OBJECT_FLAGS                                                     \
    --object coverage/meesign-server                                            \
    --instr-profile=coverage/combined.profdata                                  \
    --path-equivalence=/home/rust/src/src,$(pwd)/src                            \
    > coverage/combined.lcov

# Generate HTML reports from .lcov coverage info
function generate_report() {
    sed -i "s|^SF:/home/rust/src|SF:$(pwd)|g" "coverage/$1.lcov"
    rustfilt < "coverage/$1.lcov" > "coverage/${1}_demangled.lcov"
    genhtml --ignore-errors inconsistent "coverage/${1}_demangled.lcov" -o "coverage/reports/$1"
}

generate_report unit_tests
generate_report e2e_tests
generate_report combined
