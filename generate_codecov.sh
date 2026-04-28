#!/bin/sh

RUSTFLAGS="-C instrument-coverage"                                    \
LLVM_PROFILE_FILE="coverage/test_%m_%p.profraw"                       \
  cargo test --tests

llvm-profdata merge -sparse coverage/*.profraw -o coverage/server.profdata

llvm-cov show                                                         \
    $(                                                                \
       for file in                                                    \
         $(                                                           \
           RUSTFLAGS="-C instrument-coverage"                         \
             cargo test --tests --no-run --message-format=json        \
               | jq -r "select(.profile.test == true) | .filenames[]" \
               | grep -v dSYM -                                       \
         );                                                           \
       do                                                             \
         printf "%s %s " --object $file;                              \
       done                                                           \
    )                                                                 \
  --show-line-counts-or-regions                                       \
  --show-instantiations                                               \
  --instr-profile=coverage/server.profdata                            \
  --Xdemangler=rustfilt                                               \
  --output-dir=coverage                                               \
  --format=html                                                       \
  --ignore-filename-regex='/.cargo/registry'                          \
  --ignore-filename-regex='/rustc'
