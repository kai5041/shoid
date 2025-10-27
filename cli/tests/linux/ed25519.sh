#!/bin/bash

cmd=../../../build/linux/shoid

rm -rf out
mkdir -p out
cd out

check_ret() {
    local expected_ret=$1
    shift
    "$@"
    local status=$?
    if [ $status -ne $expected_ret ]; then
        echo "command failed: $*"
        exit 1
    fi
}

check_ret 0 $cmd generate ed25519 user
check_ret 0 $cmd sign ed25519 ../../../LICENSE ./user_private.bin out.sig
check_ret 0 $cmd verify ed25519 ../../../LICENSE ./out.sig ./user_public.bin
echo malicious >> ./out.sig
check_ret 1 $cmd verify ed25519 ../../../LICENSE ./out.sig ./user_public.bin

echo "ed25519 tests passed"
