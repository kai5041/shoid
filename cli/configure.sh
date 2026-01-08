#!/bin/sh
set -e

mkdir -p libs && cd libs
mkdir -p linux-x32_64

cd linux-x32_64

git clone https://github.com/uNetworking/uWebSockets.git
cd uWebSockets
git submodule update --init --recursive
make -j$(nproc)
cp uSockets ../libuSockets.a
