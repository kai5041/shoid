#!/bin/bash

set -e

make clean
make linux -j$(nproc)
sudo make install_linux
