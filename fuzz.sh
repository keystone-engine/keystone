#!/bin/bash
pushd .
cd build && ../make-afl.sh
popd
pushd .
cd ./afl
afl-fuzz -i ./tests -o ./findings -x ./dict -- ../build/kstool/kstool x32
popd
