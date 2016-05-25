#!/bin/bash
AFLFUZZ=afl-fuzz
KSTOOL=$(pwd)/../build/kstool/kstool

if [ $# -ne 1 ]; then 
    echo "Usage: fuzz.sh {arch}"
    exit;
fi

pushd .
cd ../build && ../make-afl.sh
popd
pushd .
cd ./afl
for arch in "$@"
do
    if [ -d "./dict/$arch" ]; then
        $AFLFUZZ -i ./tests -o ./findings -x ./dict/$arch -- $KSTOOL $arch
    else
        $AFLFUZZ -i ./tests -o ./findings -- $KSTOOL $arch
    fi
done
popd
