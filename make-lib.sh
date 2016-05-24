#!/bin/sh -ex

# Run this with "debug" option to compile Keystone with debug info
if [ -n "$1" ]
then
# compile with DEBUG option
cmake -DCMAKE_BUILD_TYPE=Debug -DBUILD_SHARED_LIBS=OFF -DLLVM_TARGETS_TO_BUILD="all" -G "Unix Makefiles" ..
else
# default compile
cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DLLVM_TARGETS_TO_BUILD="all" -G "Unix Makefiles" ..
fi

time make -j8

