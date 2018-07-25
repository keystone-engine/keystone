#!/bin/sh -e

# Build shared library of Keystone Engine
# syntax: make-share.sh [debug] [macos-universal|macos-no-universal] [lib32] [lib_only]

usage()
{
  echo ""
  echo "Syntax:  make-share.sh [debug] [macos-universal] [lib64]"
  echo ""
  echo "         debug: build with debug info"
  echo "         macos-universal: build MacOS universal binaries"
  echo "         macos-no-universal: do not build MacOS universal binaries (default)"
  echo "         lib_only: skip kstool & only build libraries"
  echo "         lib32: build 32bit libraries on 64bit system"
  echo ""
}

. "$(dirname "$0")"/make-common.sh

cmake -DBUILD_LIBS_ONLY=$BUILD_LIBS_ONLY -DLLVM_BUILD_32_BITS="$LLVM_BUILD_32_BITS" -DCMAKE_OSX_ARCHITECTURES="$ARCH" -DCMAKE_BUILD_TYPE=$BUILDTYPE -DBUILD_SHARED_LIBS=ON -DLLVM_TARGETS_TO_BUILD="all" -G "Unix Makefiles" ..

make -j8
