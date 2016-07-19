#!/bin/sh -e

# Build shared library of Keystone Engine
# syntax: make-share.sh [debug] [macos-universal] [lib64]

usage()
{
  echo ""
  echo "Syntax:  make-share.sh [debug] [macos-universal] [lib64]"
  echo ""
  echo "         debug: build with debug info"
  echo "         macos-no-universal: do not build MacOS universal binaries"
  echo "         lib64: install Linux x64 libraries in \$PREFIX/lib64 (Fedora/Redhat/Suse, etc)"
  echo ""
}

source "$(dirname "$0")"/make-common.sh

cmake -DLLVM_LIBDIR_SUFFIX="$LLVM_LIBDIR_SUFFIX" -DCMAKE_OSX_ARCHITECTURES="$ARCH" -DCMAKE_BUILD_TYPE=$BUILDTYPE -DBUILD_SHARED_LIBS=ON -DLLVM_TARGETS_TO_BUILD="all" -G "Unix Makefiles" ..

time make -j8
