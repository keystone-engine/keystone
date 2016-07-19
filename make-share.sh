#!/bin/sh -e

# Build shared library of Keystone Engine
# syntax: make-share.sh [debug] [macos-universal] [fhs]

usage()
{
  echo ""
  echo "Syntax:\tmake-share.sh [debug] [macos-universal] [fhs]\n"
  echo "\tdebug:           build with debug info"
  echo "\tmacos-no-universal: do not build MacOS universal binaries"
  echo "\tfhs: install Linux x64 libraries in \$PREFIX/lib64 (Fedora/Redhat/Suse, etc)"
  echo ""
}

source "$(dirname "$0")"/make-common.sh

cmake -DLIB_SUFFIX="$LIB_SUFFIX" -DCMAKE_OSX_ARCHITECTURES="$ARCH" -DCMAKE_BUILD_TYPE=$BUILDTYPE -DBUILD_SHARED_LIBS=ON -DLLVM_TARGETS_TO_BUILD="all" -G "Unix Makefiles" ..

time make -j8
