#!/bin/sh -e

# Build shared library of Keystone Engine
# syntax: make-share.sh [debug] [macos-universal]

usage()
{
  echo ""
  echo "Syntax:  make-share.sh [debug] [macos-universal]"
  echo "\tdebug:           build with debug info"
  echo "\tmacos-no-universal: do not build MacOS universal binaries"
  echo ""
}

BUILDTYPE='Release'

# on MacOS, build universal binaries by default
ARCH='i386;x86_64'

while [ "$1" != "" ]; do
  case $1 in
    debug)
      BUILDTYPE='Debug'
      ;;
    macos-no-universal)
      ARCH=''	# do not build MacOS universal binaries
      ;;
    *)
      echo "ERROR: unknown parameter \"$1\""
      usage
      exit 1
      ;;
  esac
  shift
done

cmake -DCMAKE_OSX_ARCHITECTURES="$ARCH" -DCMAKE_BUILD_TYPE=$BUILDTYPE -DBUILD_SHARED_LIBS=ON -DLLVM_TARGETS_TO_BUILD="all" -G "Unix Makefiles" ..

time make -j8
