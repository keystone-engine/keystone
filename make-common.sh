BUILDTYPE='Release'

# on MacOS, build universal binaries by default
ARCH='i386;x86_64'

# Linux FHS wants to install x64 libraries in "lib64"
# Examples are Fedora, Redhat, Suse.
LLVM_LIBDIR_SUFFIX=''

# by default we do NOT build 32bit on 64bit system
LLVM_BUILD_32_BITS=0

# by default we build libraries & kstool
# but we can skip kstool & build libraries only
BUILD_LIBS_ONLY=0

while [ "$1" != "" ]; do
  case $1 in
    lib_only)
      BUILD_LIBS_ONLY=1
      ;;
    lib32)
      LLVM_BUILD_32_BITS=1
      ;;
    lib64)
      LLVM_LIBDIR_SUFFIX='64'
      ;;
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
