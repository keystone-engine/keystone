BUILDTYPE='Release'

# on MacOS, build universal binaries by default
ARCH='i386;x86_64'

# Linux FHS wants to install x64 libraries in "lib64"
# Examples are Fedora, Redhat, Suse.
LIB_SUFFIX=''

while [ "$1" != "" ]; do
  case $1 in
    fhs)
      LIB_SUFFIX='64'
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
