# Keystone Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>
import sys
_python2 = sys.version_info[0] < 3
if _python2:
    range = xrange

from . import arm_const, arm64_const, mips_const, sparc_const, hexagon_const, ppc_const, systemz_const, x86_const, evm_const
from .keystone_const import *

from ctypes import *
from platform import system
from os.path import split, join, dirname, exists
import sys


import inspect
if not hasattr(sys.modules[__name__], '__file__'):
    __file__ = inspect.getfile(inspect.currentframe())

_lib_path = split(__file__)[0]
_all_libs = ('keystone.dll', 'libkeystone.so', 'libkeystone.so.%u' %KS_API_MAJOR, 'libkeystone.dylib')
_found = False

for _lib in _all_libs:
    try:
        _lib_file = join(_lib_path, _lib)
        #print(">> 0: Trying to load %s" %_lib_file);
        _ks = cdll.LoadLibrary(_lib_file)
        _found = True
        break
    except OSError:
        pass

if _found == False:
    # try loading from default paths
    for _lib in _all_libs:
        try:
            #print(">> 1: Trying to load %s" %_lib);
            _ks = cdll.LoadLibrary(_lib)
            _found = True
            break
        except OSError:
            pass

if _found == False:
    # last try: loading from python lib directory
    import distutils.sysconfig
    _lib_path = distutils.sysconfig.get_python_lib()
    for _lib in _all_libs:
        try:
            _lib_file = join(_lib_path, 'keystone', _lib)
            #print(">> 2: Trying to load %s" %_lib_file);
            _ks = cdll.LoadLibrary(_lib_file)
            _found = True
            break
        except OSError:
            pass

# Attempt Linux/Darwin specific load (10.11 specific),
# since LD_LIBRARY_PATH is not guaranteed to exist
if (_found == False) and (system() != 'Windows'):
    _lib_path = '/usr/local/lib/'
    for _lib in _all_libs:
        try:
            _lib_file = join(_lib_path, _lib)
            #print(">> 3: Trying to load %s" %_lib_file);
            _ks = cdll.LoadLibrary(_lib_file)
            _found = True
            break
        except OSError:
            pass

if _found == False:
    raise ImportError("ERROR: fail to load the dynamic library.")

__version__ = "%u.%u.%u" %(KS_VERSION_MAJOR, KS_VERSION_MINOR, KS_VERSION_EXTRA)

# setup all the function prototype
def _setup_prototype(lib, fname, restype, *argtypes):
    getattr(lib, fname).restype = restype
    getattr(lib, fname).argtypes = argtypes

kserr = c_int
ks_engine = c_void_p
ks_hook_h = c_size_t

_setup_prototype(_ks, "ks_version", c_uint, POINTER(c_int), POINTER(c_int))
_setup_prototype(_ks, "ks_arch_supported", c_bool, c_int)
_setup_prototype(_ks, "ks_open", kserr, c_uint, c_uint, POINTER(ks_engine))
_setup_prototype(_ks, "ks_close", kserr, ks_engine)
_setup_prototype(_ks, "ks_strerror", c_char_p, kserr)
_setup_prototype(_ks, "ks_errno", kserr, ks_engine)
_setup_prototype(_ks, "ks_option", kserr, ks_engine, c_int, c_void_p)
_setup_prototype(_ks, "ks_asm", c_int, ks_engine, c_char_p, c_uint64, POINTER(POINTER(c_ubyte)), POINTER(c_size_t), POINTER(c_size_t))
_setup_prototype(_ks, "ks_free", None, POINTER(c_ubyte))

# callback for OPT_SYM_RESOLVER option
KS_SYM_RESOLVER = CFUNCTYPE(c_bool, c_char_p, POINTER(c_uint64))

# access to error code via @errno of KsError
# this also includes the @stat_count returned by ks_asm
class KsError(Exception):
    def __init__(self, errno, count=None):
        self.stat_count = count
        self.errno = errno
        self.message = _ks.ks_strerror(self.errno)
        if not isinstance(self.message, str) and isinstance(self.message, bytes):
            self.message = self.message.decode('utf-8')

    # retrieve @stat_count value returned by ks_asm()
    def get_asm_count(self):
        return self.stat_count

    def __str__(self):
        return self.message


# return the core's version
def ks_version():
    major = c_int()
    minor = c_int()
    combined = _ks.ks_version(byref(major), byref(minor))
    return (major.value, minor.value, combined)


# return the binding's version
def version_bind():
    return (KS_API_MAJOR, KS_API_MINOR, (KS_API_MAJOR << 8) + KS_API_MINOR)


# check to see if this engine supports a particular arch
def ks_arch_supported(query):
    return _ks.ks_arch_supported(query)


class Ks(object):
    def __init__(self, arch, mode):
        # verify version compatibility with the core before doing anything
        (major, minor, _combined) = ks_version()
        if major != KS_API_MAJOR or minor != KS_API_MINOR:
            self._ksh = None
            # our binding version is different from the core's API version
            raise KsError(KS_ERR_VERSION)

        self._arch, self._mode = arch, mode
        self._ksh = c_void_p()
        status = _ks.ks_open(arch, mode, byref(self._ksh))
        if status != KS_ERR_OK:
            self._ksh = None
            raise KsError(status)

        if arch == KS_ARCH_X86:
            # Intel syntax is default for X86
            self._syntax = KS_OPT_SYNTAX_INTEL
        else:
            self._syntax = None


    # destructor to be called automatically when object is destroyed.
    def __del__(self):
        if self._ksh:
            try:
                status = _ks.ks_close(self._ksh)
                self._ksh = None
                if status != KS_ERR_OK:
                    raise KsError(status)
            except: # _ks might be pulled from under our feet
                pass


    # return assembly syntax.
    @property
    def syntax(self):
        return self._syntax


    # syntax setter: modify assembly syntax.
    @syntax.setter
    def syntax(self, style):
        status = _ks.ks_option(self._ksh, KS_OPT_SYNTAX, style)
        if status != KS_ERR_OK:
            raise KsError(status)
        # save syntax
        self._syntax = style


    @property
    def sym_resolver(self):
        return


    @sym_resolver.setter
    def sym_resolver(self, resolver):
        callback = KS_SYM_RESOLVER(resolver)
        status = _ks.ks_option(self._ksh, KS_OPT_SYM_RESOLVER, callback)
        if status != KS_ERR_OK:
            raise KsError(status)
        # save resolver
        self._sym_resolver = callback


    # assemble a string of assembly
    def asm(self, string, addr=0, as_bytes=False):
        encode = POINTER(c_ubyte)()
        encode_size = c_size_t()
        stat_count = c_size_t()
        if not isinstance(string, bytes) and isinstance(string, str):
            string = string.encode('ascii')

        status = _ks.ks_asm(self._ksh, string, addr, byref(encode), byref(encode_size), byref(stat_count))
        if (status != 0):
            errno = _ks.ks_errno(self._ksh)
            raise KsError(errno, stat_count.value)
        else:
            if stat_count.value == 0:
                return (None, 0)
            else:
                if as_bytes:
                    encoding = string_at(encode, encode_size.value)
                else:
                    encoding = []
                    for i in range(encode_size.value):
                        encoding.append(encode[i])

                _ks.ks_free(encode)
                return (encoding, stat_count.value)


# print out debugging info
def debug():
    archs = { "arm": KS_ARCH_ARM, "arm64": KS_ARCH_ARM64, \
        "mips": KS_ARCH_MIPS, "sparc": KS_ARCH_SPARC, \
        "systemz": KS_ARCH_SYSTEMZ, "ppc": KS_ARCH_PPC, \
        "hexagon": KS_ARCH_HEXAGON, "x86": KS_ARCH_X86, 'evm': KS_ARCH_EVM }

    all_archs = ""
    keys = archs.keys()
    for k in sorted(keys):
        if ks_arch_supported(archs[k]):
            all_archs += "-%s" % k

    (major, minor, _combined) = ks_version()

    return "python-%s-c%u.%u-b%u.%u" % (all_archs, major, minor, KS_API_MAJOR, KS_API_MINOR)

