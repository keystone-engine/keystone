#!/usr/bin/env python
# Python binding for Keystone engine. Nguyen Anh Quynh <aquynh@gmail.com>

# upload TestPyPi package with: $ python setup.py sdist upload -r pypitest
# upload PyPi package with: $ python setup.py sdist upload -r pypi

import glob
import os
import shutil
import stat
import sys
from distutils import dir_util, file_util
from distutils import log
from distutils.command.build_clib import build_clib
from distutils.command.install_lib import install_lib
from distutils.command.sdist import sdist
from distutils.core import setup

# prebuilt libraries for Windows - for sdist
PATH_LIB64 = "prebuilt/win64/keystone.dll"
PATH_LIB32 = "prebuilt/win32/keystone.dll"

# package name can be 'keystone-engine' or 'keystone-engine-windows'
PKG_NAME = 'keystone-engine'
if os.path.exists(PATH_LIB64) and os.path.exists(PATH_LIB32):
    PKG_NAME = 'keystone-engine-windows'

VERSION = '0.9.1-3'
SYSTEM = sys.platform

SETUP_DATA_FILES = []

# adapted from commit e504b81 of Nguyen Tan Cong
# Reference: https://docs.python.org/2/library/platform.html#cross-platform
is_64bits = sys.maxsize > 2 ** 32


def copy_sources():
    """Copy the C sources into the source directory.
    This rearranges the source files under the python distribution
    directory.
    """
    src = []

    try:
        dir_util.remove_tree("src/")
    except (IOError, OSError):
        pass

    dir_util.copy_tree("../../llvm", "src/llvm/")
    dir_util.copy_tree("../../include", "src/include/")
    dir_util.copy_tree("../../suite", "src/suite")

    src.extend(glob.glob("../../*.h"))
    src.extend(glob.glob("../../*.cpp"))
    src.extend(glob.glob("../../*.inc"))
    src.extend(glob.glob("../../*.def"))

    src.extend(glob.glob("../../CMakeLists.txt"))
    src.extend(glob.glob("../../CMakeUninstall.in"))
    src.extend(glob.glob("../../*.txt"))
    src.extend(glob.glob("../../*.TXT"))
    src.extend(glob.glob("../../COPYING"))
    src.extend(glob.glob("../../LICENSE*"))
    src.extend(glob.glob("../../EXCEPTIONS-CLIENT"))
    src.extend(glob.glob("../../README.md"))
    src.extend(glob.glob("../../RELEASE_NOTES"))
    src.extend(glob.glob("../../ChangeLog"))
    src.extend(glob.glob("../../SPONSORS.TXT"))
    src.extend(glob.glob("../../*.cmake"))
    src.extend(glob.glob("../../*.sh"))
    src.extend(glob.glob("../../*.bat"))

    for filename in src:
        outpath = os.path.join("./src/", os.path.basename(filename))
        log.info("%s -> %s" % (filename, outpath))
        shutil.copy(filename, outpath)


class custom_sdist(sdist):
    """Reshuffle files for distribution."""

    def run(self):
        # if prebuilt libraries are existent, then do not copy source
        if os.path.exists(PATH_LIB64) and os.path.exists(PATH_LIB32):
            return sdist.run(self)
        copy_sources()
        return sdist.run(self)


class custom_build_clib(build_clib):
    """Customized build_clib command."""

    def run(self):
        log.info('running custom_build_clib')
        build_clib.run(self)

    def finalize_options(self):
        # We want build-clib to default to build-lib as defined by the "build"
        # command.  This is so the compiled library will be put in the right
        # place along side the python code.
        self.set_undefined_options('build',
                                   ('build_lib', 'build_clib'),
                                   ('build_temp', 'build_temp'),
                                   ('compiler', 'compiler'),
                                   ('debug', 'debug'),
                                   ('force', 'force'))

        build_clib.finalize_options(self)

    def build_libraries(self, libraries):

        cur_dir = os.path.realpath(os.curdir)

        if SYSTEM in ("win32", "cygwin"):
            # if Windows prebuilt library is available, then include it
            if is_64bits and os.path.exists(PATH_LIB64):
                SETUP_DATA_FILES.append(PATH_LIB64)
                return
            elif os.path.exists(PATH_LIB32):
                SETUP_DATA_FILES.append(PATH_LIB32)
                return

        # build library from source if src/ is existent
        if not os.path.exists('src'):
            return

        try:
            for (lib_name, build_info) in libraries:
                log.info("building '%s' library", lib_name)

                # cd src/build
                os.chdir("src")
                if not os.path.isdir('build'):
                    os.mkdir('build')
                os.chdir("build")

                # platform description refers at https://docs.python.org/2/library/sys.html#sys.platform
                if SYSTEM == "cygwin":
                    os.chmod("make.sh", stat.S_IREAD | stat.S_IEXEC)
                    if is_64bits:
                        os.system("KEYSTONE_BUILD_CORE_ONLY=yes ./make.sh cygwin-mingw64")
                    else:
                        os.system("KEYSTONE_BUILD_CORE_ONLY=yes ./make.sh cygwin-mingw32")
                    SETUP_DATA_FILES.append("src/build/keystone.dll")
                else:  # Unix
                    os.chmod("../make-share.sh", stat.S_IREAD | stat.S_IEXEC)
                    os.system("../make-share.sh lib_only")
                    if SYSTEM == "darwin":
                        SETUP_DATA_FILES.append("src/build/llvm/lib/libkeystone.dylib")
                    else:  # Non-OSX
                        SETUP_DATA_FILES.append("src/build/llvm/lib/libkeystone.so")

                # back to root dir
                os.chdir(cur_dir)

        except Exception as e:
            log.error(e)
        finally:
            os.chdir(cur_dir)


class custom_install(install_lib):
    def install(self):
        install_lib.install(self)
        ks_install_dir = os.path.join(self.install_dir, 'keystone')
        for lib_file in SETUP_DATA_FILES:
            file_util.copy_file(lib_file, ks_install_dir)


def dummy_src():
    return []


setup(
    provides=['keystone'],
    packages=['keystone'],
    name=PKG_NAME,
    version=VERSION,
    author='Nguyen Anh Quynh',
    author_email='aquynh@gmail.com',
    description='Keystone assembler engine',
    url='http://www.keystone-engine.org',
    classifiers=[
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
    ],
    requires=['ctypes'],
    cmdclass=dict(
        build_clib=custom_build_clib,
        sdist=custom_sdist,
        install_lib=custom_install,
    ),

    libraries=[(
        'keystone', dict(
            package='keystone',
            sources=dummy_src()
        ),
    )],
)
