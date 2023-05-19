#!/usr/bin/env python
# Python binding for Keystone engine. Nguyen Anh Quynh <aquynh@gmail.com>

# upload TestPyPi package with: $ python setup.py sdist upload -r pypitest
# upload PyPi package with: $ python setup.py sdist upload -r pypi

import glob
import os
import shutil
import subprocess
import stat
import sys
import platform
from distutils import log
from setuptools import setup
from distutils.util import get_platform
from distutils.command.build import build as _build
from distutils.command.sdist import sdist as _sdist
from setuptools.command.bdist_egg import bdist_egg as _bdist_egg
from setuptools.command.develop import develop as _develop

#VERSION = '0.9.2' + 'rc1' + '.post2'
VERSION = '0.9.3'
SYSTEM = sys.platform
IS_64BITS = platform.architecture()[0] == '64bit'

# paths
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
LIBS_DIR = os.path.join(ROOT_DIR, 'keystone')
SRC_DIR = os.path.join(ROOT_DIR, 'src')
BUILD_DIR = os.path.join(SRC_DIR, 'build')

if SYSTEM == 'darwin':
    LIBRARY_FILE = "libkeystone.dylib"
    MAC_LIBRARY_FILE = "libkeystone*.dylib"
elif SYSTEM == 'win32':
    LIBRARY_FILE = "keystone.dll"
elif SYSTEM == 'cygwin':
    LIBRARY_FILE = "cygkeystone-0.dll"
else:
    LIBRARY_FILE = "libkeystone.so"

# prebuilt libraries for Windows - for sdist
PATH_LIB64 = os.path.join(ROOT_DIR, 'prebuilt', 'win64')
PATH_LIB32 = os.path.join(ROOT_DIR, 'prebuilt', 'win32')

def copy_sources():
    """Copy the C sources into the source directory.
    This rearranges the source files under the python distribution
    directory.
    """
    src = []

    os.system('make clean')
    shutil.rmtree(SRC_DIR, ignore_errors=True)
    os.mkdir(SRC_DIR)

    shutil.copytree(os.path.join(ROOT_DIR, '../../llvm'), os.path.join(SRC_DIR, 'llvm/'))
    shutil.copytree(os.path.join(ROOT_DIR, '../../include'), os.path.join(SRC_DIR, 'include/'))
    shutil.copytree(os.path.join(ROOT_DIR, '../../suite'), os.path.join(SRC_DIR, 'suite/'))

    src.extend(glob.glob(os.path.join(ROOT_DIR, "../../*.h")))
    src.extend(glob.glob(os.path.join(ROOT_DIR, "../../*.cpp")))
    src.extend(glob.glob(os.path.join(ROOT_DIR, "../../*.inc")))
    src.extend(glob.glob(os.path.join(ROOT_DIR, "../../*.def")))

    src.extend(glob.glob(os.path.join(ROOT_DIR, "../../CMakeLists.txt")))
    src.extend(glob.glob(os.path.join(ROOT_DIR, "../../CMakeUninstall.in")))
    src.extend(glob.glob(os.path.join(ROOT_DIR, "../../*.txt")))
    src.extend(glob.glob(os.path.join(ROOT_DIR, "../../*.TXT")))
    src.extend(glob.glob(os.path.join(ROOT_DIR, "../../COPYING")))
    src.extend(glob.glob(os.path.join(ROOT_DIR, "../../LICENSE*")))
    src.extend(glob.glob(os.path.join(ROOT_DIR, "../../EXCEPTIONS-CLIENT")))
    src.extend(glob.glob(os.path.join(ROOT_DIR, "../../README.md")))
    src.extend(glob.glob(os.path.join(ROOT_DIR, "../../RELEASE_NOTES")))
    src.extend(glob.glob(os.path.join(ROOT_DIR, "../../ChangeLog")))
    src.extend(glob.glob(os.path.join(ROOT_DIR, "../../SPONSORS.TXT")))
    src.extend(glob.glob(os.path.join(ROOT_DIR, "../../*.cmake")))
    src.extend(glob.glob(os.path.join(ROOT_DIR, "../../*.sh")))
    src.extend(glob.glob(os.path.join(ROOT_DIR, "../../*.bat")))

    for filename in src:
        outpath = os.path.join(SRC_DIR, os.path.basename(filename))
        log.info("%s -> %s" % (filename, outpath))
        shutil.copy(filename, outpath)

def build_libraries():
    cur_dir = os.getcwd()

    if SYSTEM in ("win32", "cygwin"):
        # if Windows prebuilt library is available, then include it
        if IS_64BITS and os.path.exists(os.path.join(PATH_LIB64, LIBRARY_FILE)):
            shutil.copy(os.path.join(PATH_LIB64, LIBRARY_FILE), LIBS_DIR)
            return
        elif os.path.exists(os.path.join(PATH_LIB32, LIBRARY_FILE)):
            shutil.copy(os.path.join(PATH_LIB32, LIBRARY_FILE), LIBS_DIR)
            return
        # cd src/build
    if not os.path.isdir(SRC_DIR):
        copy_sources()
    os.chdir(SRC_DIR)
    if not os.path.isdir(BUILD_DIR):
        os.mkdir(BUILD_DIR)
    os.chdir(BUILD_DIR)

    if SYSTEM == "win32":
        if IS_64BITS:
            subprocess.call([r'..\nmake-dll.bat'])
        else:
            subprocess.call([r'..\nmake-dll.bat', 'X86'])
        winobj_dir = os.path.join(BUILD_DIR, 'llvm', 'bin')  
        shutil.copy(os.path.join(winobj_dir, LIBRARY_FILE), LIBS_DIR)
    else:
        cmd = ['sh', '../make-share.sh', 'lib_only']
        subprocess.call(cmd)
        if SYSTEM == "cygwin":
            obj_dir = os.path.join(BUILD_DIR, 'llvm', 'bin')
        else:
            obj_dir = os.path.join(BUILD_DIR, 'llvm', 'lib')
        obj64_dir = os.path.join(BUILD_DIR, 'llvm', 'lib64')
        if SYSTEM == 'darwin':
            for file in glob.glob(os.path.join(obj_dir, MAC_LIBRARY_FILE)):
                try:
                    shutil.copy(file, LIBS_DIR, follow_symlinks=False)
                except:
                    shutil.copy(file, LIBS_DIR)
        else:
            try:
                shutil.copy(os.path.join(obj_dir, LIBRARY_FILE), LIBS_DIR)
            except:
                shutil.copy(os.path.join(obj64_dir, LIBRARY_FILE), LIBS_DIR)
    # back to root dir
    os.chdir(cur_dir)

class sdist(_sdist):
    def run(self):
        copy_sources()
        return _sdist.run(self)

class build(_build):
    def run(self):
        log.info("Building C++ extensions")
        build_libraries()
        return _build.run(self)

class develop(_develop):
    def run(self):
        log.info("Building C++ extensions")
        build_libraries()
        return _develop.run(self)

class bdist_egg(_bdist_egg):
    def run(self):
        self.run_command('build')
        return _bdist_egg.run(self)
    
def dummy_src():
    return []

if 'bdist_wheel' in sys.argv and '--plat-name' not in sys.argv:
    idx = sys.argv.index('bdist_wheel') + 1
    sys.argv.insert(idx, '--plat-name')
    name = get_platform()
    if 'linux' in name:
        # linux_* platform tags are disallowed because the python ecosystem is fubar
        # linux builds should be built in the centos 5 vm for maximum compatibility
        # see https://github.com/pypa/manylinux
        # see also https://github.com/angr/angr-dev/blob/master/bdist.sh
        sys.argv.insert(idx + 1, 'manylinux1_' + platform.machine())
    elif 'mingw' in name:
        if IS_64BITS:
            sys.argv.insert(idx + 1, 'win_amd64')
        else:
            sys.argv.insert(idx + 1, 'win32')
    else:
        # https://www.python.org/dev/peps/pep-0425/
        sys.argv.insert(idx + 1, name.replace('.', '_').replace('-', '_'))


long_desc = '''
Keystone is a lightweight multi-platform, multi-architecture assembler framework.
It offers some unparalleled features:

- Multi-architecture, with support for Arm, Arm64 (AArch64/Armv8), Ethereum Virtual Machine, Hexagon, Mips, PowerPC, Sparc, SystemZ & X86 (include 16/32/64bit).
- Clean/simple/lightweight/intuitive architecture-neutral API.
- Implemented in C/C++ languages, with bindings for Java, Masm, C#, PowerShell, Perl, Python, NodeJS, Ruby, Go, Rust, Haskell, VB6 & OCaml available.
- Native support for Windows & \*nix (with Mac OSX, Linux, \*BSD & Solaris confirmed).
- Thread-safe by design.
- Open source - with a dual license.

Further information is available at http://www.keystone-engine.org


License
-------

Keystone is available under a dual license:

- Version 2 of the GNU General Public License (GPLv2). (I.e. Without the "any later version" clause.).
  License information can be found in the COPYING file EXCEPTIONS-CLIENT file.

  This combination allows almost all of open source projects to use Keystone without conflicts.

- For commercial usage in production environments, contact the authors of Keystone to buy a royalty-free license.

  See LICENSE-COM.TXT for more information.
'''

setup(
    provides=['keystone'],
    packages=['keystone'],
    name='keystone-engine',
    version=VERSION,
    author='Nguyen Anh Quynh',
    author_email='aquynh@gmail.com',
    description='Keystone assembler engine',
    long_description=long_desc,
    long_description_content_type="text/markdown",
    url='https://www.keystone-engine.org',
    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 5 - Production/Stable',

        # Indicate who your project is intended for
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',

        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
    ],
    requires=['ctypes'],
    cmdclass={'build': build, 'develop': develop, 'sdist': sdist, 'bdist_egg': bdist_egg},
    zip_safe=False,
    include_package_data=True,
    is_pure=False,
    package_data={
        'keystone': ['*']
    }
)
