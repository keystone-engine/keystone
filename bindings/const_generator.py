# Keystone Engine
# Adapted from the code of Dang Hoang Vu for Capstone Engine, 2013
from __future__ import print_function
import sys, re, os

INCL_DIR = os.path.join('..', 'include', 'keystone')

# NOTE: this reflects the value of KS_ERR_ASM_xxx in keystone.h
ks_err_val = { 'KS_ERR_ASM': '128', 'KS_ERR_ASM_ARCH': '512' }

include = [ 'arm.h', 'arm64.h', 'mips.h', 'x86.h', 'sparc.h', 'riscv.h', 'ppc.h', 'systemz.h', 'hexagon.h', 'evm.h', 'keystone.h' ]

def CamelCase(s):
    # return re.sub(r'(\w)+\_?', lambda m:m.group(0).capitalize(), s)
    return ''.join(''.join([w[0].upper(), w[1:].lower()]) for w in s.split('_'))

template = {
    'powershell': {
            'header': "/// For Keystone Engine. AUTO-GENERATED FILE, DO NOT EDIT [%s_h.cs]\n",
            'footer': "",
            'out_file': './powershell/Keystone/Const/%s_h.cs',
            # prefixes for constant filenames of all archs - case sensitive
            'keystone.h': 'keystone',
            'comment_open': '///',
            'comment_close': '',
            'rules': [
                {
                    'regex': r'.*',
                    'line_format': 'KS_{0} = {1},\n',
                    'fn': (lambda x: x),
                },
            ]
        },
    'rust': {
            'header': "#![allow(non_camel_case_types)]\n// For Keystone Engine. AUTO-GENERATED FILE, DO NOT EDIT [%s_const.rs]\nuse ::libc::*;\n",
            'footer': "",
            # prefixes for constant filenames of all archs - case sensitive
            'arm.h': 'keystone',
            'arm64.h': 'keystone',
            'mips.h': 'keystone',
            'x86.h': 'keystone',
            'sparc.h': 'keystone',
            'riscv.h': 'keystone',
            'systemz.h': 'keystone',
            'ppc.h': 'keystone',
            'hexagon.h': 'keystone',
            'evm.h': 'keystone',
            'keystone.h': 'keystone',
            'comment_open': '/*',
            'comment_close': '*/',
            'out_file': './rust/keystone-sys/src/%s_const.rs',
            'rules': [
                {
                    'regex': r'(API)_.*',
                    'pre': '\n',
                    'line_format': 'pub const {0}: c_uint = {1};\n',
                    'fn': (lambda x: x),
                },
                {   'regex': r'MODE_.*',
                    'pre': '\n' +
                            'bitflags! {{\n' +
                            '#[repr(C)]\n' +
                            '    pub struct Mode: c_int {{\n',
                    'line_format': '        const {0} = {1};\n',
                    'fn': (lambda x: '_'.join(x.split('_')[1:]) if not re.match(r'MODE_\d+', x) else x),
                    'post': '    }\n}',
                },
                {
                    'regex': r'ARCH_.*',
                    'pre': '\n' +
                            '#[repr(C)]\n' +
                            '#[derive(Debug, PartialEq, Clone, Copy)]\n' +
                            'pub enum Arch {{\n',
                    'line_format': '    {0} = {1},\n',
                    'fn': (lambda x: '_'.join(x.split('_')[1:])),
                    'post': '}\n',
                },
                {
                    'regex': r'(OPT_([A-Z]+)|OPT_SYM_RESOLVER)$',
                    'pre': '#[repr(C)]\n' +
                            '#[derive(Debug, PartialEq, Clone, Copy)]\n' +
                            'pub enum OptionType {{\n',
                    'line_format': '    {0} = {1},\n',
                    'fn': (lambda x: '_'.join(x.split('_')[1:])),
                    'post': '}\n',
                },
                {
                    'regex': r'OPT_(?!SYM)([A-Z]+\_)+[A-Z]+',
                    'pre': 'bitflags! {{\n'
                            '#[repr(C)]\n' +
                            '    pub struct OptionValue: size_t {{\n',
                    'line_format': '        const {0} = {1};\n',
                    'fn': (lambda x: '_'.join(x.split('_')[1:])),
                    'post': '    }\n}\n',
                },
                {
                    'regex': r'ERR_(.*)',
                    'pre': 'bitflags! {{\n' +
                            '#[repr(C)]\n' +
                            '    pub struct Error: c_int {{\n',
                    'line_format': '        const {0} = {1};\n',
                    'fn': (lambda x: '_'.join(x.split('_')[1:])),
                    'post': '    }\n}',
                },
            ],
    },
    'go': {
            'header': "package keystone\n// For Keystone Engine. AUTO-GENERATED FILE, DO NOT EDIT [%s_const.go]\n\n",
            'footer': "",
            # prefixes for constant filenames of all archs - case sensitive
            'arm.h': 'arm',
            'arm64.h': 'arm64',
            'mips.h': 'mips',
            'x86.h': 'x86',
            'sparc.h': 'sparc',
            'riscv.h': 'riscv',
            'systemz.h': 'systemz',
            'ppc.h': 'ppc',
            'hexagon.h': 'hexagon',
            'evm.h': 'evm',
            'keystone.h': 'keystone',
            'comment_open': '/*',
            'comment_close': '*/',
            'out_file': './go/keystone/%s_const.go',
            'rules': [
                {
                    'regex': r'API_.*',
                    'pre': 'const (\n',
                    'line_format': '\t{0} = {1}\n',
                    'fn': (lambda x: x),
                    'post': ')\n',
                },
                {   'regex': r'MODE_.*',
                    'pre': 'const (\n',
                    'line_format': '\t{0} Mode = {1}\n',
                    'fn': (lambda x: x),
                    'post': ')\n',
                },
                {
                    'regex': r'ARCH_.*',
                    'pre': 'const (\n',
                    'line_format': '\t{0} Architecture = {1}\n',
                    'fn': (lambda x: x),
                    'post': ')\n',
                },
                {
                    'regex': r'OPT_([A-Z]+)$',
                    'pre': 'const (\n',
                    'line_format': '\t{0} OptionType = {1}\n',
                    'fn': (lambda x: x),
                    'post': ')\n',
                },
                {
                    'regex': r'OPT_([A-Z]+\_)+[A-Z]+',
                    'pre': 'const (\n',
                    'line_format': '\t{0} OptionValue = {1}\n',
                    'fn': (lambda x: x),
                    'post': ')\n',
                },
                {
                    'regex': r'ERR_.*',
                    'pre': 'const (\n',
                    'line_format': '\t{0} Error = {1}\n',
                    'fn': (lambda x: x),
                    'post': ')\n',
                },
            ]
    },
    'python': {
            'header': "# For Keystone Engine. AUTO-GENERATED FILE, DO NOT EDIT [%s_const.py]\n",
            'footer': "",
            'out_file': './python/keystone/%s_const.py',
            # prefixes for constant filenames of all archs - case sensitive
            'arm.h': 'arm',
            'arm64.h': 'arm64',
            'mips.h': 'mips',
            'x86.h': 'x86',
            'sparc.h': 'sparc',
            'riscv.h': 'riscv',
            'systemz.h': 'systemz',
            'ppc.h': 'ppc',
            'hexagon.h': 'hexagon',
            'evm.h': 'evm',
            'keystone.h': 'keystone',
            'comment_open': '#',
            'comment_close': '',
            'rules': [
                {
                    'regex': r'.*',
                    'line_format': 'KS_{0} = {1}\n',
                    'fn': (lambda x: x),
                },
            ]
        },
    'nodejs': {
            'header': "// For Keystone Engine. AUTO-GENERATED FILE, DO NOT EDIT [%s_const.js]\n",
            'footer': "",
            'out_file': './nodejs/consts/%s.js',
            # prefixes for constant filenames of all archs - case sensitive
            'arm.h': 'arm',
            'arm64.h': 'arm64',
            'mips.h': 'mips',
            'x86.h': 'x86',
            'sparc.h': 'sparc',
            'riscv.h': 'riscv',
            'systemz.h': 'systemz',
            'ppc.h': 'ppc',
            'hexagon.h': 'hexagon',
            'evm.h': 'evm',
            'keystone.h': 'keystone',
            'comment_open': '//',
            'comment_close': '',
            'rules': [
                {
                    'regex': r'.*',
                    'line_format': 'module.exports.{0} = {1}\n',
                    'fn': (lambda x: x),
                },
            ]
    },
    'ruby': {
            'header': "# For Keystone Engine. AUTO-GENERATED FILE, DO NOT EDIT [%s_const.rb]\n\nmodule Keystone\n",
            'footer': "end",
            'out_file': './ruby/keystone_gem/lib/keystone/%s_const.rb',
            # prefixes for constant filenames of all archs - case sensitive
            'arm.h': 'arm',
            'arm64.h': 'arm64',
            'mips.h': 'mips',
            'x86.h': 'x86',
            'sparc.h': 'sparc',
            'riscv.h': 'riscv.h',
            'systemz.h': 'systemz',
            'ppc.h': 'ppc',
            'hexagon.h': 'hexagon',
            'evm.h': 'evm',
            'keystone.h': 'keystone',
            'comment_open': '#',
            'comment_close': '',
            'rules': [
                {
                    'regex': r'.*',
                    'line_format': '\tKS_{0} = {1}\n',
                    'fn': (lambda x: x),
                },
            ]
    },
    'csharp': {
            'header': "// For Keystone Engine. AUTO-GENERATED FILE, DO NOT EDIT [%sConstants.cs]\nnamespace KeystoneNET\n{",
            'footer': "}",
            'out_file': './csharp/KeystoneNET/KeystoneNET/Constants/%sConstants.cs',
            # prefixes for constant filenames of all archs - case sensitive
            'keystone.h': 'keystone',
            'arm.h': 'arm',
            'arm64.h': 'arm64',
            'mips.h': 'mips',
            'x86.h': 'x86',
            'sparc.h': 'sparc',
            'riscv.h': 'riscv',
            'systemz.h': 'systemz',
            'ppc.h': 'ppc',
            'hexagon.h': 'hexagon',
            'evm.h': 'evm',
            'keystone.h': 'keystone',
            'comment_open': '//',
            'comment_close': '',
            'rules': [
                {
                    'regex': r'(ARCH)_.*',
                    'pre': '\n\tpublic enum KeystoneArchitecture : int\n\t{{\n',
                    'post': '\t}',
                    'line_format': '\t\tKS_{0} = {1},\n',
                    'fn': (lambda x: x),
                },
                {
                    'regex': r'(MODE)_.*',
                    'pre': '\n\tpublic enum KeystoneMode : uint\n\t{{\n',
                    'post': '\t}',
                    'line_format': '\t\tKS_{0} = {1},\n',
                    'fn': (lambda x: x),
                },
                {
                    'regex': r'(ERR)_.*',
                    'pre': '\n\tpublic enum {0}Error : short\n\t{{\n',
                    'post': '\t}',
                    'line_format': '\t\tKS_{0} = {1},\n',
                    'fn': (lambda x: x),
                },
                {
                    'regex': r'((OPT_([A-Z]+))|(OPT_SYM_RESOLVER))$',
                    'pre': '\n\tpublic enum KeystoneOptionType : short\n\t{{\n',
                    'post': '\t}',
                    'line_format': '\t\tKS_{0} = {1},\n',
                    'fn': (lambda x: x),
                },
                {
                    'regex': r'OPT_(?!SYM)([A-Z]+\_)+[A-Z]+',
                    'pre': '\n\tpublic enum KeystoneOptionValue : short\n\t{{\n',
                    'post': '\t}',
                    'line_format': '\t\tKS_{0} = {1},\n',
                    'fn': (lambda x: x),
                },
            ]
    },
}

# markup for comments to be added to autogen files
MARKUP = '//>'

def gen(lang):
    global include, INCL_DIR

    consts = {}

    templ = template[lang]
    for target in include:
        if target not in templ:
            continue
        prefix = templ[target]
        if target == 'keystone.h':
            prefix = 'keystone'
        lines = open(os.path.join(INCL_DIR, target)).readlines()

        consts[prefix] = []

        previous = {}
        count = 0
        for line in lines:
            line = line.strip()

            if line.startswith(MARKUP):  # markup for comments
                outfile.write(("\n%s%s%s\n" %(templ['comment_open'], \
                            line.replace(MARKUP, ''), templ['comment_close'])).encode("utf-8"))
                continue

            if line == '' or line.startswith('//'):
                continue

            tmp = line.strip().split(',')
            for t in tmp:
                t = t.strip()
                if not t or t.startswith('//'): continue
                f = re.split('\s+', t)

                # parse #define KS_TARGET (num)
                define = False
                if f[0] == '#define' and len(f) >= 3:
                    define = True
                    f.pop(0)
                    f.insert(1, '=')

                # if f[0].startswith("KS_" + prefix.upper()):
                if f[0].startswith("KS_"):
                    if len(f) > 1 and f[1] not in ('//', '='):
                        print("WARNING: Unable to convert %s" % f)
                        print("  Line =", line)
                        continue
                    elif len(f) > 1 and f[1] == '=':
                        rhs = ''.join(f[2:])
                    else:
                        rhs = str(count)

                    lhs = f[0].strip()
                    # evaluate bitshifts in constants e.g. "KS_X86 = 1 << 1"
                    match = re.match(r'(?P<rhs>\s*\d+\s*<<\s*\d+\s*)', rhs)
                    if match:
                        rhs = str(eval(match.group(1)))
                    else:
                        # evaluate references to other constants e.g. "KS_ARM_REG_X = KS_ARM_REG_SP"
                        match = re.match(r'^([^\d]\w+)$', rhs)
                        if match:
                            try:
                                rhs = previous[match.group(1)]
                            except:
                                rhs = match.group(1)

                    if not rhs.isdigit():
                        for k, v in previous.items():
                            rhs = re.sub(r'\b%s\b' % k, v, rhs)
                        try:
                            rhs = str(eval(rhs))
                        except:
                            rhs = ks_err_val[rhs]

                    lhs_strip = re.sub(r'^KS_', '', lhs)
                    consts[prefix].append((lhs_strip, rhs))

                    count = int(rhs) + 1

                    previous[lhs] = str(rhs)


    rules = templ['rules']

    for prefix in consts.keys():
        outfile = open(templ['out_file'] % prefix, 'wb')   # open as binary prevents windows newlines
        outfile.write (str.encode(templ['header'] % prefix))

        for rule in rules:
            regex = rule['regex']

            consts2 = []
            for const in consts.get(prefix):
                if not (re.match(regex, const[0])):
                    continue

                consts2.append(const)

            if len(consts2) == 0:
                continue

            if rule.get('pre'):
                outfile.write(str.encode(rule.get('pre').format(CamelCase(prefix))))

            for const in consts2:
                lhs_strip = const[0]
                rhs = const[1]
                outfile.write(rule['line_format'].format(rule['fn'](lhs_strip), rhs, lhs_strip).encode("utf-8"))

            if rule.get('post'):
                outfile.write(str.encode (rule.get('post')))
                outfile.write(str.encode ('\n'))

        outfile.write(str.encode(templ['footer']))
        outfile.close()

def main():
    lang = sys.argv[1]
    if not lang in template:
        raise RuntimeError("Unsupported binding %s" % lang)
    gen(sys.argv[1])

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:", sys.argv[0], " <python>")
        sys.exit(1)
    main()
