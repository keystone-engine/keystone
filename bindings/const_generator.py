# Keystone Engine
# Adapted from the code of Dang Hoang Vu for Capstone Engine, 2013
from __future__ import print_function
import sys, re, os

INCL_DIR = os.path.join('..', 'include', 'keystone')

# NOTE: this reflects the value of KS_ERR_ASM_xxx in keystone.h
ks_err_val = { 'KS_ERR_ASM': '128', 'KS_ERR_ASM_ARCH': '512' }

include = [ 'arm.h', 'arm64.h', 'mips.h', 'x86.h', 'sparc.h', 'ppc.h', 'systemz.h', 'hexagon.h', 'keystone.h' ]

def CamelCase(s):
    # return re.sub(r'(\w)+\_?', lambda m:m.group(0).capitalize(), s)
    return ''.join(''.join([w[0].upper(), w[1:].lower()]) for w in s.split('_'))

template = {
    'rust': {
            'header': "// For Keystone Engine. AUTO-GENERATED FILE, DO NOT EDIT [%s_const.rs]\n",
            'footer': "",
            #'line_format': 'pub const KS_%s : u32 = %s;\n',
            #'out_file': './rust/src/%s_const.rs',
            # prefixes for constant filenames of all archs - case sensitive
            'arm.h': 'arm',
            'arm64.h': 'arm64',
            'mips.h': 'mips',
            'x86.h': 'x86',
            'sparc.h': 'sparc',
            'systemz.h': 'systemz',
            'ppc.h': 'ppc',
            'hexagon.h': 'hexagon',
            'keystone.h': 'keystone',
            'comment_open': '/*',
            'comment_close': '*/',
            'rules': [
                {
                    'regex': r'.*',
                    'pre': '\n',
                    'line_format': 'pub const KS_{0} : u32 = {1};\n',
                    'fn': (lambda x: x),
                    'post': '\n',
                    #'filename': './rust/src/keystone_const.rs'
                    'filename': './rust/src/%s_const.rs',
                },
                {
                    'regex': r'ARCH_.*',
                    'pre': '#[derive(Debug, PartialEq, Clone, Copy)]\n' + 
                            'pub enum Arch {\n',
                    'line_format': '\t{0},\n',
                    'fn': (lambda x: '_'.join(x.split('_')[1:])),
                    'post': '}\n\n',
                    'filename': './rust/src/%s_const.rs',
                },
                {   'regex': r'ARCH_.*',
                    'pre': 'impl Arch {\n\t#[inline]\n\tpub fn val(&self) -> u32 {\n\t\tmatch *self {\n',
                    'line_format': '\t\t\tArch::{0} => {1},\n',
                    'fn': (lambda x: '_'.join(x.split('_')[1:])),
                    'post': '\t\t}\n\t}\n}\n',
                    'filename': './rust/src/%s_const.rs',
                },
                {
                    'regex': r'OPT_([A-Z]+)$',
                    'pre': '#[derive(Debug, PartialEq, Clone, Copy)]\n' + 
                            'pub enum OptionType {\n',
                    'line_format': '\t{0},\n',
                    'fn': (lambda x: '_'.join(x.split('_')[1:])),
                    'post': '\tMAX,\n' +
                            '}\n',
                    'filename': './rust/src/%s_const.rs',
                },
                {   
                    'regex': r'OPT_([A-Z]+)$',
                    'pre': 'impl OptionType {\n\t#[inline]\n\tpub fn val(&self) -> u32 {\n\t\tmatch *self {\n',
                    'line_format': '\t\t\tOptionType::{0} => {1},\n',
                    'fn': (lambda x: '_'.join(x.split('_')[1:])),
                    'post': '\t\t\tOptionType::MAX => 99\n' +
                            '\t\t}\n\t}\n}\n',
                    'filename': './rust/src/%s_const.rs',
                },
                {
                    'regex': r'OPT_([A-Z]+\_)+[A-Z]+',
                    'pre': '#[derive(Debug, PartialEq, Clone, Copy)]\n' + 
                            'pub enum OptionValue {\n',
                    'line_format': '\t{0},\n',
                    'fn': (lambda x: '_'.join(x.split('_')[1:])),
                    'post': '}\n',
                    'filename': './rust/src/%s_const.rs',
                },
                {   
                    'regex': r'OPT_([A-Z]+\_)+[A-Z]+',
                    'pre': 'impl OptionValue {\n\t#[inline]\n\tpub fn val(&self) -> u32 {\n\t\tmatch *self {\n',
                    'line_format': '\t\t\tOptionValue::{0} => {1},\n',
                    'fn': (lambda x: '_'.join(x.split('_')[1:])),
                    'post': '\t\t}\n\t}\n}\n',
                    'filename': './rust/src/%s_const.rs',
                },
                {
                    'regex': r'ERR_.*',
                    'pre': '#[derive(Debug, PartialEq, Clone, Copy)]\n' + 
                            'pub enum Error {\n',
                    'line_format': '\t{0},\n',
                    'fn': (lambda x: '_'.join(x.split('_')[1:])),
                    'post': '\tUNKNOWN,\n' +
                            '}\n',
                    'filename': './rust/src/%s_const.rs',
                },
                {   'regex': r'ERR_.*',
                    'pre': 'impl Error {\n\t#[inline]\n\tpub fn from_val(v: u32) -> Error {\n\t\tmatch v {\n',
                    'line_format': '\t\t\t{1} => Error::{0},\n',
                    'fn': (lambda x: '_'.join(x.split('_')[1:])),
                    'post': '\t\t\t_ => Error::UNKNOWN,\n\t\t}\n\t}\n}\n',
                    'filename': './rust/src/%s_const.rs',
                },
                {   'regex': r'ERR_.*',
                    'pre': 'impl Error {\n\t#[inline]\n\tpub fn to_val(&self) -> u32 {\n\t\tmatch *self {\n',
                    'line_format': '\t\t\tError::{0} => {1},\n',
                    'fn': (lambda x: '_'.join(x.split('_')[1:])),
                    'post': '\t\t}\n\t}\n}\n',
                    'filename': './rust/src/%s_const.rs',
                },
            ],
    },
    'go': {
            'header': "package keystone\n// For Keystone Engine. AUTO-GENERATED FILE, DO NOT EDIT [keystone_constants_%s.go]\n",
            'footer': "",
            'line_format': 'const KS_%s = %s\n',
            'out_file': './go/keystone/keystone_constants_%s.go',
            # prefixes for constant filenames of all archs - case sensitive
            'arm.h': 'arm',
            'arm64.h': 'arm64',
            'mips.h': 'mips',
            'x86.h': 'x86',
            'sparc.h': 'sparc',
            'systemz.h': 'systemz',
            'ppc.h': 'ppc',
            'hexagon.h': 'hexagon',
            'keystone.h': 'keystone',
            'comment_open': '/*',
            'comment_close': '*/',
    },
    'python': {
            'header': "# For Keystone Engine. AUTO-GENERATED FILE, DO NOT EDIT [%s_const.py]\n",
            'footer': "",
            'line_format': 'KS_%s = %s\n',
            'out_file': './python/keystone/%s_const.py',
            # prefixes for constant filenames of all archs - case sensitive
            'arm.h': 'arm',
            'arm64.h': 'arm64',
            'mips.h': 'mips',
            'x86.h': 'x86',
            'sparc.h': 'sparc',
            'systemz.h': 'systemz',
            'ppc.h': 'ppc',
            'hexagon.h': 'hexagon',
            'keystone.h': 'keystone',
            'comment_open': '#',
            'comment_close': '',
        },
    'nodejs': {
            'header': "// For Keystone Engine. AUTO-GENERATED FILE, DO NOT EDIT [%s_const.js]\n",
            'footer': "",
            'line_format': 'module.exports.%s = %s\n',
            'out_file': './nodejs/consts/%s.js',
            # prefixes for constant filenames of all archs - case sensitive
            'arm.h': 'arm',
            'arm64.h': 'arm64',
            'mips.h': 'mips',
            'x86.h': 'x86',
            'sparc.h': 'sparc',
            'systemz.h': 'systemz',
            'ppc.h': 'ppc',
            'hexagon.h': 'hexagon',
            'keystone.h': 'keystone',
            'comment_open': '//',
            'comment_close': '',
    },
    'ruby': {
            'header': "# For Keystone Engine. AUTO-GENERATED FILE, DO NOT EDIT [%s_const.rb]\n\nmodule Keystone\n",
            'footer': "end",
            'line_format': '\tKS_%s = %s\n',
            'out_file': './ruby/keystone_gem/lib/keystone/%s_const.rb',
            # prefixes for constant filenames of all archs - case sensitive
            'arm.h': 'arm',
            'arm64.h': 'arm64',
            'mips.h': 'mips',
            'x86.h': 'x86',
            'sparc.h': 'sparc',
            'systemz.h': 'systemz',
            'ppc.h': 'ppc',
            'hexagon.h': 'hexagon',
            'keystone.h': 'keystone',
            'comment_open': '#',
            'comment_close': '',
    },
}

# markup for comments to be added to autogen files
MARKUP = '//>'

def gen(lang):
    global include, INCL_DIR
    templ = template[lang]
    for target in include:
        prefix = templ[target]
        if target == 'keystone.h':
            prefix = ''
        lines = open(os.path.join(INCL_DIR, target)).readlines()

        consts = []

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
                    consts.append((lhs_strip, rhs))

                    count = int(rhs) + 1

                    #if (count == 1):
                    #    outfile.write(("\n").encode("utf-8"))
                    #print (lhs_strip)

                    #outfile.write((templ['line_format'] % (lhs_strip, rhs)).encode("utf-8"))
                    previous[lhs] = str(rhs)

        rules = templ['rules']

        for rule in rules:
            regex = rule['regex']

            outfile = open(rule['filename'] % prefix, 'a+b')   # open as binary prevents windows newlines
            outfile.write (templ['header'])
            outfile.write (rule['pre'])
            for const in consts:
                if not (re.match(regex, const[0])):
                    continue

                lhs_strip = const[0]
                rhs = const[1]
                outfile.write(rule['line_format'].format(rule['fn'](lhs_strip), rhs, lhs_strip).encode("utf-8"))

            outfile.write (rule['post'])
            outfile.write ('\n')
            outfile.write (templ['footer'])
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
