# Keystone Engine
# Adapted from the code of Dang Hoang Vu for Capstone Engine, 2013
from __future__ import print_function
import sys, re, os

INCL_DIR = os.path.join('..', 'include', 'keystone')

# NOTE: this reflects the value of KS_ERR_ASM_xxx in keystone.h
ks_err_val = { 'KS_ERR_ASM': '128', 'KS_ERR_ASM_ARCH': '512' }

include = [ 'arm.h', 'arm64.h', 'mips.h', 'x86.h', 'sparc.h', 'ppc.h', 'systemz.h', 'hexagon.h', 'keystone.h' ]

template = {
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
}

# markup for comments to be added to autogen files
MARKUP = '//>'

def gen(lang):
    global include, INCL_DIR
    templ = template[lang]
    for target in include:
        prefix = templ[target]
        outfile = open(templ['out_file'] %(prefix), 'wb')   # open as binary prevents windows newlines
        outfile.write((templ['header'] % (prefix)).encode("utf-8"))
        if target == 'keystone.h':
            prefix = ''
        lines = open(os.path.join(INCL_DIR, target)).readlines()

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
                    count = int(rhs) + 1
                    if (count == 1):
                        outfile.write(("\n").encode("utf-8"))

                    outfile.write((templ['line_format'] % (lhs_strip, rhs)).encode("utf-8"))
                    previous[lhs] = str(rhs)

        outfile.write((templ['footer']).encode("utf-8"))
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
