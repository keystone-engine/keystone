var extend = require('util')._extend,
    archs = ['arm64', 'arm', 'hexagon', 'mips', 'ppc', 'sparc', 'systemz', 'x86'],
    i

module.exports = require('./keystone')

for (i = 0; i < archs.length; ++i) {
    extend(module.exports, require('./' + archs[i]));
}
