var keystone = require('.')  // Or: require('keystone') if you have installed it

console.log('Using keystone ' + keystone.version.major + '.' + keystone.version.minor)

var ks, assembly, result

// Check if architecture is supported
if (! keystone.is_arch_supported(keystone.ARCH_X86)) {
  throw 'Warning: X86 architecture not supported by keystone.'
}

// Create a new Keystone instance for X86 64bit
ks = new keystone.Ks(keystone.ARCH_X86, keystone.MODE_64)

// Assemble some instructions
assembly = 'inc rcx; dec rbx'
result = ks.asm(assembly)
console.log('"' + assembly + '"', ':', result.encoding)

// Change syntax, assemble some more instructions
assembly = 'lea rax, [label1]\nnop\nnop\nlabel1:'
ks.syntax = keystone.OPT_SYNTAX_NASM
result = ks.asm(assembly)
console.log('"' + assembly.replace(/\n/g, '; ') + '"', ':', result.encoding)

// Close Keystone instance to free resources
ks.close()
