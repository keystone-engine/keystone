#!/bin/sh

echo "::X86-32"
kstool x32 "add eax, ecx"
# encoding: [0x01,0xc8]
echo

echo "::X86-64"
kstool x64 "add rax, rcx"
#encoding: [0x48,0x01,0xc8]
echo

echo "::X86-32 ATT"
kstool x32att "add %ecx, %eax"
# encoding: [0x01,0xc8]
echo

echo "::X86-64 ATT"
kstool x64att "add %rcx, %rax"
#encoding: [0x48,0x01,0xc8]
echo

echo "::Arm"
kstool arm "sub r1, r2, r5"
#encoding: [0x05,0x10,0x42,0xe0]
echo

echo "::Arm BE"
kstool armbe "sub r1, r2, r5"
#encoding: [0x05,0x10,0x42,0xe0]
echo

echo "::Thumb LE"
kstool thumb "movs r4, #0xf0"
#encoding: [0xf0,0x24]
echo

echo "::Thumb BE"
kstool thumbbe "movs r4, #0xf0"
#encoding: [0x24,0xf0]
echo

echo "::Arm64 BE"
kstool arm64be "ldr w1, [sp, #0x8]" 
#encoding: [0xe1,0x0b,0x40,0xb9]
echo

echo "::Sparc BE"
kstool sparcbe "add %g1, %g2, %g3"
#encoding: [0x86,0x00,0x40,0x02]
echo

echo "::Sparc LE"
kstool sparc "add %g1, %g2, %g3"
#encoding: [0x02,0x40,0x00,0x86]
echo

echo "::Mips BE"
kstool mipsbe "and \$9, \$6, \$7" 
#encoding: [0x00,0xc7,0x48,0x24]
echo

echo "::Mips LE"
kstool mips "and \$9, \$6, \$7" 
#encoding: [0x24,0x48,0xc7,0x00]
echo

echo "::Mips64 LE"
kstool mips64 "and    \$9, \$6, \$7"
#encoding: [0x24,0x48,0xc7,0x00]
echo

echo "::Mips64 BE"
kstool mips64be "and    \$9, \$6, \$7"
#encoding: [0x00,0xc7,0x48,0x24]
echo

echo "::SystemZ"
kstool systemz "a %r0, 4095(%r15,%r1)"
#encoding: [0x5a,0x0f,0x1f,0xff]
echo

echo "::Hexagon"
kstool hex "v23.w=vavg(v11.w,v2.w):rnd"
#encoding: [0xd7,0xcb,0xe2,0x1c]
echo

echo "::PPC BE"
kstool ppc32be "add 1, 2, 3"
#encoding: [0x7c,0x22,0x1a,0x14]
echo

echo "::PPC64 LE"
kstool ppc64 "add 1, 2, 3"
#encoding: [0x14,0x1a,0x22,0x7c]
echo

echo "::PPC64 BE"
kstool ppc64be "add 1, 2, 3"
#encoding: [0x7c,0x22,0x1a,0x14]
echo
