# RUN: llvm-mc %s -triple=csky -show-encoding -csky-no-aliases -mattr=+e1 \
# RUN: -mattr=+e2 -mattr=+btst16 | FileCheck -check-prefixes=CHECK-ASM,CHECK-ASM-AND-OBJ %s
# RUN: llvm-mc -filetype=obj -triple=csky -mattr=+e1 -mattr=+e2 -mattr=+btst16 < %s \
# RUN:     | llvm-objdump --mattr=+e1 --mattr=+e2 --mattr=+btst16 -M no-aliases -M abi-names -d -r - \
# RUN:     | FileCheck -check-prefixes=CHECK-ASM-AND-OBJ,CHECK-OBJ %s

# CHECK-ASM-AND-OBJ: addi16 a0, a0, 2
# CHECK-ASM: encoding: [0x06,0x58]
addi16 a0, a0, 2

# CHECK-ASM-AND-OBJ: addi16 a0, sp, 4
# CHECK-ASM: encoding: [0x01,0x18]
addi16 a0, sp, 4

# CHECK-ASM-AND-OBJ: addi16 a0, a1, 2
# CHECK-ASM: encoding: [0x06,0x59]
addi16 a0, a1, 2

# CHECK-ASM-AND-OBJ: addi16 sp, sp, 8
# CHECK-ASM: encoding: [0x02,0x14]
addi16 sp, sp, 8

# CHECK-ASM-AND-OBJ: subi16 a0, a0, 2
# CHECK-ASM: encoding: [0x07,0x58]
subi16 a0, a0, 2

# CHECK-ASM-AND-OBJ: subi16 a0, a1, 2
# CHECK-ASM: encoding: [0x07,0x59]
subi16 a0, a1, 2

# CHECK-ASM-AND-OBJ: subi16 sp, sp, 8
# CHECK-ASM: encoding: [0x22,0x14]
subi16 sp, sp, 8

# CHECK-ASM-AND-OBJ: lsli16 a0, a1, 2
# CHECK-ASM: encoding: [0x02,0x41]
lsli16 a0, a1, 2

# CHECK-ASM-AND-OBJ: lsri16 a0, a1, 2
# CHECK-ASM: encoding: [0x02,0x49]
lsri16 a0, a1, 2

# CHECK-ASM-AND-OBJ: asri16 a0, a1, 2
# CHECK-ASM: encoding: [0x02,0x51]
asri16 a0, a1, 2

# CHECK-ASM-AND-OBJ: btsti16 a0, 2
# CHECK-ASM: encoding: [0xc2,0x38]
btsti16 a0, 2

# CHECK-ASM-AND-OBJ: bclri16 a0, 2
# CHECK-ASM: encoding: [0x82,0x38]
bclri16 a0, 2

# CHECK-ASM-AND-OBJ: bseti16 a0, 2
# CHECK-ASM: encoding: [0xa2,0x38]
bseti16 a0, 2

# CHECK-ASM-AND-OBJ: cmpnei16 a0, 2
# CHECK-ASM: encoding: [0x42,0x38]
cmpnei16 a0, 2

# CHECK-ASM-AND-OBJ: cmphsi16 a0, 2
# CHECK-ASM: encoding: [0x01,0x38]
cmphsi16 a0, 2

# CHECK-ASM-AND-OBJ: cmplti16 a0, 2
# CHECK-ASM: encoding: [0x21,0x38]
cmplti16 a0, 2

# CHECK-ASM-AND-OBJ: movi16 a0, 2
# CHECK-ASM: encoding: [0x02,0x30]
movi16 a0, 2

# CHECK-ASM-AND-OBJ: addu16 a3, l0, l1
# CHECK-ASM: encoding: [0x74,0x5c]
addu16 a3, l0, l1

# CHECK-ASM-AND-OBJ: subu16 a3, l0, l1
# CHECK-ASM: encoding: [0x75,0x5c]
subu16 a3, l0, l1

# CHECK-ASM-AND-OBJ: and16 a3, l0
# CHECK-ASM: encoding: [0xd0,0x68]
and16 a3, l0

# CHECK-ASM-AND-OBJ: andn16 a3, l0
# CHECK-ASM: encoding: [0xd1,0x68]
andn16 a3, l0

# CHECK-ASM-AND-OBJ: or16 a3, l0
# CHECK-ASM: encoding: [0xd0,0x6c]
or16 a3, l0

# CHECK-ASM-AND-OBJ: xor16 a3, l0
# CHECK-ASM: encoding: [0xd1,0x6c]
xor16 a3, l0

# CHECK-ASM-AND-OBJ: nor16 a3, l0
# CHECK-ASM: encoding: [0xd2,0x6c]
nor16 a3, l0

# CHECK-ASM-AND-OBJ: lsl16 a3, l0
# CHECK-ASM: encoding: [0xd0,0x70]
lsl16 a3, l0

# CHECK-ASM-AND-OBJ: rotl16 a3, l0
# CHECK-ASM: encoding: [0xd3,0x70]
rotl16 a3, l0

# CHECK-ASM-AND-OBJ: lsr16 a3, l0
# CHECK-ASM: encoding: [0xd1,0x70]
lsr16 a3, l0

# CHECK-ASM-AND-OBJ: asr16 a3, l0
# CHECK-ASM: encoding: [0xd2,0x70]
asr16 a3, l0

# CHECK-ASM-AND-OBJ: mult16 a3, l0
# CHECK-ASM: encoding: [0xd0,0x7c]
mult16 a3, l0

# CHECK-ASM-AND-OBJ: addc16 a3, l0
# CHECK-ASM: encoding: [0xd1,0x60]
addc16 a3, l0

# CHECK-ASM-AND-OBJ: subc16 a3, l0
# CHECK-ASM: encoding: [0xd3,0x60]
subc16 a3, l0

# CHECK-OBJ: ld16.b a0, (a0, 0x2)
# CHECK-ASM: ld16.b a0, (a0, 2)
# CHECK-ASM: encoding: [0x02,0x80]
ld16.b a0, (a0, 2)

# CHECK-OBJ: ld16.h a0, (a0, 0x2)
# CHECK-ASM: ld16.h a0, (a0, 2)
# CHECK-ASM: encoding: [0x01,0x88]
ld16.h a0, (a0, 2)

# CHECK-OBJ: ld16.w a0, (a0, 0x4)
# CHECK-ASM: ld16.w a0, (a0, 4)
# CHECK-ASM: encoding: [0x01,0x90]
ld16.w a0, (a0, 4)

# CHECK-OBJ: ld16.w a0, (sp, 0x4)
# CHECK-ASM: ld16.w a0, (sp, 4)
# CHECK-ASM: encoding: [0x01,0x98]
ld16.w a0, (sp, 4)

# CHECK-OBJ: st16.b a0, (a0, 0x2)
# CHECK-ASM: st16.b a0, (a0, 2)
# CHECK-ASM: encoding: [0x02,0xa0]
st16.b a0, (a0, 2)

# CHECK-OBJ: st16.h a0, (a0, 0x2)
# CHECK-ASM: st16.h a0, (a0, 2)
# CHECK-ASM: encoding: [0x01,0xa8]
st16.h a0, (a0, 2)

# CHECK-OBJ: st16.w a0, (a0, 0x4)
# CHECK-ASM: st16.w a0, (a0, 4)
# CHECK-ASM: encoding: [0x01,0xb0]
st16.w a0, (a0, 4)

# CHECK-OBJ: st16.w a0, (sp, 0x4)
# CHECK-ASM: st16.w a0, (sp, 4)
# CHECK-ASM: encoding: [0x01,0xb8]
st16.w a0, (sp, 4)

# CHECK-ASM-AND-OBJ: revb16 a3, l0
# CHECK-ASM: encoding: [0xd2,0x78]
revb16 a3, l0

# CHECK-ASM-AND-OBJ: revh16 a3, l0
# CHECK-ASM: encoding: [0xd3,0x78]
revh16 a3, l0

# CHECK-ASM-AND-OBJ: mvcv16 a3
# CHECK-ASM: encoding: [0xc3,0x64]
mvcv16 a3

# CHECK-ASM-AND-OBJ: cmpne16 a3, l0
# CHECK-ASM: encoding: [0x0e,0x65]
cmpne16 a3, l0

# CHECK-ASM-AND-OBJ: cmphs16 a3, l0
# CHECK-ASM: encoding: [0x0c,0x65]
cmphs16 a3, l0

# CHECK-ASM-AND-OBJ: cmplt16 a3, l0
# CHECK-ASM: encoding: [0x0d,0x65]
cmplt16 a3, l0

# CHECK-ASM-AND-OBJ: tst16 a3, l0
# CHECK-ASM: encoding: [0x0e,0x69]
tst16 a3, l0

# CHECK-ASM-AND-OBJ: tstnbz16 a3
# CHECK-ASM: encoding: [0x0f,0x68]
tstnbz16 a3

# CHECK-ASM: br16 .L.test
# CHECK-ASM: encoding: [A,0x04'A']
.L.test:
br16 .L.test

# CHECK-ASM: bt16 .L.test2
# CHECK-ASM: encoding: [A,0x08'A']
.L.test2:
bt16 .L.test2

# CHECK-ASM: bf16 .L.test3
# CHECK-ASM: encoding: [A,0x0c'A']
.L.test3:
bf16 .L.test3

# CHECK-ASM-AND-OBJ: jmp16 a3
# CHECK-ASM: encoding: [0x0c,0x78]
jmp16 a3

# CHECK-ASM-AND-OBJ: jsr16 a3
# CHECK-ASM: encoding: [0xcd,0x7b]
jsr16 a3
