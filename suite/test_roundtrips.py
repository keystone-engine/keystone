#!/usr/bin/python
# encoding: utf-8

from __future__ import unicode_literals

from capstone import *
from keystone import *

roundtrip_tests = [
    ("x64", "adc qword ptr [edx + r12d*2], r8"),
    ("x64", "add qword ptr [ecx + 0x66ccefe4], r11"),
    ("x64", "and rax, 0xffffffffcf6f1a35"),
    ("x64", "cmovns rdi, qword ptr [r15d + esi*4 - 1]"),
    ("x64", "cmp qword ptr [r9d - 0x1f6968e2], rbx"),
    ("x64", "cmpsq qword ptr gs:[rsi], qword ptr [rdi]"),
    ("x64", "dec qword ptr [r15d]"),
    ("x64", "div qword ptr cs:[r14d - 0x7c]"),
    ("x64", "imul r14, qword ptr [r10d - 0x42bcfafd], 0x71"),
    ("x64", "lock xchg qword ptr [r8d + 0x24], rsi"),
    ("x64", "lodsq rax, qword ptr es:[rsi]"),
    ("x64", "mov r10, qword ptr cs:[r10d - 0x77]"),
    ("x64", "movabs rax, qword ptr fs:[0x21bd3b669c88595f]"),
    ("x64", "movsq qword ptr [rdi], qword ptr fs:[rsi]"),
    ("x64", "movsxd r11, dword ptr cs:[eax - 0x206b31ee]"),
    ("x64", "mul qword ptr gs:[eax - 0x34]"),
    ("x64", "neg qword ptr [r8d + 0x4d18b551]"),
    ("x64", "or rax, 0xffffffffd8751dd5"),
    ("x64", "push 0xe269eeca"),
    ("x64", "rcl qword ptr ss:[r10d + 0x23], -3"),
    ("x64", "rcr qword ptr [esi + 0xf], -9"),
    ("x64", "rep lodsq rax, qword ptr es:[rsi]"),
    ("x64", "repe scasq rax, qword ptr [edi]"),
    ("x64", "repne cmpsq qword ptr ss:[rsi], qword ptr [rdi]"),
    ("x64", "rol qword ptr [r14d + 0x76], 0x5c"),
    ("x64", "ror qword ptr [ebp + 0x67217b00], -0x69"),
    ("x64", "sar qword ptr [esi + 0x29], 0xf"),
    ("x64", "sbb qword ptr [eax - 0x49], r8"),
    ("x64", "scasq rax, qword ptr [edi]"),
    ("x64", "shl qword ptr [eax], cl"),
    ("x64", "shr qword ptr [esi + 0x6a], 5"),
    ("x64", "stosq qword ptr [edi], rax"),
    ("x64", "sub rcx, qword ptr [eax + 0x38]"),
    ("x64", "test edi, ebx"),
    ("x64", "vaddpd zmm21 {k1} {z}, zmm11, zmmword ptr [rdx + 0x1bc0]"),
    ("x64", "vaddps zmm3 {k7} {z}, zmm18, dword ptr [r15 + xmm6*4 + 0x1f0]{1to16}"),
    ("x64", "vcvtsd2si edi, qword ptr [rbp + 0x18]"),
    ("x64", "vcvtss2si r9d, dword ptr [rdx - 0x64]"),
    ("x64", "vmaxpd zmm27 {k3}, zmm9, zmmword ptr [r15 - 0xc00]"),
    ("x64", "vmaxps zmm0 {k2} {z}, zmm8, zmmword ptr [r9 - 0x1b40]"),
    ("x64", "vminps zmm2 {k6} {z}, zmm18, dword ptr [r14 - 0x1e4]{1to16}"),
    ("x64", "vpandnq zmm19 {k7} {z}, zmm28, zmmword ptr [rax + xmm5*2 + 0xb00]"),
    ("x64", "vpermi2pd zmm30 {k2} {z}, zmm19, zmmword ptr [rcx + 0x200]"),
    ("x64", "vpermi2ps zmm3 {k3} {z}, zmm28, zmmword ptr [r8 + 0xcc0]"),
    ("x64", "vpermt2d zmm14 {k7}, zmm6, zmmword ptr [r13 + 0x1280]"),
    ("x64", "vpmaxsd zmm31 {k5}, zmm8, zmmword ptr [r8 - 0x780]"),
    ("x64", "vpmaxsq zmm16 {k7}, zmm2, qword ptr [rsi - 0x228]{1to8}"),
    ("x64", "vpminsd zmm4 {k1} {z}, zmm25, zmmword ptr [r8 + 0x1d80]"),
    ("x64", "vpminsq zmm28 {k5}, zmm28, zmmword ptr [r15 + xmm3 - 0x1400]"),
    ("x64", "vpminuq zmm21 {k2}, zmm15, zmmword ptr [r10 - 0x1300]"),
    ("x64", "vpord zmm15 {k2} {z}, zmm8, zmmword ptr [rdi + r11*4 + 0xc40]"),
    ("x64", "vporq zmm29 {k5} {z}, zmm2, zmmword ptr fs:[r11 - 0x1c40]"),
    ("x64", "vpsllq zmm21 {k2}, zmm28, xmmword ptr [rcx - 0x2b0]"),
    ("x64", "vpsravd zmm27, zmm24, zmmword ptr [r10 + 0x5c0]"),
    ("x64", "vpsrlq zmm17 {k7}, zmmword ptr [r9 - 0x1680], 0x73"),
    ("x64", "vpsubq zmm19 {k4}, zmm24, zmmword ptr [rbx + 0x10c0]"),
    ("x64", "vpxord zmm12 {k5} {z}, zmm8, zmmword ptr [rbp + 0x740]"),
    ("x64", "vpxorq zmm21 {k2}, zmm1, zmmword ptr [rbx - 0x1180]"),
    ("x64", "xchg rax, rax"),
    ("x64", "xor qword ptr [esi + 0x1df54066], 0x6c"),
]

arch_modes = {
    "x64": {
        "capstone_arch": CS_ARCH_X86, "capstone_mode": CS_MODE_64,
        "keystone_arch": KS_ARCH_X86, "keystone_mode": KS_MODE_64,
    }
}


def assemble(arch_mode, s):
    if not s:
        return b""
    ks = Ks(arch_modes[arch_mode]["keystone_arch"],
            arch_modes[arch_mode]["keystone_mode"])
    try:
        encoding, _ = ks.asm(s)
    except keystone.KsError:
        return None
    return b"".join([chr(i) for i in encoding])


def disassemble(arch_mode, b):
    cs = Cs(arch_modes[arch_mode]["capstone_arch"],
            arch_modes[arch_mode]["capstone_mode"])
    return "\n".join(["{} {}".format(i.mnemonic, i.op_str)
                      for i in cs.disasm(b, 0x0)])

if __name__ == "__main__":
    colors = {
        "bold": '\033[1m',
        "green": '\033[32m',
        "neutral": '\033[0m',
        "red": '\033[31m',
    }
    counter = 0
    counter_failed = 0
    print("")
    print("== {}keystone/capstone round-trip tests{} ==".format(
        colors["bold"], colors["neutral"]))
    print("")
    for arch_mode, assembly in roundtrip_tests:
        counter += 1
        assembled = assemble(arch_mode, assembly)
        disassembled = disassemble(arch_mode, assembled)
        reassembled = assemble(arch_mode, disassembled)
        if assembled == reassembled:
            status_color = colors["green"]
            status_marker = "✓"
            equality = "=="
        else:
            status_color = colors["red"]
            status_marker = "✘"
            equality = "!="
            counter_failed += 1
        print("  {}{}{}  [{}] asm('{}') {} asm(disasm(asm(…))) ⇔ {} {} {}".format(
            status_color, status_marker, colors["neutral"], arch_mode,
            assembly, equality, repr(assembled), equality, repr(reassembled)))
    print("")
    print("** Results: {}{}{} of {}{}{} tests failed **".format(
        colors["bold"], counter_failed, colors["neutral"],
        colors["bold"], counter, colors["neutral"]))
    print("")
