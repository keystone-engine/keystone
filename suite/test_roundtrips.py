#!/usr/bin/python
# encoding: utf-8

from __future__ import unicode_literals

from capstone import *
from keystone import *

roundtrip_tests = [
    ("x64", "adc qword ptr [edx + r12d*2], r8"),
    ("x64", "add qword ptr [ecx + 0x66ccefe4], r11"),
    ("x64", "and rax, 0xffffffffcf6f1a35"),
    ("x64", "cmp qword ptr [r9d - 0x1f6968e2], rbx"),
    ("x64", "cmpsq qword ptr gs:[rsi], qword ptr [rdi]"),
    ("x64", "div qword ptr cs:[r14d - 0x7c]"),
    ("x64", "imul r14, qword ptr [r10d - 0x42bcfafd], 0x71"),
    ("x64", "lodsq rax, qword ptr es:[rsi]"),
    ("x64", "mov r10, qword ptr cs:[r10d - 0x77]"),
    ("x64", "movabs rax, qword ptr fs:[0x21bd3b669c88595f]"),
    ("x64", "movsq qword ptr [rdi], qword ptr fs:[rsi]"),
    ("x64", "or rax, 0xffffffffd8751dd5"),
    ("x64", "push 0xe269eeca"),
    ("x64", "rcl qword ptr ss:[r10d + 0x23], -3"),
    ("x64", "rep lodsq rax, qword ptr es:[rsi]"),
    ("x64", "repe scasq rax, qword ptr [edi]"),
    ("x64", "repne cmpsq qword ptr ss:[rsi], qword ptr [rdi]"),
    ("x64", "sar qword ptr [esi + 0x29], 0xf"),
    ("x64", "sbb qword ptr [eax - 0x49], r8"),
    ("x64", "scasq rax, qword ptr [edi]"),
    ("x64", "stosq qword ptr [edi], rax"),
    ("x64", "sub rcx, qword ptr [eax + 0x38]"),
    ("x64", "test edi, ebx"),
    ("x64", "vaddpd zmm21 {k1} {z}, zmm11, zmmword ptr [rdx + 0x1bc0]"),
    ("x64", "vpminsd zmm4 {k1} {z}, zmm25, zmmword ptr [r8 + 0x1d80]"),
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
