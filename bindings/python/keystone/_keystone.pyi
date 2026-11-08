import enum
from collections.abc import Callable
from types import TracebackType
from typing import Final, final

from _typeshed import structseq

__version__: Final[str]

class Arch(enum.IntEnum):
   AARCH64 = 1
   AMDGPU = 2
   ARM = 3
   AVR = 4
   BPF = 5
   CSKY = 6
   EVM = 7
   LANAI = 8
   LOONGARCH = 9
   HEXAGON = 10
   M68K = 11
   MIPS = 12
   MSP430 = 13
   PPC = 14
   RISCV = 15
   SPARC = 16
   SYSTEMZ = 17
   THUMB = 18
   VE = 19
   WASM = 20
   X86 = 21
   X64 = 22
   XTENSA = 23

class Width(enum.IntEnum):
   W16 = 16
   W32 = 32
   W64 = 64

class ArchVariant(enum.IntFlag):
   NONE = 0
   ARM_V7 = 1
   ARM_MCLASS = 2
   ARM_EM = 4
   THUMB_V7 = 1
   THUMB_MCLASS = 2
   THUMB_EM = 4

class Endian(enum.IntEnum):
   LITTLE = 1
   BIG = 2

class KsErr(enum.IntEnum):
   OK = 0
   MEM = 1
   HANDLE = 2
   ARCH = 3
   ENDIAN = 4
   WIDTH = 5
   FEATURE = 6
   CPU = 7
   VERSION = 8
   OPT_INVALID = 9
   ASM_SYNTAX = 10
   ASM_INVALID_TOKEN = 11
   ASM_INVALID_DIRECTIVE = 12
   ASM_MISSING_SYMBOL = 13
   ASM_INVALID_SYMBOL = 14
   ASM_MACRO_ERROR = 15
   ASM_INSN_UNSUPPORTED = 16
   ASM_EXPR_ERROR = 17
   ASM_FIXUP_INVALID = 18
   ASM_LABEL_INVALID = 19
   ASM_INVALID_OPERAND = 20
   ASM_MISSING_FEATURE = 21
   ASM_MNEMONIC_FAIL = 22

class X86Syntax(enum.IntEnum):
   ATT = 0
   INTEL = 1
   NASM = 2

class Radix(enum.IntEnum):
   BINARY = 2
   OCTAL = 8
   DECIMAL = 10
   HEXADECIMAL = 16
   BASE36 = 36

class ArmItMode(enum.IntEnum):
   ALWAYS = 0
   NEVER = 1
   ARM_ONLY = 2
   THUMB_ONLY = 3

@final
class ErrorLocation(structseq[int | str], tuple[int, int, str]):
   __match_args__: Final = ("line", "column", "message")
   @property
   def line(self) -> int: ...
   @property
   def column(self) -> int: ...
   @property
   def message(self) -> str: ...

@final
class Assembly(structseq[bytes | int], tuple[bytes, int]):
   __match_args__: Final = ("bytes", "stat_count")
   @property
   def bytes(self) -> bytes: ...
   @property
   def stat_count(self) -> int: ...

class KeystoneError(Exception):
   code: KsErr
   locations: list[ErrorLocation]

def version() -> tuple[int, int]: ...
def arch_supported(arch: Arch) -> bool: ...

@final
class Keystone:
   def __new__(cls, arch: Arch) -> Keystone: ...
   def __enter__(self) -> Keystone: ...
   def __exit__(
      self,
      exc_type: type[BaseException] | None,
      exc: BaseException | None,
      traceback: TracebackType | None,
   ) -> None: ...
   def close(self) -> None: ...
   def asm(self, code: str | bytes, address: int = 0) -> Assembly: ...
   arch: Arch
   endian: Endian
   width: Width
   arch_variant: ArchVariant
   x86_syntax: X86Syntax
   radix: Radix
   arm_it_mode: ArmItMode
   csky_compressed: bool
   feature: str
   cpu: str
   symbol_resolver: Callable[[str], int | None] | None
