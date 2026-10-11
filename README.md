# Keystone

Keystone is an assembler library. You give it a string of assembly and an
address, and it gives you back the machine code.

## Architectures

Keystone supports every architecture in LLVM. The entire list is below.

AArch64, AMDGPU, ARM and Thumb, AVR, BPF, C-SKY, EVM, Hexagon, Lanai,
LoongArch, M68k, MIPS, MSP430, PowerPC, RISC-V, SPARC, SystemZ, VE,
WebAssembly, x86, and Xtensa.

## Building

You'll need CMake, a C++17 compiler, and ideally Ninja.

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
cmake --install build
```

Every architecture is built by default, and most of the build time is LLVM.
If you only need a few, pass them to `KEYSTONE_ARCH`, e.g.
`-DKEYSTONE_ARCH="x86;aarch64;riscv"`. Set `KEYSTONE_BUILD_SHARED_LIBS=OFF`
for a static library.

With Nix, `nix build .#keystone` builds the library and `nix develop` gives
you a shell with everything needed to hack on it.

## Usage

### C

```c
#include <inttypes.h>
#include <keystone/keystone.h>
#include <stdio.h>

int main(void) {
  ks_engine *ks;
  if (ks_new(&ks, KS_ARCH_X86) != KS_ERR_OK)
    return 1;
  ks_set_width(ks, KS_WIDTH_64);

  ks_asm_result r = {0};
  if (ks_assemble(ks, "mov rax, 1; ret", 0x1000, &r) == KS_ERR_OK) {
    for (size_t i = 0; i < r.size; i++)
      printf("%02x ", r.bytes[i]);
    printf("\n");
  } else {
    for (size_t i = 0; i < r.error_count; i++)
      fprintf(stderr, "%" PRIu64 ":%" PRIu64 ": %s\n", r.errors[i].line_number,
              r.errors[i].column_number, r.errors[i].error_message);
  }

  ks_asm_result_free(&r);
  ks_delete(ks);
}
```

If you've used v1, `ks_open` and `ks_close` are now `ks_new` and `ks_delete`,
and `ks_asm` and `ks_errno` are gone. `ks_assemble` returns everything about a
call in a `ks_asm_result`, including the line and column of every error rather
than just the first, and nothing is left behind in the engine between calls.
Options also have their own setters now, like `ks_set_width` and
`ks_set_x86_syntax`, instead of going through `ks_option`.

### Rust

```toml
[dependencies]
keystone-engine = { git = "https://github.com/keystone-engine/keystone" }
```

```rust
use keystone_engine::{Arch, Keystone, X86Syntax};

let mut engine = Keystone::new(Arch::X86)?;
engine.set_x86_syntax(X86Syntax::NASM)?;

let asm = engine.asm("mov ah, 0x80", 0)?;
assert_eq!(asm.bytes, [0xb4, 0x80]);
```

The crate is `no_std`. If you already have Keystone 2 installed, it'll link
against that through `pkg-config`, and otherwise it builds Keystone from source.

Every architecture is behind a Cargo feature, and all of them except AMDGPU are
on by default. AMDGPU alone is over half the library, so it's opt-in with
`arch_amdgpu`. If you only need one or two architectures, turning off the
defaults does make a big difference: an x86-only build is around 3.5 MB,
compared to 13 MB with the defaults. Keystone is linked statically unless you
enable `dynamic_linkage`.

## Testing

The test suite runs LLVM's own MC encoding tests through Keystone, which has
over 250,000 assertions across every architecture. This is tested in the Rust
bindings.

```sh
cargo test --release --features arch_all
```

## Updating LLVM

The tooling for moving to a new LLVM release lives in [`tools/`](tools/), see
its README.

## License

Keystone is licensed under the [Mozilla Public License 2.0](LICENSE). The vendored
LLVM sources under `llvm/` remain under the Apache License 2.0 with LLVM Exceptions,
see [`llvm/LICENSE.TXT`](llvm/LICENSE.TXT).
