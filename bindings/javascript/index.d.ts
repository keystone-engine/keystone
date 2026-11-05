export declare const Arch: Readonly<{
  AArch64: 1;
  Amdgpu: 2;
  ARM: 3;
  AVR: 4;
  BPF: 5;
  CSKY: 6;
  EVM: 7;
  Lanai: 8;
  LoongArch: 9;
  Hexagon: 10;
  M68k: 11;
  MIPS: 12;
  MSP430: 13;
  PPC: 14;
  RISCV: 15;
  Sparc: 16;
  Systemz: 17;
  Thumb: 18;
  VE: 19;
  WASM: 20;
  X86: 21;
  X64: 22;
  Xtensa: 23;
}>;
export type Arch = (typeof Arch)[keyof typeof Arch];

export declare const Width: Readonly<{ W16: 16; W32: 32; W64: 64 }>;
export type Width = (typeof Width)[keyof typeof Width];

/** Bit flags, combine with `|`. */
export declare const ArchVariant: Readonly<{
  None: 0;
  ARMv7: 1;
  ARMMClass: 2;
  ARMEM: 4;
  Thumbv7: 1;
  ThumbMClass: 2;
  ThumbEM: 4;
}>;
export type ArchVariant = number;

export declare const Endian: Readonly<{ Little: 1; Big: 2 }>;
export type Endian = (typeof Endian)[keyof typeof Endian];

export declare const KsErr: Readonly<{
  Ok: 0;
  Mem: 1;
  Handle: 2;
  Arch: 3;
  Endian: 4;
  Width: 5;
  Feature: 6;
  Cpu: 7;
  Version: 8;
  OptInvalid: 9;
  AsmSyntax: 10;
  AsmInvalidToken: 11;
  AsmInvalidDirective: 12;
  AsmMissingSymbol: 13;
  AsmInvalidSymbol: 14;
  AsmMacroError: 15;
  AsmInsnUnsupported: 16;
  AsmExprError: 17;
  AsmFixupInvalid: 18;
  AsmLabelInvalid: 19;
  AsmInvalidOperand: 20;
  AsmMissingFeature: 21;
  AsmMnemonicFail: 22;
}>;
export type KsErr = (typeof KsErr)[keyof typeof KsErr];

export declare const X86Syntax: Readonly<{ ATT: 0; Intel: 1; NASM: 2 }>;
export type X86Syntax = (typeof X86Syntax)[keyof typeof X86Syntax];

export declare const Radix: Readonly<{
  Binary: 2;
  Octal: 8;
  Decimal: 10;
  Hexadecimal: 16;
  Base36: 36;
}>;
export type Radix = (typeof Radix)[keyof typeof Radix];

export declare const ArmItMode: Readonly<{
  Always: 0;
  Never: 1;
  ARMOnly: 2;
  ThumbOnly: 3;
}>;
export type ArmItMode = (typeof ArmItMode)[keyof typeof ArmItMode];

export interface ErrorLocation {
  line: number;
  column: number;
  message: string;
}

export interface Assembly {
  bytes: Uint8Array;
  statCount: number;
}

/** Returns the symbol's value, or `undefined` or `null` to leave it unresolved. */
export type SymbolResolver = (symbol: string) => bigint | number | null | undefined;

export declare class KeystoneError extends Error {
  readonly code: KsErr;
  readonly locations: ErrorLocation[];
}

/** Loads the WebAssembly. Await it once before anything else, later calls return the same promise. */
export declare function init(): Promise<void>;

export declare function version(): { major: number; minor: number };

export declare function archSupported(arch: Arch): boolean;

export declare class Keystone {
  constructor(arch: Arch);

  /** Frees the engine. Later calls throw a `KsErr.Handle` error. */
  close(): void;
  [Symbol.dispose](): void;

  /** Setting it resets every other option and clears the symbol resolver. */
  arch: Arch;
  endian: Endian;
  width: Width;
  archVariant: ArchVariant;
  x86Syntax: X86Syntax;
  /** Radix of unprefixed integer literals. `0x` and `0b` prefixes still apply. */
  radix: Radix;
  armItMode: ArmItMode;
  cskyCompressed: boolean;
  /** Comma-separated features. `Arch.AArch64` enables every extension (`all`) until a list replaces it. */
  feature: string;
  cpu: string;
  /** Undefined symbols fail with `KsErr.AsmMissingSymbol` while this is `null`. */
  symbolResolver: SymbolResolver | null;

  asm(code: string, address?: bigint | number): Assembly;
}
