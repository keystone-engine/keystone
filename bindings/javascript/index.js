// Keystone Assembler Engine (www.keystone-engine.org)
// By Nguyen Anh Quynh <aquynh@gmail.com>, 2016
// By Amaan Qureshi <git@amaanq.com>, 2025

import createModule from "./keystone.mjs";

let wasm;
let loading;

export function init() {
  loading ??= createModule().then((module) => {
    wasm = module;
    resolveSymbol = wasm.addFunction(resolve, "iiii");
  }, (error) => {
    loading = undefined;
    throw error;
  });
  return loading;
}

function loaded() {
  if (!wasm) throw new Error("keystone-engine: await init() before using it");
  return wasm;
}

export const Arch = Object.freeze({
  AArch64: 1,
  Amdgpu: 2,
  ARM: 3,
  AVR: 4,
  BPF: 5,
  CSKY: 6,
  EVM: 7,
  Lanai: 8,
  LoongArch: 9,
  Hexagon: 10,
  M68k: 11,
  MIPS: 12,
  MSP430: 13,
  PPC: 14,
  RISCV: 15,
  Sparc: 16,
  Systemz: 17,
  Thumb: 18,
  VE: 19,
  WASM: 20,
  X86: 21,
  X64: 22,
  Xtensa: 23,
});

export const Width = Object.freeze({ W16: 16, W32: 32, W64: 64 });

export const ArchVariant = Object.freeze({
  None: 0,
  ARMv7: 1,
  ARMMClass: 2,
  ARMEM: 4,
  Thumbv7: 1,
  ThumbMClass: 2,
  ThumbEM: 4,
});

export const Endian = Object.freeze({ Little: 1, Big: 2 });

export const KsErr = Object.freeze({
  Ok: 0,
  Mem: 1,
  Handle: 2,
  Arch: 3,
  Endian: 4,
  Width: 5,
  Feature: 6,
  Cpu: 7,
  Version: 8,
  OptInvalid: 9,
  AsmSyntax: 10,
  AsmInvalidToken: 11,
  AsmInvalidDirective: 12,
  AsmMissingSymbol: 13,
  AsmInvalidSymbol: 14,
  AsmMacroError: 15,
  AsmInsnUnsupported: 16,
  AsmExprError: 17,
  AsmFixupInvalid: 18,
  AsmLabelInvalid: 19,
  AsmInvalidOperand: 20,
  AsmMissingFeature: 21,
  AsmMnemonicFail: 22,
});

export const X86Syntax = Object.freeze({ ATT: 0, Intel: 1, NASM: 2 });

export const Radix = Object.freeze({
  Binary: 2,
  Octal: 8,
  Decimal: 10,
  Hexadecimal: 16,
  Base36: 36,
});

export const ArmItMode = Object.freeze({
  Always: 0,
  Never: 1,
  ARMOnly: 2,
  ThumbOnly: 3,
});

export class KeystoneError extends Error {
  constructor(code, locations = []) {
    const text = wasm.UTF8ToString(wasm._ks_strerror(code));
    const detail = locations.map((l) => `\nat line ${l.line}, column ${l.column}: ${l.message}`);
    super(text + detail.join(""));
    this.name = "KeystoneError";
    this.code = code;
    this.locations = locations;
  }
}

function check(code) {
  if (code !== KsErr.Ok) throw new KeystoneError(code);
}

function withString(text, code, body) {
  if (text.includes("\0")) throw new KeystoneError(code);

  const size = wasm.lengthBytesUTF8(text) + 1;
  const ptr = wasm._malloc(size);
  wasm.stringToUTF8(text, ptr, size);
  try {
    return body(ptr);
  } finally {
    wasm._free(ptr);
  }
}

const memory = () => new DataView(wasm.HEAPU8.buffer);

// Resolver callbacks keyed by engine handle, which is also the C payload.
const resolvers = new Map();

let resolveSymbol;

function resolve(payload, symbol, value) {
  const entry = resolvers.get(payload);
  if (!entry || entry.thrown) return 0;

  try {
    const resolved = entry.callback(wasm.UTF8ToString(symbol));
    if (resolved === undefined || resolved === null) return 0;
    memory().setBigUint64(value, BigInt.asUintN(64, BigInt(resolved)), true);
    return 1;
  } catch (error) {
    // A JS exception unwinding through wasm would skip the engine's C++ cleanup.
    entry.thrown = { error };
    return 0;
  }
}

const engines = new FinalizationRegistry((handle) => {
  resolvers.delete(handle);
  wasm._ks_delete(handle);
});

export function version() {
  const packed = loaded()._ks_version(0, 0);
  return { major: packed >>> 16, minor: packed & 0xffff };
}

export function archSupported(arch) {
  return loaded()._ks_arch_supported(arch) !== 0;
}

export class Keystone {
  #handle;

  constructor(arch) {
    const out = loaded()._malloc(4);
    try {
      check(wasm._ks_new(out, arch));
      this.#handle = wasm.HEAPU32[out >> 2];
    } finally {
      wasm._free(out);
    }
    engines.register(this, this.#handle, this);
  }

  get #live() {
    if (!this.#handle) throw new KeystoneError(KsErr.Handle);
    return this.#handle;
  }

  close() {
    if (!this.#handle) return;

    engines.unregister(this);
    resolvers.delete(this.#handle);
    wasm._ks_delete(this.#handle);
    this.#handle = 0;
  }

  get arch() {
    return wasm._ks_get_arch(this.#live);
  }

  set arch(arch) {
    check(wasm._ks_set_arch(this.#live, arch));
    resolvers.delete(this.#handle);
  }

  get endian() {
    return wasm._ks_get_endian(this.#live);
  }

  set endian(endian) {
    check(wasm._ks_set_endian(this.#live, endian));
  }

  get width() {
    return wasm._ks_get_width(this.#live);
  }

  set width(width) {
    check(wasm._ks_set_width(this.#live, width));
  }

  get archVariant() {
    return wasm._ks_get_arch_variant(this.#live);
  }

  set archVariant(variant) {
    check(wasm._ks_set_arch_variant(this.#live, variant));
  }

  get x86Syntax() {
    return wasm._ks_get_x86_syntax(this.#live);
  }

  set x86Syntax(syntax) {
    check(wasm._ks_set_x86_syntax(this.#live, syntax));
  }

  get radix() {
    return wasm._ks_get_radix(this.#live);
  }

  set radix(radix) {
    check(wasm._ks_set_radix(this.#live, radix));
  }

  get armItMode() {
    return wasm._ks_get_arm_it_mode(this.#live);
  }

  set armItMode(mode) {
    check(wasm._ks_set_arm_it_mode(this.#live, mode));
  }

  get cskyCompressed() {
    return wasm._ks_get_csky_compressed(this.#live) !== 0;
  }

  set cskyCompressed(compressed) {
    check(wasm._ks_set_csky_compressed(this.#live, compressed));
  }

  get feature() {
    return wasm.UTF8ToString(wasm._ks_get_feature(this.#live));
  }

  set feature(features) {
    const handle = this.#live;
    check(withString(features, KsErr.Feature, (ptr) => wasm._ks_set_feature(handle, ptr)));
  }

  get cpu() {
    return wasm.UTF8ToString(wasm._ks_get_cpu(this.#live));
  }

  set cpu(cpu) {
    const handle = this.#live;
    check(withString(cpu, KsErr.Cpu, (ptr) => wasm._ks_set_cpu(handle, ptr)));
  }

  get symbolResolver() {
    return resolvers.get(this.#live)?.callback ?? null;
  }

  set symbolResolver(callback) {
    const handle = this.#live;
    const resolver = wasm._malloc(8);
    wasm.HEAPU32[resolver >> 2] = callback ? handle : 0;
    wasm.HEAPU32[(resolver >> 2) + 1] = callback ? resolveSymbol : 0;
    try {
      check(wasm._ks_set_symbol_resolver(handle, resolver));
    } finally {
      wasm._free(resolver);
    }

    if (callback) resolvers.set(handle, { callback, thrown: null });
    else resolvers.delete(handle);
  }

  asm(code, address = 0) {
    const handle = this.#live;
    const entry = resolvers.get(handle);
    if (entry) entry.thrown = null;

    return withString(code, KsErr.AsmSyntax, (text) => {
      const result = wasm._malloc(24);
      wasm.HEAPU8.fill(0, result, result + 24);
      try {
        const rc = wasm._ks_assemble(handle, text, BigInt.asUintN(64, BigInt(address)), result);
        if (entry?.thrown) throw entry.thrown.error;

        const view = memory();
        const word = (offset) => view.getUint32(result + offset, true);
        if (rc === KsErr.Ok) {
          const bytes = wasm.HEAPU8.slice(word(4), word(4) + word(8));
          return { bytes, statCount: word(12) };
        }

        const locations = [];
        for (let i = 0, at = word(16); i < word(20); i++, at += 24) {
          locations.push({
            line: Number(view.getBigUint64(at, true)),
            column: Number(view.getBigUint64(at + 8, true)),
            message: wasm.UTF8ToString(view.getUint32(at + 16, true)),
          });
        }
        throw new KeystoneError(rc, locations);
      } finally {
        wasm._ks_asm_result_free(result);
        wasm._free(result);
      }
    });
  }
}

if (Symbol.dispose) Keystone.prototype[Symbol.dispose] = Keystone.prototype.close;
