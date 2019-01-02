(** Module proving OCaml bindings to the Keystone assembler engine *)


module Types : sig
  (** Type definitions for Keystone *)

  (** Keystone engine type *)
  type ks_t

  (** Keystone Architecture. Please see keystone.h for a full description. *)
  type ks_arch =
    | KS_ARCH_ARM
    | KS_ARCH_ARM64
    | KS_ARCH_MIPS
    | KS_ARCH_X86
    | KS_ARCH_PPC
    | KS_ARCH_SPARC
    | KS_ARCH_SYSTEMZ
    | KS_ARCH_HEXAGON
    | KS_ARCH_MAX

  (** Keystone error types. Please see keystone.h for a full description. *)
  type ks_error =
    | KS_ERR_OK
    | KS_ERR_NOMEM
    | KS_ERR_ARCH
    | KS_ERR_HANDLE
    | KS_ERR_MODE
    | KS_ERR_VERSION
    | KS_ERR_OPT_INVALID
    | KS_ERR_ASM_EXPR_TOKEN
    | KS_ERR_ASM_DIRECTIVE_VALUE_RANGE
    | KS_ERR_ASM_DIRECTIVE_ID
    | KS_ERR_ASM_DIRECTIVE_TOKEN
    | KS_ERR_ASM_DIRECTIVE_STR
    | KS_ERR_ASM_DIRECTIVE_COMMA
    | KS_ERR_ASM_DIRECTIVE_RELOC_NAME
    | KS_ERR_ASM_DIRECTIVE_RELOC_TOKEN
    | KS_ERR_ASM_DIRECTIVE_FPOINT
    | KS_ERR_ASM_DIRECTIVE_UNKNOWN
    | KS_ERR_ASM_VARIANT_INVALID
    | KS_ERR_ASM_DIRECTIVE_EQU
    | KS_ERR_ASM_EXPR_BRACKET
    | KS_ERR_ASM_SYMBOL_MODIFIER
    | KS_ERR_ASM_SYMBOL_REDEFINED
    | KS_ERR_ASM_SYMBOL_MISSING
    | KS_ERR_ASM_RPAREN
    | KS_ERR_ASM_STAT_TOKEN
    | KS_ERR_ASM_UNSUPPORTED
    | KS_ERR_ASM_MACRO_TOKEN
    | KS_ERR_ASM_MACRO_PAREN
    | KS_ERR_ASM_MACRO_EQU
    | KS_ERR_ASM_MACRO_ARGS
    | KS_ERR_ASM_MACRO_LEVELS_EXCEED
    | KS_ERR_ASM_MACRO_STR
    | KS_ERR_ASM_ESC_BACKSLASH
    | KS_ERR_ASM_ESC_OCTAL
    | KS_ERR_ASM_ESC_SEQUENCE
    | KS_ERR_ASM_ESC_STR
    | KS_ERR_ASM_TOKEN_INVALID
    | KS_ERR_ASM_INSN_UNSUPPORTED
    | KS_ERR_ASM_FIXUP_INVALID
    | KS_ERR_ASM_LABEL_INVALID
    | KS_ERR_ASM_FRAGMENT_INVALID
    | KS_ERR_ASM_INVALIDOPERAND
    | KS_ERR_ASM_MISSINGFEATURE
    | KS_ERR_ASM_MNEMONICFAIL

  type ks_opt_type =
    | KS_OPT_SYNTAX

  type ks_opt_value =
    | KS_OPT_SYNTAX_INTEL
    | KS_OPT_SYNTAX_ATT
    | KS_OPT_SYNTAX_NASM
    | KS_OPT_SYNTAX_MASM
    | KS_OPT_SYNTAX_GAS
    | KS_OPT_SYNTAX_RADIX16

  type ks_mode =
    | KS_MODE_ARM
    | KS_MODE_BIG_ENDIAN
    | KS_MODE_LITTLE_ENDIAN
    | KS_MODE_THUMB
    | KS_MODE_V8
    | KS_MODE_MICRO
    | KS_MODE_MIPS3
    | KS_MODE_MIPS32R6
    | KS_MODE_MIPS32
    | KS_MODE_MIPS64
    | KS_MODE_16
    | KS_MODE_32
    | KS_MODE_64
    | KS_MODE_PPC32
    | KS_MODE_PPC64
    | KS_MODE_QPX
    | KS_MODE_SPARC32
    | KS_MODE_SPARC64
    | KS_MODE_V9
end

(** Record containing a successful encoding result.
    encoding field contains an int array
    encoding_size is size of the encoding
    stat_count records how many statements were successfully processed.
*)
type encoded_result =
  {
    encoding: int array;
    encoding_size : int;
    stat_count : int;
  }

(** Determine if the given architecture is supported. True if the
    architecture is supported, false otherwise *)
val ks_arch_supported : Types.ks_arch -> bool

val ks_version : int -> int -> int


(** Set an option for a Keystone engine instance.
    Takes an engine instance, an option type and an option value.

    Returns KS_ERR_OK on success or another value on failure.
*)
val ks_option :
  Types.ks_t ->
  Types.ks_opt_type -> Types.ks_opt_value -> Types.ks_error

(** Given a ks_err type, returns a string description of the error. *)
val ks_strerror : Types.ks_error -> string



(** Create a new instance of Keystone engine.
    arch: is architecture type, mode is hardware mode.

    Returns a Keystone engine or a string with an error message.
*)
val ks_open :
  Types.ks_arch -> ?endian:Types.ks_mode -> Types.ks_mode -> (Types.ks_t, string) Result.result



(** Close the Keystone engine instance *)
val ks_close : Types.ks_t -> int64


(** Given a Keystone engine instance, returns the last error number on
    some API function failure. *)
val ks_errno :
  Types.ks_t -> Types.ks_error


(** Assemble a string: takes a Keystone engine instance, a string to
assemble and a start address to assemble from.

On success returns Ok with a encoded_result record
 *)
val ks_asm :
  Types.ks_t ->
  string -> int -> (encoded_result, string) Result.result

(** Convert an array containing an encoding of an assembly string and
returns a string representation. *)
val asm_array_to_string : int array -> string
