open Keystone

module T = Keystone.Types

let test_ks arch mode ?(syntax=T.KS_OPT_SYNTAX_INTEL) ?(endian=T.KS_MODE_LITTLE_ENDIAN) asm  =
  Printf.printf "ASSEMBLING %s\n" asm; flush stdout;
  match (ks_open arch ~endian:endian mode) with
  | Result.Ok engine ->
     begin
       ignore(ks_option engine T.KS_OPT_SYNTAX syntax);
       match (ks_asm engine asm 0) with
       | Result.Ok(result) ->
          Printf.printf "%s = %s\nAssembled: %i bytes, %i statements\n \n"
                        asm
                        (asm_array_to_string result.encoding)
                        result.encoding_size
                        result.stat_count;
          ignore(ks_close engine)

       | Result.Error s -> ignore (ks_close engine);
                           Printf.printf "ERROR: failed on ks_asm with: %s\n" s
     end

  | Result.Error e -> Printf.printf "ERROR: failed on ks_open: %s\n" e


let _ =
  test_ks T.KS_ARCH_X86 T.KS_MODE_16 "add eax, ecx";
  test_ks T.KS_ARCH_X86 T.KS_MODE_32 "add eax, ecx";
  test_ks T.KS_ARCH_X86 T.KS_MODE_64 "add rax, rcx";
  test_ks T.KS_ARCH_X86 T.KS_MODE_32 ~syntax:T.KS_OPT_SYNTAX_ATT "add %ecx, %eax";
  test_ks T.KS_ARCH_X86 T.KS_MODE_64 ~syntax:T.KS_OPT_SYNTAX_ATT "add %rcx, %rax";
  test_ks T.KS_ARCH_X86 T.KS_MODE_32 ~syntax:T.KS_OPT_SYNTAX_RADIX16 "add eax, 15";

  test_ks T.KS_ARCH_ARM T.KS_MODE_ARM  "sub r1, r2, r5";
  test_ks T.KS_ARCH_ARM T.KS_MODE_ARM  "sub r1, r2, r5";
  test_ks T.KS_ARCH_ARM T.KS_MODE_ARM ~endian:T.KS_MODE_BIG_ENDIAN "sub r1, r2, r5";
  test_ks T.KS_ARCH_ARM T.KS_MODE_THUMB "movs r4, #0xf0";
  test_ks T.KS_ARCH_ARM T.KS_MODE_THUMB ~endian:T.KS_MODE_BIG_ENDIAN "movs r4, #0xf0";

  test_ks T.KS_ARCH_ARM64 T.KS_MODE_LITTLE_ENDIAN "ldr w1, [sp, #0x8]";

  test_ks T.KS_ARCH_HEXAGON T.KS_MODE_BIG_ENDIAN "v23.w=vavg(v11.w,v2.w):rnd";

  test_ks T.KS_ARCH_MIPS T.KS_MODE_MIPS32 "and $9, $6, $7";
  test_ks T.KS_ARCH_MIPS T.KS_MODE_MIPS32 ~endian:T.KS_MODE_BIG_ENDIAN "and $9, $6, $7";

  test_ks T.KS_ARCH_MIPS T.KS_MODE_MIPS64 "and $9, $6, $7";
  test_ks T.KS_ARCH_MIPS T.KS_MODE_MIPS64 ~endian:T.KS_MODE_BIG_ENDIAN "and $9, $6, $7";

  test_ks T.KS_ARCH_PPC T.KS_MODE_PPC32 ~endian:T.KS_MODE_BIG_ENDIAN "add 1,2,3";
  test_ks T.KS_ARCH_PPC T.KS_MODE_PPC64 "add 1,2,3";
  test_ks T.KS_ARCH_PPC T.KS_MODE_PPC64 ~endian:T.KS_MODE_BIG_ENDIAN "add 1,2,3";

  test_ks T.KS_ARCH_SPARC T.KS_MODE_SPARC32 "add %g1, %g2, %g3";
  test_ks T.KS_ARCH_SPARC T.KS_MODE_SPARC32 ~endian:T.KS_MODE_BIG_ENDIAN "add %g1, %g2, %g3";

  test_ks T.KS_ARCH_SYSTEMZ T.KS_MODE_BIG_ENDIAN "a %r0, 4095(%r15, %r1)"
