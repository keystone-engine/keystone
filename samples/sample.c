// Sample code for Keystone Assembler Engine (www.keystone-enigne.org).
// By Nguyen Anh Quynh, 2016

#include <stdio.h>
#include <string.h>

#include <keystone/keystone.h>

static int test_ks(ks_arch arch, int mode, const char *assembly, int syntax)
{
    ks_engine *ks;
    ks_err err;
    size_t count;
    unsigned char *encode;
    size_t size;

    err = ks_open(arch, mode, &ks);
    if (err != KS_ERR_OK) {
        printf("ERROR: failed on ks_open(), quit\n");
        return -1;
    }

    if (syntax)
        ks_option(ks, KS_OPT_SYNTAX, syntax);

    if (ks_asm(ks, assembly, 0, &encode, &size, &count)) {
        printf("ERROR: failed on ks_asm() with count = %lu, error code = %u\n", count, ks_errno(ks));
    } else {
        size_t i;

        printf("%s = ", assembly);
        for (i = 0; i < size; i++) {
            printf("%02x ", encode[i]);
        }
        printf("\n");
        printf("Assembled: %lu bytes, %lu statements\n\n", size, count);
    }

    // NOTE: free encode after usage to avoid leaking memory
    ks_free(encode);

    // close Keystone instance when done
    ks_close(ks);

    return 0;
}

// symbol resolver callback
static bool sym_resolver(const char *symbol, uint64_t *value)
{
    // is this the missing symbol "_l1" that we want to handle?
    if (!strcmp(symbol, "_l1")) {
        // put value of this symbol in @value
        *value = 0x1002;
        // we handled this symbol, so return true
        return true;
    }

    // we did not handle this symbol, so return false
    return false;
}

// test symbol resolver to handle missing symbols
static int test_sym_resolver()
{
    ks_engine *ks;
    ks_err err;
    size_t count;
    unsigned char *encode;
    size_t size;
    const char *assembly = "jmp _l1; nop";

    err = ks_open(KS_ARCH_X86, KS_MODE_32, &ks);
    if (err != KS_ERR_OK) {
        printf("ERROR: failed on ks_open(), quit\n");
        return -1;
    }

    // register callback for symbol resolver
    ks_option(ks, KS_OPT_SYM_RESOLVER, (size_t)sym_resolver);

    if (ks_asm(ks, assembly, 0x1000, &encode, &size, &count)) {
        printf("ERROR: failed on ks_asm() with count = %lu, error code = %u\n", count, ks_errno(ks));
    } else {
        size_t i;

        printf("%s = ", assembly);
        for (i = 0; i < size; i++) {
            printf("%02x ", encode[i]);
        }
        printf("\n");
        printf("Assembled: %lu bytes, %lu statements\n\n", size, count);
    }

    // NOTE: free encode after usage to avoid leaking memory
    ks_free(encode);

    // close Keystone instance when done
    ks_close(ks);

    return 0;
}

int main(int argc, char **argv)
{
    // X86
    test_ks(KS_ARCH_X86, KS_MODE_16, "add eax, ecx", 0);
    test_ks(KS_ARCH_X86, KS_MODE_32, "add eax, ecx", 0);
    test_ks(KS_ARCH_X86, KS_MODE_64, "add rax, rcx", 0);
    test_ks(KS_ARCH_X86, KS_MODE_32, "add %ecx, %eax", KS_OPT_SYNTAX_ATT);
    test_ks(KS_ARCH_X86, KS_MODE_64, "add %rcx, %rax", KS_OPT_SYNTAX_ATT);

    test_ks(KS_ARCH_X86, KS_MODE_32, "add eax, 0x15", 0);
    test_ks(KS_ARCH_X86, KS_MODE_32, "add eax, 15h", 0);
    test_ks(KS_ARCH_X86, KS_MODE_32, "add eax, 15", 0);

    // RADIX16 syntax Intel (default syntax)
    test_ks(KS_ARCH_X86, KS_MODE_32, "add eax, 15", KS_OPT_SYNTAX_RADIX16);
    // RADIX16 syntax for AT&T
    test_ks(KS_ARCH_X86, KS_MODE_32, "add $15, %eax", KS_OPT_SYNTAX_RADIX16 | KS_OPT_SYNTAX_ATT);

    // ARM
    test_ks(KS_ARCH_ARM, KS_MODE_ARM, "sub r1, r2, r5", 0);
    test_ks(KS_ARCH_ARM, KS_MODE_ARM + KS_MODE_BIG_ENDIAN, "sub r1, r2, r5", 0);
    test_ks(KS_ARCH_ARM, KS_MODE_THUMB, "movs r4, #0xf0", 0);
    test_ks(KS_ARCH_ARM, KS_MODE_THUMB + KS_MODE_BIG_ENDIAN, "movs r4, #0xf0", 0);

    // ARM64
    test_ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, "ldr w1, [sp, #0x8]", 0);

    // Hexagon
    test_ks(KS_ARCH_HEXAGON, KS_MODE_BIG_ENDIAN, "v23.w=vavg(v11.w,v2.w):rnd", 0);

    // Mips
    test_ks(KS_ARCH_MIPS, KS_MODE_MIPS32, "and $9, $6, $7", 0);
    test_ks(KS_ARCH_MIPS, KS_MODE_MIPS32 + KS_MODE_BIG_ENDIAN, "and $9, $6, $7", 0);
    test_ks(KS_ARCH_MIPS, KS_MODE_MIPS64, "and $9, $6, $7", 0);
    test_ks(KS_ARCH_MIPS, KS_MODE_MIPS64 + KS_MODE_BIG_ENDIAN, "and $9, $6, $7", 0);

    // PowerPC
    test_ks(KS_ARCH_PPC, KS_MODE_PPC32 + KS_MODE_BIG_ENDIAN, "add 1, 2, 3", 0);
    test_ks(KS_ARCH_PPC, KS_MODE_PPC64, "add 1, 2, 3", 0);
    test_ks(KS_ARCH_PPC, KS_MODE_PPC64 + KS_MODE_BIG_ENDIAN, "add 1, 2, 3", 0);

    // RISCV
    test_ks(KS_ARCH_RISCV, KS_MODE_RISCV32 + KS_MODE_LITTLE_ENDIAN, "addi x0, x0, 10", 0);
    test_ks(KS_ARCH_RISCV, KS_MODE_RISCV64 + KS_MODE_LITTLE_ENDIAN, "addiw x0, x0, 10", 0);

    // Sparc
    test_ks(KS_ARCH_SPARC, KS_MODE_SPARC32 + KS_MODE_LITTLE_ENDIAN, "add %g1, %g2, %g3", 0);
    test_ks(KS_ARCH_SPARC, KS_MODE_SPARC32 + KS_MODE_BIG_ENDIAN, "add %g1, %g2, %g3", 0);

    // SystemZ
    test_ks(KS_ARCH_SYSTEMZ, KS_MODE_BIG_ENDIAN, "a %r0, 4095(%r15,%r1)", 0);

    // Test Symbol Resolver
    test_sym_resolver();

    return 0;
}
