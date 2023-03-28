// Kstool for Keystone Assembler Engine.
// By Nguyen Anh Quynh, 2016-2020
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <errno.h>
#include <limits.h>
#if !defined(WIN32) && !defined(WIN64) && !defined(_WIN32) && !defined(_WIN64)
#include <unistd.h>
#else
#endif
#include <fcntl.h>

#include <keystone/keystone.h>

#if defined(WIN32) || defined(WIN64) || defined(_WIN32) || defined(_WIN64)
#include "getopt.h"
#endif

static void usage(char *prog)
{
    printf("Kstool v%u.%u.%u for Keystone Assembler Engine (www.keystone-engine.org)\nBy Nguyen Anh Quynh, 2016-2020\n\n",
            KS_VERSION_MAJOR, KS_VERSION_MINOR, KS_VERSION_EXTRA);
    printf("Syntax: %s [-b] <arch+mode> <assembly-string> [start-address-in-hex-format]\n", prog);
    printf("\nThe following <arch+mode> options are supported:\n");

    if (ks_arch_supported(KS_ARCH_X86)) {
        printf("        x16:       X86 16bit, Intel syntax\n");
        printf("        x32:       X86 32bit, Intel syntax\n");
        printf("        x64:       X86 64bit, Intel syntax\n");
        printf("        x16att:    X86 16bit, AT&T syntax\n");
        printf("        x32att:    X86 32bit, AT&T syntax\n");
        printf("        x64att:    X86 64bit, AT&T syntax\n");
        printf("        x16nasm:   X86 16bit, NASM syntax\n");
        printf("        x32nasm:   X86 32bit, NASM syntax\n");
        printf("        x64nasm:   X86 64bit, NASM syntax\n");
    }

    if (ks_arch_supported(KS_ARCH_ARM)) {
        printf("        arm:       ARM - little endian\n");
        printf("        armbe:     ARM - big endian\n");
        printf("        thumb:     Thumb - little endian\n");
        printf("        thumbbe:   Thumb - big endian\n");
        printf("        armv8:     ARM V8 - little endian\n");
        printf("        armv8be:   ARM V8 - big endian\n");
        printf("        thumbv8:   Thumb V8 - little endian\n");
        printf("        thumbv8be: Thumb V8 - big endian\n");
    }

    if (ks_arch_supported(KS_ARCH_ARM64)) {
        printf("        arm64:     AArch64\n");
    }

    if (ks_arch_supported(KS_ARCH_HEXAGON)) {
        printf("        hexagon:   Hexagon\n");
    }

    if (ks_arch_supported(KS_ARCH_MIPS)) {
        printf("        mips:      Mips - little endian\n");
        printf("        mipsbe:    Mips - big endian\n");
        printf("        mips64:    Mips64 - little endian\n");
        printf("        mips64be:  Mips64 - big endian\n");
    }

    if (ks_arch_supported(KS_ARCH_PPC)) {
        printf("        ppc32be:   PowerPC32 - big endian\n");
        printf("        ppc64:     PowerPC64 - little endian\n");
        printf("        ppc64be:   PowerPC64 - big endian\n");
    }

    if (ks_arch_supported(KS_ARCH_SPARC)) {
        printf("        sparc:     Sparc - little endian\n");
        printf("        sparcbe:   Sparc - big endian\n");
        printf("        sparc64be: Sparc64 - big endian\n");
    }

    if (ks_arch_supported(KS_ARCH_SYSTEMZ)) {
        printf("        systemz:   SystemZ (S390x)\n");
    }

    if (ks_arch_supported(KS_ARCH_EVM)) {
        printf("        evm:       Ethereum Virtual Machine\n");
    }

    if (ks_arch_supported(KS_ARCH_RISCV)){
        printf("        riscv32:     RISC-V32 - little endian\n");
        printf("        riscv64:     RISC-V64 - little endian\n");
    }

    printf("\nExtra options:\n");
    printf("        -b binary output\n\n");
}

int main(int argc, char **argv)
{
    ks_engine *ks;
    ks_err err = KS_ERR_ARCH;
    char *mode, *assembly = NULL;
    uint64_t start_addr = 0;
    char *input = NULL;
    size_t count;
    unsigned char *insn = NULL;
    size_t size;
    bool binary_output = false;
    int c;
    int args_left;

    while ((c = getopt(argc, argv, "bh")) != -1) {
      switch (c) {
        case 'b':
          binary_output = true;
          break;
        case 'h':
          usage(argv[0]);
          return 0;
        default:
          usage(argv[0]);
          return -1;
      }
    }

    args_left = argc - optind;
    if (args_left == 1) {
        // handle code from stdin
#if !defined(WIN32) && !defined(WIN64) && !defined(_WIN32) && !defined(_WIN64)
        int flags;
        size_t index = 0;
        char buf[1024];

        mode = argv[optind];

        if ((flags = fcntl(STDIN_FILENO, F_GETFL, 0)) == -1)
            flags = 0;

        fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);

        while(fgets(buf, sizeof(buf), stdin)) {
            input = (char*)realloc(input, index + strlen(buf));
            if (!input) {
                printf("Failed to allocate memory.");
                return 1;
            }

            memcpy(&input[index], buf, strlen(buf));
            index += strlen(buf);
        }

        fcntl(STDIN_FILENO, F_SETFL, flags);

        assembly = input;
        if (!assembly) {
            usage(argv[0]);
            return -1;
        }
#else   // Windows does not handle code from stdin
        usage(argv[0]);
        return -1;
#endif
    } else if (args_left == 2) {
        // kstool <arch> <assembly>
        mode = argv[optind];
        assembly = argv[optind + 1];
    } else if (args_left == 3) {
        // kstool <arch> <assembly> <address>
        char *temp;
        mode = argv[optind];
        assembly = argv[optind + 1];
        start_addr = strtoull(argv[optind + 2], &temp, 16);
        if (temp == argv[optind + 2] || *temp != '\0' || errno == ERANGE) {
            printf("ERROR: invalid address argument, quit!\n");
            return -2;
        }
    } else {
        usage(argv[0]);
        return -1;
    }

    if (!strcmp(mode, "x16")) {
        err = ks_open(KS_ARCH_X86, KS_MODE_16, &ks);
    }
    if (!strcmp(mode, "x32")) {
        err = ks_open(KS_ARCH_X86, KS_MODE_32, &ks);
    }
    if (!strcmp(mode, "x64")) {
        err = ks_open(KS_ARCH_X86, KS_MODE_64, &ks);
    }

    if (!strcmp(mode, "x16att")) {
        err = ks_open(KS_ARCH_X86, KS_MODE_16, &ks);
        if (!err) {
            ks_option(ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_ATT);
        }
    }
    if (!strcmp(mode, "x32att")) {
        err = ks_open(KS_ARCH_X86, KS_MODE_32, &ks);
        if (!err) {
            ks_option(ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_ATT);
        }
    }
    if (!strcmp(mode, "x64att")) {
        err = ks_open(KS_ARCH_X86, KS_MODE_64, &ks);
        if (!err) {
            ks_option(ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_ATT);
        }
    }

    if (!strcmp(mode, "x16nasm")) {
        err = ks_open(KS_ARCH_X86, KS_MODE_16, &ks);
        if (!err) {
            ks_option(ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_NASM);
        }
    }
    if (!strcmp(mode, "x32nasm")) {
        err = ks_open(KS_ARCH_X86, KS_MODE_32, &ks);
        if (!err) {
            ks_option(ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_NASM);
        }
    }
    if (!strcmp(mode, "x64nasm")) {
        err = ks_open(KS_ARCH_X86, KS_MODE_64, &ks);
        if (!err) {
            ks_option(ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_NASM);
        }
    }

    if (!strcmp(mode, "arm")) {
        err = ks_open(KS_ARCH_ARM, KS_MODE_ARM+KS_MODE_LITTLE_ENDIAN, &ks);
    }

    if (!strcmp(mode, "armbe")) {
        err = ks_open(KS_ARCH_ARM, KS_MODE_ARM+KS_MODE_BIG_ENDIAN, &ks);
    }

    if (!strcmp(mode, "thumb")) {
        err = ks_open(KS_ARCH_ARM, KS_MODE_THUMB+KS_MODE_LITTLE_ENDIAN, &ks);
    }

    if (!strcmp(mode, "thumbbe")) {
        err = ks_open(KS_ARCH_ARM, KS_MODE_THUMB+KS_MODE_BIG_ENDIAN, &ks);
    }

    if (!strcmp(mode, "armv8")) {
        err = ks_open(KS_ARCH_ARM, KS_MODE_ARM+KS_MODE_LITTLE_ENDIAN+KS_MODE_V8, &ks);
    }

    if (!strcmp(mode, "armv8be")) {
        err = ks_open(KS_ARCH_ARM, KS_MODE_ARM+KS_MODE_BIG_ENDIAN+KS_MODE_V8, &ks);
    }

    if (!strcmp(mode, "thumbv8")) {
        err = ks_open(KS_ARCH_ARM, KS_MODE_THUMB+KS_MODE_LITTLE_ENDIAN+KS_MODE_V8, &ks);
    }

    if (!strcmp(mode, "thumbv8be")) {
        err = ks_open(KS_ARCH_ARM, KS_MODE_THUMB+KS_MODE_BIG_ENDIAN+KS_MODE_V8, &ks);
    }

    if (!strcmp(mode, "arm64")) {
        err = ks_open(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, &ks);
    }

    if (!strcmp(mode, "hex") || !strcmp(mode, "hexagon")) {
        err = ks_open(KS_ARCH_HEXAGON, KS_MODE_BIG_ENDIAN, &ks);
    }

    if (!strcmp(mode, "mips")) {
        err = ks_open(KS_ARCH_MIPS, KS_MODE_MIPS32+KS_MODE_LITTLE_ENDIAN, &ks);
    }

    if (!strcmp(mode, "mipsbe")) {
        err = ks_open(KS_ARCH_MIPS, KS_MODE_MIPS32+KS_MODE_BIG_ENDIAN, &ks);
    }

    if (!strcmp(mode, "mips64")) {
        err = ks_open(KS_ARCH_MIPS, KS_MODE_MIPS64+KS_MODE_LITTLE_ENDIAN, &ks);
    }

    if (!strcmp(mode, "mips64be")) {
        err = ks_open(KS_ARCH_MIPS, KS_MODE_MIPS64+KS_MODE_BIG_ENDIAN, &ks);
    }

    if (!strcmp(mode, "ppc32be")) {
        err = ks_open(KS_ARCH_PPC, KS_MODE_PPC32+KS_MODE_BIG_ENDIAN, &ks);
    }

    if (!strcmp(mode, "ppc64")) {
        err = ks_open(KS_ARCH_PPC, KS_MODE_PPC64+KS_MODE_LITTLE_ENDIAN, &ks);
    }

    if (!strcmp(mode, "ppc64be")) {
        err = ks_open(KS_ARCH_PPC, KS_MODE_PPC64+KS_MODE_BIG_ENDIAN, &ks);
    }

    if (!strcmp(mode, "sparc")) {
        err = ks_open(KS_ARCH_SPARC, KS_MODE_SPARC32+KS_MODE_LITTLE_ENDIAN, &ks);
    }

    if (!strcmp(mode, "sparcbe")) {
        err = ks_open(KS_ARCH_SPARC, KS_MODE_SPARC32+KS_MODE_BIG_ENDIAN, &ks);
    }

    if (!strcmp(mode, "sparc64be")) {
        err = ks_open(KS_ARCH_SPARC, KS_MODE_SPARC64+KS_MODE_BIG_ENDIAN, &ks);
    }

    if (!strcmp(mode, "systemz") || !strcmp(mode, "sysz") || !strcmp(mode, "s390x")) {
        err = ks_open(KS_ARCH_SYSTEMZ, KS_MODE_BIG_ENDIAN, &ks);
    }

    if (!strcmp(mode, "evm")) {
        err = ks_open(KS_ARCH_EVM, 0, &ks);
    }

    if (!strcmp(mode, "riscv32")) {
        err = ks_open(KS_ARCH_RISCV, KS_MODE_RISCV32+KS_MODE_LITTLE_ENDIAN, &ks);
    }

    if (!strcmp(mode, "riscv64")) {
        err = ks_open(KS_ARCH_RISCV, KS_MODE_RISCV64+KS_MODE_LITTLE_ENDIAN, &ks);
    }
    
    if (err) {
        printf("ERROR: failed on ks_open()\n");
        usage(argv[0]);
        return -1;
    }

    if (ks_asm(ks, assembly, start_addr, &insn, &size, &count)) {
        printf("ERROR: failed on ks_asm() with count = %zu, error = '%s' (code = %u)\n", count, ks_strerror(ks_errno(ks)), ks_errno(ks));
    } else {
        if (binary_output) {
          size_t i;
          for (i = 0; i < size; ++i) {
            putchar(insn[i]);
          }
        } else {
          size_t i;
          printf("%s = [ ", assembly);
          for (i = 0; i < size; i++) {
              printf("%02x ", insn[i]);
          }
          printf("]\n");
          //printf("Assembled: %lu bytes, %lu statement(s)\n", size, count);
        }
    }

    // NOTE: free insn after usage to avoid leaking memory
    if (insn != NULL) {
        ks_free(insn);
    }

    // close Keystone instance when done
    ks_close(ks);

    free(input);

    return 0;
}
