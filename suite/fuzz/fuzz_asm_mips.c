#include <keystone/keystone.h>

#include <string.h>

FILE * outfile = NULL;


int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    ks_engine *ks;
    ks_err err;
    size_t count;
    unsigned char *encode = NULL;
    size_t size;
    char * assembler;

    if (outfile == NULL) {
        // we compute the output
        outfile = fopen("/dev/null", "w");
        if (outfile == NULL) {
            printf("failed opening /dev/null\n");
            abort();
        }
    }

    if (Size < 1) {
        return 0;
    }

    err = ks_open(KS_ARCH_MIPS, KS_MODE_MIPS32+KS_MODE_LITTLE_ENDIAN, &ks);
    if (err != KS_ERR_OK) {
        printf("ERROR: failed on ks_open(), quit error = %u\n", err);
        abort();
    }

    ks_option(ks, KS_OPT_SYNTAX, Data[Size-1]);

    assembler = malloc(Size);
    memcpy(assembler, Data, Size-1);
    //null terminate string
    assembler[Size-1] = 0;

    if (ks_asm(ks, assembler, 0, &encode, &size, &count) != KS_ERR_OK) {
        fprintf(outfile, "ERROR: ks_asm() failed & count = %lu, error = %u\n",
                count, ks_errno(ks));
    } else {
        size_t i;

        fprintf(outfile, "%s = ", assembler);
        for (i = 0; i < size; i++) {
            fprintf(outfile, "%02x ", encode[i]);
        }
        fprintf(outfile, "\n");
        fprintf(outfile, "Compiled: %lu bytes, statements: %lu\n", size, count);
    }

    free(assembler);
    // NOTE: free encode after usage to avoid leaking memory
    if (encode != NULL) {
        ks_free(encode);
    }

    // close Keystone instance when done
    ks_close(ks);

    return 0;
}
