#include <keystone/keystone.h>
int main(int argc, char **argv) {
  int ks_arch = KS_ARCH_X86, ks_mode = KS_MODE_64;
  char *assembly = "x=y--y;.=x-y";
  ks_engine *ks;
  ks_err err = ks_open(ks_arch, ks_mode, &ks);
  if (!err) {
    size_t count, size;
    unsigned char *insn;
    if (ks_asm(ks, assembly, 0, &insn, &size, &count))
      printf("ERROR: failed on ks_asm() with error = %s, code = %u\n", ks_strerror(ks_errno(ks)), ks_errno(ks));
    ks_free(insn);
  }
  ks_close(ks);
  return 0;
}
