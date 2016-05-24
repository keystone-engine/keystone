#include <keystone/keystone.h>
int main(int argc, char **argv) {
  int ks_arch = KS_ARCH_SYSTEMZ, ks_mode = KS_MODE_LITTLE_ENDIAN;
  ks_engine *ks;
  ks_err err = ks_open(ks_arch, ks_mode, &ks);
  if (!err) {
    size_t count, size;
    unsigned char *insn;
    ks_asm(ks, 0, 0, &insn, &size, &count);
    ks_free(insn);
  }
  ks_close(ks);
}
