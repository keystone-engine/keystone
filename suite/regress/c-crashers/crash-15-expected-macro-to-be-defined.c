#include <keystone/keystone.h>
int main(int argc, char **argv) {
  int ks_arch = KS_ARCH_SYSTEMZ, ks_mode = KS_MODE_LITTLE_ENDIAN;
  unsigned char assembly[] = {
    0x12, ';', 0x12, 'i', ';', '.', 'i', 'R', 'p', ' ',
    'e', 'm', 'i', 'R', 'p', ',', 0xca, 0xe9, ',', 'I',
    '=', 0x00,
  };
  ks_engine *ks;
  ks_err err = ks_open(ks_arch, ks_mode, &ks);
  if (!err) {
    size_t count, size;
    unsigned char *insn;
    ks_asm(ks, (char *)assembly, 0, &insn, &size, &count);
    ks_free(insn);
  }
  ks_close(ks);
}
