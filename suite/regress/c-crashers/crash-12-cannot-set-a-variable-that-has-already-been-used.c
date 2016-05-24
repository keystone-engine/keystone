#include <keystone/keystone.h>
int main(int argc, char **argv) {
  int ks_arch = KS_ARCH_SYSTEMZ, ks_mode = KS_MODE_LITTLE_ENDIAN;
  unsigned char assembly[] = {
    'A', 'A', '=', 'F', '/', 'A', 0x0a, 'F', '/', 'A',
    0x0a, 'A', 'A', '=', 'F', '/', 'a', 0x0a, 'A', '=',
    '9', '/', '7', 0x0a, 'A', 'A', '=', 'F', '/', 'a',
    0x0a, 'A', '=', 'F', 0x00,
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
