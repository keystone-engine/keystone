/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* MC Register Information                                                    *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

namespace llvm_ks {

extern const int16_t CSKYRegDiffLists[] = {
  /* 0 */ -1, -1, 0,
  /* 3 */ -129, 1, 0,
  /* 6 */ 1, 1, 0,
  /* 9 */ 128, 1, 0,
  /* 12 */ 128, 0,
  /* 14 */ 129, 0,
};

extern const LaneBitmask CSKYLaneMaskLists[] = {
  /* 0 */ LaneBitmask(0x0000000000000001), 
  /* 1 */ LaneBitmask(0x0000000000000001), LaneBitmask(0x0000000000000002), 
  /* 3 */ LaneBitmask(0xFFFFFFFFFFFFFFFF), 
};

extern const uint16_t CSKYSubRegIdxLists[] = {
  /* 0 */ 3, 1, 
  /* 2 */ 1, 2, 
};


#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"
#endif
extern const char CSKYRegStrings[] = {
  /* 0 */ "R9_R10\000"
  /* 7 */ "R19_R20\000"
  /* 15 */ "R29_R30\000"
  /* 23 */ "R0\000"
  /* 26 */ "R10_R11\000"
  /* 34 */ "R20_R21\000"
  /* 42 */ "R30_R31\000"
  /* 50 */ "R0_R1\000"
  /* 56 */ "R11_R12\000"
  /* 64 */ "R21_R22\000"
  /* 72 */ "R31_R32\000"
  /* 80 */ "F10_32\000"
  /* 87 */ "F20_32\000"
  /* 94 */ "F30_32\000"
  /* 101 */ "F0_32\000"
  /* 107 */ "F11_32\000"
  /* 114 */ "F21_32\000"
  /* 121 */ "F31_32\000"
  /* 128 */ "F1_32\000"
  /* 134 */ "F12_32\000"
  /* 141 */ "F22_32\000"
  /* 148 */ "F2_32\000"
  /* 154 */ "F13_32\000"
  /* 161 */ "F23_32\000"
  /* 168 */ "F3_32\000"
  /* 174 */ "F14_32\000"
  /* 181 */ "F24_32\000"
  /* 188 */ "F4_32\000"
  /* 194 */ "F15_32\000"
  /* 201 */ "F25_32\000"
  /* 208 */ "F5_32\000"
  /* 214 */ "F16_32\000"
  /* 221 */ "F26_32\000"
  /* 228 */ "F6_32\000"
  /* 234 */ "F17_32\000"
  /* 241 */ "F27_32\000"
  /* 248 */ "F7_32\000"
  /* 254 */ "F18_32\000"
  /* 261 */ "F28_32\000"
  /* 268 */ "F8_32\000"
  /* 274 */ "F19_32\000"
  /* 281 */ "F29_32\000"
  /* 288 */ "F9_32\000"
  /* 294 */ "R1_R2\000"
  /* 300 */ "R12_R13\000"
  /* 308 */ "R22_R23\000"
  /* 316 */ "R2_R3\000"
  /* 322 */ "R13_R14\000"
  /* 330 */ "R23_R24\000"
  /* 338 */ "F10_64\000"
  /* 345 */ "F20_64\000"
  /* 352 */ "F30_64\000"
  /* 359 */ "F0_64\000"
  /* 365 */ "F11_64\000"
  /* 372 */ "F21_64\000"
  /* 379 */ "F31_64\000"
  /* 386 */ "F1_64\000"
  /* 392 */ "F12_64\000"
  /* 399 */ "F22_64\000"
  /* 406 */ "F2_64\000"
  /* 412 */ "F13_64\000"
  /* 419 */ "F23_64\000"
  /* 426 */ "F3_64\000"
  /* 432 */ "F14_64\000"
  /* 439 */ "F24_64\000"
  /* 446 */ "F4_64\000"
  /* 452 */ "F15_64\000"
  /* 459 */ "F25_64\000"
  /* 466 */ "F5_64\000"
  /* 472 */ "F16_64\000"
  /* 479 */ "F26_64\000"
  /* 486 */ "F6_64\000"
  /* 492 */ "F17_64\000"
  /* 499 */ "F27_64\000"
  /* 506 */ "F7_64\000"
  /* 512 */ "F18_64\000"
  /* 519 */ "F28_64\000"
  /* 526 */ "F8_64\000"
  /* 532 */ "F19_64\000"
  /* 539 */ "F29_64\000"
  /* 546 */ "F9_64\000"
  /* 552 */ "R3_R4\000"
  /* 558 */ "R14_R15\000"
  /* 566 */ "R24_R25\000"
  /* 574 */ "R4_R5\000"
  /* 580 */ "R15_R16\000"
  /* 588 */ "R25_R26\000"
  /* 596 */ "R5_R6\000"
  /* 602 */ "R16_R17\000"
  /* 610 */ "R26_R27\000"
  /* 618 */ "R6_R7\000"
  /* 624 */ "R17_R18\000"
  /* 632 */ "F10_128\000"
  /* 640 */ "F20_128\000"
  /* 648 */ "F30_128\000"
  /* 656 */ "F0_128\000"
  /* 663 */ "F11_128\000"
  /* 671 */ "F21_128\000"
  /* 679 */ "F31_128\000"
  /* 687 */ "F1_128\000"
  /* 694 */ "F12_128\000"
  /* 702 */ "F22_128\000"
  /* 710 */ "F2_128\000"
  /* 717 */ "F13_128\000"
  /* 725 */ "F23_128\000"
  /* 733 */ "F3_128\000"
  /* 740 */ "F14_128\000"
  /* 748 */ "F24_128\000"
  /* 756 */ "F4_128\000"
  /* 763 */ "F15_128\000"
  /* 771 */ "F25_128\000"
  /* 779 */ "F5_128\000"
  /* 786 */ "F16_128\000"
  /* 794 */ "F26_128\000"
  /* 802 */ "F6_128\000"
  /* 809 */ "F17_128\000"
  /* 817 */ "F27_128\000"
  /* 825 */ "F7_128\000"
  /* 832 */ "F18_128\000"
  /* 840 */ "F28_128\000"
  /* 848 */ "F8_128\000"
  /* 855 */ "F19_128\000"
  /* 863 */ "F29_128\000"
  /* 871 */ "F9_128\000"
  /* 878 */ "R27_R28\000"
  /* 886 */ "R7_R8\000"
  /* 892 */ "R18_R19\000"
  /* 900 */ "R28_R29\000"
  /* 908 */ "R8_R9\000"
  /* 914 */ "C\000"
};
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

extern const MCRegisterDesc CSKYRegDesc[] = { // Descriptors
  { 6, 0, 0, 0, 0, 0, 0, 0 },
  { 914, 2, 2, 2, 8192, 3, 0, 0 },
  { 23, 2, 14, 2, 8193, 3, 0, 0 },
  { 53, 2, 9, 2, 8194, 3, 0, 0 },
  { 297, 2, 9, 2, 8195, 3, 0, 0 },
  { 319, 2, 9, 2, 8196, 3, 0, 0 },
  { 555, 2, 9, 2, 8197, 3, 0, 0 },
  { 577, 2, 9, 2, 8198, 3, 0, 0 },
  { 599, 2, 9, 2, 8199, 3, 0, 0 },
  { 621, 2, 9, 2, 8200, 3, 0, 0 },
  { 889, 2, 9, 2, 8201, 3, 0, 0 },
  { 911, 2, 9, 2, 8202, 3, 0, 0 },
  { 3, 2, 9, 2, 8203, 3, 0, 0 },
  { 30, 2, 9, 2, 8204, 3, 0, 0 },
  { 60, 2, 9, 2, 8205, 3, 0, 0 },
  { 304, 2, 9, 2, 8206, 3, 0, 0 },
  { 326, 2, 9, 2, 8207, 3, 0, 0 },
  { 562, 2, 9, 2, 8208, 3, 0, 0 },
  { 584, 2, 9, 2, 8209, 3, 0, 0 },
  { 606, 2, 9, 2, 8210, 3, 0, 0 },
  { 628, 2, 9, 2, 8211, 3, 0, 0 },
  { 896, 2, 9, 2, 8212, 3, 0, 0 },
  { 11, 2, 9, 2, 8213, 3, 0, 0 },
  { 38, 2, 9, 2, 8214, 3, 0, 0 },
  { 68, 2, 9, 2, 8215, 3, 0, 0 },
  { 312, 2, 9, 2, 8216, 3, 0, 0 },
  { 334, 2, 9, 2, 8217, 3, 0, 0 },
  { 570, 2, 9, 2, 8218, 3, 0, 0 },
  { 592, 2, 9, 2, 8219, 3, 0, 0 },
  { 614, 2, 9, 2, 8220, 3, 0, 0 },
  { 882, 2, 9, 2, 8221, 3, 0, 0 },
  { 904, 2, 9, 2, 8222, 3, 0, 0 },
  { 19, 2, 9, 2, 8223, 3, 0, 0 },
  { 46, 2, 9, 2, 8224, 3, 0, 0 },
  { 76, 2, 12, 2, 8225, 3, 0, 0 },
  { 101, 2, 6, 2, 8226, 3, 0, 0 },
  { 359, 1, 4, 1, 8226, 0, 0, 0 },
  { 656, 0, 2, 0, 8226, 0, 0, 0 },
  { 128, 2, 6, 2, 8227, 3, 0, 0 },
  { 386, 1, 4, 1, 8227, 0, 0, 0 },
  { 687, 0, 2, 0, 8227, 0, 0, 0 },
  { 148, 2, 6, 2, 8228, 3, 0, 0 },
  { 406, 1, 4, 1, 8228, 0, 0, 0 },
  { 710, 0, 2, 0, 8228, 0, 0, 0 },
  { 168, 2, 6, 2, 8229, 3, 0, 0 },
  { 426, 1, 4, 1, 8229, 0, 0, 0 },
  { 733, 0, 2, 0, 8229, 0, 0, 0 },
  { 188, 2, 6, 2, 8230, 3, 0, 0 },
  { 446, 1, 4, 1, 8230, 0, 0, 0 },
  { 756, 0, 2, 0, 8230, 0, 0, 0 },
  { 208, 2, 6, 2, 8231, 3, 0, 0 },
  { 466, 1, 4, 1, 8231, 0, 0, 0 },
  { 779, 0, 2, 0, 8231, 0, 0, 0 },
  { 228, 2, 6, 2, 8232, 3, 0, 0 },
  { 486, 1, 4, 1, 8232, 0, 0, 0 },
  { 802, 0, 2, 0, 8232, 0, 0, 0 },
  { 248, 2, 6, 2, 8233, 3, 0, 0 },
  { 506, 1, 4, 1, 8233, 0, 0, 0 },
  { 825, 0, 2, 0, 8233, 0, 0, 0 },
  { 268, 2, 6, 2, 8234, 3, 0, 0 },
  { 526, 1, 4, 1, 8234, 0, 0, 0 },
  { 848, 0, 2, 0, 8234, 0, 0, 0 },
  { 288, 2, 6, 2, 8235, 3, 0, 0 },
  { 546, 1, 4, 1, 8235, 0, 0, 0 },
  { 871, 0, 2, 0, 8235, 0, 0, 0 },
  { 80, 2, 6, 2, 8236, 3, 0, 0 },
  { 338, 1, 4, 1, 8236, 0, 0, 0 },
  { 632, 0, 2, 0, 8236, 0, 0, 0 },
  { 107, 2, 6, 2, 8237, 3, 0, 0 },
  { 365, 1, 4, 1, 8237, 0, 0, 0 },
  { 663, 0, 2, 0, 8237, 0, 0, 0 },
  { 134, 2, 6, 2, 8238, 3, 0, 0 },
  { 392, 1, 4, 1, 8238, 0, 0, 0 },
  { 694, 0, 2, 0, 8238, 0, 0, 0 },
  { 154, 2, 6, 2, 8239, 3, 0, 0 },
  { 412, 1, 4, 1, 8239, 0, 0, 0 },
  { 717, 0, 2, 0, 8239, 0, 0, 0 },
  { 174, 2, 6, 2, 8240, 3, 0, 0 },
  { 432, 1, 4, 1, 8240, 0, 0, 0 },
  { 740, 0, 2, 0, 8240, 0, 0, 0 },
  { 194, 2, 6, 2, 8241, 3, 0, 0 },
  { 452, 1, 4, 1, 8241, 0, 0, 0 },
  { 763, 0, 2, 0, 8241, 0, 0, 0 },
  { 214, 2, 6, 2, 8242, 3, 0, 0 },
  { 472, 1, 4, 1, 8242, 0, 0, 0 },
  { 786, 0, 2, 0, 8242, 0, 0, 0 },
  { 234, 2, 6, 2, 8243, 3, 0, 0 },
  { 492, 1, 4, 1, 8243, 0, 0, 0 },
  { 809, 0, 2, 0, 8243, 0, 0, 0 },
  { 254, 2, 6, 2, 8244, 3, 0, 0 },
  { 512, 1, 4, 1, 8244, 0, 0, 0 },
  { 832, 0, 2, 0, 8244, 0, 0, 0 },
  { 274, 2, 6, 2, 8245, 3, 0, 0 },
  { 532, 1, 4, 1, 8245, 0, 0, 0 },
  { 855, 0, 2, 0, 8245, 0, 0, 0 },
  { 87, 2, 6, 2, 8246, 3, 0, 0 },
  { 345, 1, 4, 1, 8246, 0, 0, 0 },
  { 640, 0, 2, 0, 8246, 0, 0, 0 },
  { 114, 2, 6, 2, 8247, 3, 0, 0 },
  { 372, 1, 4, 1, 8247, 0, 0, 0 },
  { 671, 0, 2, 0, 8247, 0, 0, 0 },
  { 141, 2, 6, 2, 8248, 3, 0, 0 },
  { 399, 1, 4, 1, 8248, 0, 0, 0 },
  { 702, 0, 2, 0, 8248, 0, 0, 0 },
  { 161, 2, 6, 2, 8249, 3, 0, 0 },
  { 419, 1, 4, 1, 8249, 0, 0, 0 },
  { 725, 0, 2, 0, 8249, 0, 0, 0 },
  { 181, 2, 6, 2, 8250, 3, 0, 0 },
  { 439, 1, 4, 1, 8250, 0, 0, 0 },
  { 748, 0, 2, 0, 8250, 0, 0, 0 },
  { 201, 2, 6, 2, 8251, 3, 0, 0 },
  { 459, 1, 4, 1, 8251, 0, 0, 0 },
  { 771, 0, 2, 0, 8251, 0, 0, 0 },
  { 221, 2, 6, 2, 8252, 3, 0, 0 },
  { 479, 1, 4, 1, 8252, 0, 0, 0 },
  { 794, 0, 2, 0, 8252, 0, 0, 0 },
  { 241, 2, 6, 2, 8253, 3, 0, 0 },
  { 499, 1, 4, 1, 8253, 0, 0, 0 },
  { 817, 0, 2, 0, 8253, 0, 0, 0 },
  { 261, 2, 6, 2, 8254, 3, 0, 0 },
  { 519, 1, 4, 1, 8254, 0, 0, 0 },
  { 840, 0, 2, 0, 8254, 0, 0, 0 },
  { 281, 2, 6, 2, 8255, 3, 0, 0 },
  { 539, 1, 4, 1, 8255, 0, 0, 0 },
  { 863, 0, 2, 0, 8255, 0, 0, 0 },
  { 94, 2, 6, 2, 8256, 3, 0, 0 },
  { 352, 1, 4, 1, 8256, 0, 0, 0 },
  { 648, 0, 2, 0, 8256, 0, 0, 0 },
  { 121, 2, 6, 2, 8257, 3, 0, 0 },
  { 379, 1, 4, 1, 8257, 0, 0, 0 },
  { 679, 0, 2, 0, 8257, 0, 0, 0 },
  { 50, 3, 2, 2, 16385, 1, 0, 0 },
  { 294, 3, 2, 2, 16386, 1, 0, 0 },
  { 316, 3, 2, 2, 16387, 1, 0, 0 },
  { 552, 3, 2, 2, 16388, 1, 0, 0 },
  { 574, 3, 2, 2, 16389, 1, 0, 0 },
  { 596, 3, 2, 2, 16390, 1, 0, 0 },
  { 618, 3, 2, 2, 16391, 1, 0, 0 },
  { 886, 3, 2, 2, 16392, 1, 0, 0 },
  { 908, 3, 2, 2, 16393, 1, 0, 0 },
  { 0, 3, 2, 2, 16394, 1, 0, 0 },
  { 26, 3, 2, 2, 16395, 1, 0, 0 },
  { 56, 3, 2, 2, 16396, 1, 0, 0 },
  { 300, 3, 2, 2, 16397, 1, 0, 0 },
  { 322, 3, 2, 2, 16398, 1, 0, 0 },
  { 558, 3, 2, 2, 16399, 1, 0, 0 },
  { 580, 3, 2, 2, 16400, 1, 0, 0 },
  { 602, 3, 2, 2, 16401, 1, 0, 0 },
  { 624, 3, 2, 2, 16402, 1, 0, 0 },
  { 892, 3, 2, 2, 16403, 1, 0, 0 },
  { 7, 3, 2, 2, 16404, 1, 0, 0 },
  { 34, 3, 2, 2, 16405, 1, 0, 0 },
  { 64, 3, 2, 2, 16406, 1, 0, 0 },
  { 308, 3, 2, 2, 16407, 1, 0, 0 },
  { 330, 3, 2, 2, 16408, 1, 0, 0 },
  { 566, 3, 2, 2, 16409, 1, 0, 0 },
  { 588, 3, 2, 2, 16410, 1, 0, 0 },
  { 610, 3, 2, 2, 16411, 1, 0, 0 },
  { 878, 3, 2, 2, 16412, 1, 0, 0 },
  { 900, 3, 2, 2, 16413, 1, 0, 0 },
  { 15, 3, 2, 2, 16414, 1, 0, 0 },
  { 42, 3, 2, 2, 16415, 1, 0, 0 },
  { 72, 3, 2, 2, 16416, 1, 0, 0 },
};

extern const MCPhysReg CSKYRegUnitRoots[][2] = {
  { CSKY::C },
  { CSKY::R0 },
  { CSKY::R1 },
  { CSKY::R2 },
  { CSKY::R3 },
  { CSKY::R4 },
  { CSKY::R5 },
  { CSKY::R6 },
  { CSKY::R7 },
  { CSKY::R8 },
  { CSKY::R9 },
  { CSKY::R10 },
  { CSKY::R11 },
  { CSKY::R12 },
  { CSKY::R13 },
  { CSKY::R14 },
  { CSKY::R15 },
  { CSKY::R16 },
  { CSKY::R17 },
  { CSKY::R18 },
  { CSKY::R19 },
  { CSKY::R20 },
  { CSKY::R21 },
  { CSKY::R22 },
  { CSKY::R23 },
  { CSKY::R24 },
  { CSKY::R25 },
  { CSKY::R26 },
  { CSKY::R27 },
  { CSKY::R28 },
  { CSKY::R29 },
  { CSKY::R30 },
  { CSKY::R31 },
  { CSKY::R32 },
  { CSKY::F0_32 },
  { CSKY::F1_32 },
  { CSKY::F2_32 },
  { CSKY::F3_32 },
  { CSKY::F4_32 },
  { CSKY::F5_32 },
  { CSKY::F6_32 },
  { CSKY::F7_32 },
  { CSKY::F8_32 },
  { CSKY::F9_32 },
  { CSKY::F10_32 },
  { CSKY::F11_32 },
  { CSKY::F12_32 },
  { CSKY::F13_32 },
  { CSKY::F14_32 },
  { CSKY::F15_32 },
  { CSKY::F16_32 },
  { CSKY::F17_32 },
  { CSKY::F18_32 },
  { CSKY::F19_32 },
  { CSKY::F20_32 },
  { CSKY::F21_32 },
  { CSKY::F22_32 },
  { CSKY::F23_32 },
  { CSKY::F24_32 },
  { CSKY::F25_32 },
  { CSKY::F26_32 },
  { CSKY::F27_32 },
  { CSKY::F28_32 },
  { CSKY::F29_32 },
  { CSKY::F30_32 },
  { CSKY::F31_32 },
};

// Register classes...

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"
#endif
extern const char CSKYRegClassStrings[] = {
  /* 0 */ "sFPR32\000"
  /* 7 */ "sFPR64\000"
  /* 14 */ "sFPR128\000"
  /* 22 */ "GPRPair_with_sub32_0_in_GPRSP\000"
  /* 52 */ "GPRPair_with_sub32_32_in_GPRSP\000"
  /* 83 */ "GPRPair_with_sub32_32_in_GPR\000"
  /* 112 */ "GPRPair_with_sub32_0_in_mGPR\000"
  /* 141 */ "GPRPair_with_sub32_32_in_mGPR\000"
  /* 171 */ "GPRPair_with_sub32_0_in_sGPR\000"
  /* 200 */ "GPRPair_with_sub32_32_in_sGPR\000"
  /* 230 */ "sFPR64_V\000"
  /* 239 */ "CARRY\000"
  /* 245 */ "GPRPair\000"
};
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

using CSKYRegisterClassStorage = MCRegisterClassStorage<20, 329, 263, 33, 7, 34>;
extern const MCRegisterClassStorage<20, 329, 263, 33, 7, 34> CSKYMCRegisterClassStorage = {
  {
    {
      offsetof(CSKYRegisterClassStorage, Regs[0]) - 0 * sizeof(MCRegisterClass),
      offsetof(CSKYRegisterClassStorage, BitSets[0]) - 0 * sizeof(MCRegisterClass),
      1,
      32,
      32,
      17,
      CSKY::FPR32RegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(CSKYRegisterClassStorage, SubClassMasks[0]) - 0 * sizeof(MCRegisterClass),
      offsetof(CSKYRegisterClassStorage, SuperRegIdxSeqs[0]) - 0 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(CSKYRegisterClassStorage, SuperClasses[0]) - 0 * sizeof(MCRegisterClass),
      0
    },
    {
      offsetof(CSKYRegisterClassStorage, Regs[32]) - 1 * sizeof(MCRegisterClass),
      offsetof(CSKYRegisterClassStorage, BitSets[17]) - 1 * sizeof(MCRegisterClass),
      108,
      32,
      32,
      5,
      CSKY::GPRRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(CSKYRegisterClassStorage, SubClassMasks[2]) - 1 * sizeof(MCRegisterClass),
      offsetof(CSKYRegisterClassStorage, SuperRegIdxSeqs[2]) - 1 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(CSKYRegisterClassStorage, SuperClasses[0]) - 1 * sizeof(MCRegisterClass),
      0
    },
    {
      offsetof(CSKYRegisterClassStorage, Regs[64]) - 2 * sizeof(MCRegisterClass),
      offsetof(CSKYRegisterClassStorage, BitSets[22]) - 2 * sizeof(MCRegisterClass),
      0,
      32,
      16,
      11,
      CSKY::sFPR32RegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(CSKYRegisterClassStorage, SubClassMasks[5]) - 2 * sizeof(MCRegisterClass),
      offsetof(CSKYRegisterClassStorage, SuperRegIdxSeqs[0]) - 2 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(CSKYRegisterClassStorage, SuperClasses[0]) - 2 * sizeof(MCRegisterClass),
      1
    },
    {
      offsetof(CSKYRegisterClassStorage, Regs[80]) - 3 * sizeof(MCRegisterClass),
      offsetof(CSKYRegisterClassStorage, BitSets[33]) - 3 * sizeof(MCRegisterClass),
      195,
      32,
      16,
      3,
      CSKY::sGPRRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(CSKYRegisterClassStorage, SubClassMasks[7]) - 3 * sizeof(MCRegisterClass),
      offsetof(CSKYRegisterClassStorage, SuperRegIdxSeqs[2]) - 3 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(CSKYRegisterClassStorage, SuperClasses[1]) - 3 * sizeof(MCRegisterClass),
      1
    },
    {
      offsetof(CSKYRegisterClassStorage, Regs[96]) - 4 * sizeof(MCRegisterClass),
      offsetof(CSKYRegisterClassStorage, BitSets[36]) - 4 * sizeof(MCRegisterClass),
      136,
      32,
      8,
      2,
      CSKY::mGPRRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(CSKYRegisterClassStorage, SubClassMasks[10]) - 4 * sizeof(MCRegisterClass),
      offsetof(CSKYRegisterClassStorage, SuperRegIdxSeqs[2]) - 4 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(CSKYRegisterClassStorage, SuperClasses[2]) - 4 * sizeof(MCRegisterClass),
      2
    },
    {
      offsetof(CSKYRegisterClassStorage, Regs[104]) - 5 * sizeof(MCRegisterClass),
      offsetof(CSKYRegisterClassStorage, BitSets[38]) - 5 * sizeof(MCRegisterClass),
      239,
      32,
      1,
      1,
      CSKY::CARRYRegClassID,
      255, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(CSKYRegisterClassStorage, SubClassMasks[13]) - 5 * sizeof(MCRegisterClass),
      offsetof(CSKYRegisterClassStorage, SuperRegIdxSeqs[1]) - 5 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(CSKYRegisterClassStorage, SuperClasses[4]) - 5 * sizeof(MCRegisterClass),
      0
    },
    {
      offsetof(CSKYRegisterClassStorage, Regs[105]) - 6 * sizeof(MCRegisterClass),
      offsetof(CSKYRegisterClassStorage, BitSets[39]) - 6 * sizeof(MCRegisterClass),
      46,
      32,
      1,
      3,
      CSKY::GPRSPRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(CSKYRegisterClassStorage, SubClassMasks[14]) - 6 * sizeof(MCRegisterClass),
      offsetof(CSKYRegisterClassStorage, SuperRegIdxSeqs[2]) - 6 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(CSKYRegisterClassStorage, SuperClasses[4]) - 6 * sizeof(MCRegisterClass),
      2
    },
    {
      offsetof(CSKYRegisterClassStorage, Regs[106]) - 7 * sizeof(MCRegisterClass),
      offsetof(CSKYRegisterClassStorage, BitSets[42]) - 7 * sizeof(MCRegisterClass),
      8,
      64,
      32,
      17,
      CSKY::FPR64RegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(CSKYRegisterClassStorage, SubClassMasks[17]) - 7 * sizeof(MCRegisterClass),
      offsetof(CSKYRegisterClassStorage, SuperRegIdxSeqs[5]) - 7 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(CSKYRegisterClassStorage, SuperClasses[6]) - 7 * sizeof(MCRegisterClass),
      0
    },
    {
      offsetof(CSKYRegisterClassStorage, Regs[138]) - 8 * sizeof(MCRegisterClass),
      offsetof(CSKYRegisterClassStorage, BitSets[59]) - 8 * sizeof(MCRegisterClass),
      245,
      64,
      32,
      21,
      CSKY::GPRPairRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(CSKYRegisterClassStorage, SubClassMasks[19]) - 8 * sizeof(MCRegisterClass),
      offsetof(CSKYRegisterClassStorage, SuperRegIdxSeqs[1]) - 8 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000003),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      true, /* HasDisjunctSubRegs */
      true, /* CoveredBySubRegs */
      offsetof(CSKYRegisterClassStorage, SuperClasses[6]) - 8 * sizeof(MCRegisterClass),
      0
    },
    {
      offsetof(CSKYRegisterClassStorage, Regs[170]) - 9 * sizeof(MCRegisterClass),
      offsetof(CSKYRegisterClassStorage, BitSets[80]) - 9 * sizeof(MCRegisterClass),
      83,
      64,
      31,
      21,
      CSKY::GPRPair_with_sub32_32_in_GPRRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(CSKYRegisterClassStorage, SubClassMasks[20]) - 9 * sizeof(MCRegisterClass),
      offsetof(CSKYRegisterClassStorage, SuperRegIdxSeqs[1]) - 9 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000003),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      true, /* HasDisjunctSubRegs */
      true, /* CoveredBySubRegs */
      offsetof(CSKYRegisterClassStorage, SuperClasses[6]) - 9 * sizeof(MCRegisterClass),
      1
    },
    {
      offsetof(CSKYRegisterClassStorage, Regs[201]) - 10 * sizeof(MCRegisterClass),
      offsetof(CSKYRegisterClassStorage, BitSets[101]) - 10 * sizeof(MCRegisterClass),
      171,
      64,
      16,
      19,
      CSKY::GPRPair_with_sub32_0_in_sGPRRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(CSKYRegisterClassStorage, SubClassMasks[21]) - 10 * sizeof(MCRegisterClass),
      offsetof(CSKYRegisterClassStorage, SuperRegIdxSeqs[1]) - 10 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000003),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      true, /* HasDisjunctSubRegs */
      true, /* CoveredBySubRegs */
      offsetof(CSKYRegisterClassStorage, SuperClasses[7]) - 10 * sizeof(MCRegisterClass),
      2
    },
    {
      offsetof(CSKYRegisterClassStorage, Regs[217]) - 11 * sizeof(MCRegisterClass),
      offsetof(CSKYRegisterClassStorage, BitSets[120]) - 11 * sizeof(MCRegisterClass),
      7,
      64,
      16,
      11,
      CSKY::sFPR64RegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(CSKYRegisterClassStorage, SubClassMasks[22]) - 11 * sizeof(MCRegisterClass),
      offsetof(CSKYRegisterClassStorage, SuperRegIdxSeqs[5]) - 11 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(CSKYRegisterClassStorage, SuperClasses[9]) - 11 * sizeof(MCRegisterClass),
      2
    },
    {
      offsetof(CSKYRegisterClassStorage, Regs[233]) - 12 * sizeof(MCRegisterClass),
      offsetof(CSKYRegisterClassStorage, BitSets[131]) - 12 * sizeof(MCRegisterClass),
      230,
      64,
      16,
      11,
      CSKY::sFPR64_VRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(CSKYRegisterClassStorage, SubClassMasks[24]) - 12 * sizeof(MCRegisterClass),
      offsetof(CSKYRegisterClassStorage, SuperRegIdxSeqs[5]) - 12 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(CSKYRegisterClassStorage, SuperClasses[11]) - 12 * sizeof(MCRegisterClass),
      2
    },
    {
      offsetof(CSKYRegisterClassStorage, Regs[249]) - 13 * sizeof(MCRegisterClass),
      offsetof(CSKYRegisterClassStorage, BitSets[142]) - 13 * sizeof(MCRegisterClass),
      200,
      64,
      15,
      19,
      CSKY::GPRPair_with_sub32_32_in_sGPRRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(CSKYRegisterClassStorage, SubClassMasks[26]) - 13 * sizeof(MCRegisterClass),
      offsetof(CSKYRegisterClassStorage, SuperRegIdxSeqs[1]) - 13 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000003),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      true, /* HasDisjunctSubRegs */
      true, /* CoveredBySubRegs */
      offsetof(CSKYRegisterClassStorage, SuperClasses[13]) - 13 * sizeof(MCRegisterClass),
      3
    },
    {
      offsetof(CSKYRegisterClassStorage, Regs[264]) - 14 * sizeof(MCRegisterClass),
      offsetof(CSKYRegisterClassStorage, BitSets[161]) - 14 * sizeof(MCRegisterClass),
      112,
      64,
      8,
      18,
      CSKY::GPRPair_with_sub32_0_in_mGPRRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(CSKYRegisterClassStorage, SubClassMasks[27]) - 14 * sizeof(MCRegisterClass),
      offsetof(CSKYRegisterClassStorage, SuperRegIdxSeqs[1]) - 14 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000003),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      true, /* HasDisjunctSubRegs */
      true, /* CoveredBySubRegs */
      offsetof(CSKYRegisterClassStorage, SuperClasses[16]) - 14 * sizeof(MCRegisterClass),
      4
    },
    {
      offsetof(CSKYRegisterClassStorage, Regs[272]) - 15 * sizeof(MCRegisterClass),
      offsetof(CSKYRegisterClassStorage, BitSets[179]) - 15 * sizeof(MCRegisterClass),
      141,
      64,
      7,
      18,
      CSKY::GPRPair_with_sub32_32_in_mGPRRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(CSKYRegisterClassStorage, SubClassMasks[28]) - 15 * sizeof(MCRegisterClass),
      offsetof(CSKYRegisterClassStorage, SuperRegIdxSeqs[1]) - 15 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000003),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      true, /* HasDisjunctSubRegs */
      true, /* CoveredBySubRegs */
      offsetof(CSKYRegisterClassStorage, SuperClasses[20]) - 15 * sizeof(MCRegisterClass),
      5
    },
    {
      offsetof(CSKYRegisterClassStorage, Regs[279]) - 16 * sizeof(MCRegisterClass),
      offsetof(CSKYRegisterClassStorage, BitSets[197]) - 16 * sizeof(MCRegisterClass),
      22,
      64,
      1,
      19,
      CSKY::GPRPair_with_sub32_0_in_GPRSPRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(CSKYRegisterClassStorage, SubClassMasks[29]) - 16 * sizeof(MCRegisterClass),
      offsetof(CSKYRegisterClassStorage, SuperRegIdxSeqs[1]) - 16 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000003),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      true, /* HasDisjunctSubRegs */
      true, /* CoveredBySubRegs */
      offsetof(CSKYRegisterClassStorage, SuperClasses[25]) - 16 * sizeof(MCRegisterClass),
      4
    },
    {
      offsetof(CSKYRegisterClassStorage, Regs[280]) - 17 * sizeof(MCRegisterClass),
      offsetof(CSKYRegisterClassStorage, BitSets[216]) - 17 * sizeof(MCRegisterClass),
      52,
      64,
      1,
      19,
      CSKY::GPRPair_with_sub32_32_in_GPRSPRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(CSKYRegisterClassStorage, SubClassMasks[30]) - 17 * sizeof(MCRegisterClass),
      offsetof(CSKYRegisterClassStorage, SuperRegIdxSeqs[1]) - 17 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000003),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      true, /* HasDisjunctSubRegs */
      true, /* CoveredBySubRegs */
      offsetof(CSKYRegisterClassStorage, SuperClasses[29]) - 17 * sizeof(MCRegisterClass),
      4
    },
    {
      offsetof(CSKYRegisterClassStorage, Regs[281]) - 18 * sizeof(MCRegisterClass),
      offsetof(CSKYRegisterClassStorage, BitSets[235]) - 18 * sizeof(MCRegisterClass),
      15,
      128,
      32,
      17,
      CSKY::FPR128RegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(CSKYRegisterClassStorage, SubClassMasks[31]) - 18 * sizeof(MCRegisterClass),
      offsetof(CSKYRegisterClassStorage, SuperRegIdxSeqs[1]) - 18 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(CSKYRegisterClassStorage, SuperClasses[33]) - 18 * sizeof(MCRegisterClass),
      0
    },
    {
      offsetof(CSKYRegisterClassStorage, Regs[313]) - 19 * sizeof(MCRegisterClass),
      offsetof(CSKYRegisterClassStorage, BitSets[252]) - 19 * sizeof(MCRegisterClass),
      14,
      128,
      16,
      11,
      CSKY::sFPR128RegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(CSKYRegisterClassStorage, SubClassMasks[32]) - 19 * sizeof(MCRegisterClass),
      offsetof(CSKYRegisterClassStorage, SuperRegIdxSeqs[1]) - 19 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(CSKYRegisterClassStorage, SuperClasses[33]) - 19 * sizeof(MCRegisterClass),
      1
    },
  },
  {
    /* 0 */ CSKY::F0_32, CSKY::F1_32, CSKY::F2_32, CSKY::F3_32, CSKY::F4_32, CSKY::F5_32, CSKY::F6_32, CSKY::F7_32, CSKY::F8_32, CSKY::F9_32, CSKY::F10_32, CSKY::F11_32, CSKY::F12_32, CSKY::F13_32, CSKY::F14_32, CSKY::F15_32, CSKY::F16_32, CSKY::F17_32, CSKY::F18_32, CSKY::F19_32, CSKY::F20_32, CSKY::F21_32, CSKY::F22_32, CSKY::F23_32, CSKY::F24_32, CSKY::F25_32, CSKY::F26_32, CSKY::F27_32, CSKY::F28_32, CSKY::F29_32, CSKY::F30_32, CSKY::F31_32, 
    /* 32 */ CSKY::R0, CSKY::R1, CSKY::R2, CSKY::R3, CSKY::R12, CSKY::R13, CSKY::R18, CSKY::R19, CSKY::R20, CSKY::R21, CSKY::R22, CSKY::R23, CSKY::R24, CSKY::R25, CSKY::R15, CSKY::R4, CSKY::R5, CSKY::R6, CSKY::R7, CSKY::R8, CSKY::R9, CSKY::R10, CSKY::R11, CSKY::R16, CSKY::R17, CSKY::R26, CSKY::R27, CSKY::R28, CSKY::R29, CSKY::R30, CSKY::R14, CSKY::R31, 
    /* 64 */ CSKY::F0_32, CSKY::F1_32, CSKY::F2_32, CSKY::F3_32, CSKY::F4_32, CSKY::F5_32, CSKY::F6_32, CSKY::F7_32, CSKY::F8_32, CSKY::F9_32, CSKY::F10_32, CSKY::F11_32, CSKY::F12_32, CSKY::F13_32, CSKY::F14_32, CSKY::F15_32, 
    /* 80 */ CSKY::R0, CSKY::R1, CSKY::R2, CSKY::R3, CSKY::R12, CSKY::R13, CSKY::R15, CSKY::R4, CSKY::R5, CSKY::R6, CSKY::R7, CSKY::R8, CSKY::R9, CSKY::R10, CSKY::R11, CSKY::R14, 
    /* 96 */ CSKY::R0, CSKY::R1, CSKY::R2, CSKY::R3, CSKY::R4, CSKY::R5, CSKY::R6, CSKY::R7, 
    /* 104 */ CSKY::C, 
    /* 105 */ CSKY::R14, 
    /* 106 */ CSKY::F0_64, CSKY::F1_64, CSKY::F2_64, CSKY::F3_64, CSKY::F4_64, CSKY::F5_64, CSKY::F6_64, CSKY::F7_64, CSKY::F8_64, CSKY::F9_64, CSKY::F10_64, CSKY::F11_64, CSKY::F12_64, CSKY::F13_64, CSKY::F14_64, CSKY::F15_64, CSKY::F16_64, CSKY::F17_64, CSKY::F18_64, CSKY::F19_64, CSKY::F20_64, CSKY::F21_64, CSKY::F22_64, CSKY::F23_64, CSKY::F24_64, CSKY::F25_64, CSKY::F26_64, CSKY::F27_64, CSKY::F28_64, CSKY::F29_64, CSKY::F30_64, CSKY::F31_64, 
    /* 138 */ CSKY::R0_R1, CSKY::R1_R2, CSKY::R2_R3, CSKY::R3_R4, CSKY::R4_R5, CSKY::R5_R6, CSKY::R6_R7, CSKY::R7_R8, CSKY::R8_R9, CSKY::R9_R10, CSKY::R10_R11, CSKY::R11_R12, CSKY::R12_R13, CSKY::R13_R14, CSKY::R14_R15, CSKY::R15_R16, CSKY::R16_R17, CSKY::R17_R18, CSKY::R18_R19, CSKY::R19_R20, CSKY::R20_R21, CSKY::R21_R22, CSKY::R22_R23, CSKY::R23_R24, CSKY::R24_R25, CSKY::R25_R26, CSKY::R26_R27, CSKY::R27_R28, CSKY::R28_R29, CSKY::R29_R30, CSKY::R30_R31, CSKY::R31_R32, 
    /* 170 */ CSKY::R0_R1, CSKY::R1_R2, CSKY::R2_R3, CSKY::R3_R4, CSKY::R4_R5, CSKY::R5_R6, CSKY::R6_R7, CSKY::R7_R8, CSKY::R8_R9, CSKY::R9_R10, CSKY::R10_R11, CSKY::R11_R12, CSKY::R12_R13, CSKY::R13_R14, CSKY::R14_R15, CSKY::R15_R16, CSKY::R16_R17, CSKY::R17_R18, CSKY::R18_R19, CSKY::R19_R20, CSKY::R20_R21, CSKY::R21_R22, CSKY::R22_R23, CSKY::R23_R24, CSKY::R24_R25, CSKY::R25_R26, CSKY::R26_R27, CSKY::R27_R28, CSKY::R28_R29, CSKY::R29_R30, CSKY::R30_R31, 
    /* 201 */ CSKY::R0_R1, CSKY::R1_R2, CSKY::R2_R3, CSKY::R3_R4, CSKY::R4_R5, CSKY::R5_R6, CSKY::R6_R7, CSKY::R7_R8, CSKY::R8_R9, CSKY::R9_R10, CSKY::R10_R11, CSKY::R11_R12, CSKY::R12_R13, CSKY::R13_R14, CSKY::R14_R15, CSKY::R15_R16, 
    /* 217 */ CSKY::F0_64, CSKY::F1_64, CSKY::F2_64, CSKY::F3_64, CSKY::F4_64, CSKY::F5_64, CSKY::F6_64, CSKY::F7_64, CSKY::F8_64, CSKY::F9_64, CSKY::F10_64, CSKY::F11_64, CSKY::F12_64, CSKY::F13_64, CSKY::F14_64, CSKY::F15_64, 
    /* 233 */ CSKY::F0_64, CSKY::F1_64, CSKY::F2_64, CSKY::F3_64, CSKY::F4_64, CSKY::F5_64, CSKY::F6_64, CSKY::F7_64, CSKY::F8_64, CSKY::F9_64, CSKY::F10_64, CSKY::F11_64, CSKY::F12_64, CSKY::F13_64, CSKY::F14_64, CSKY::F15_64, 
    /* 249 */ CSKY::R0_R1, CSKY::R1_R2, CSKY::R2_R3, CSKY::R3_R4, CSKY::R4_R5, CSKY::R5_R6, CSKY::R6_R7, CSKY::R7_R8, CSKY::R8_R9, CSKY::R9_R10, CSKY::R10_R11, CSKY::R11_R12, CSKY::R12_R13, CSKY::R13_R14, CSKY::R14_R15, 
    /* 264 */ CSKY::R0_R1, CSKY::R1_R2, CSKY::R2_R3, CSKY::R3_R4, CSKY::R4_R5, CSKY::R5_R6, CSKY::R6_R7, CSKY::R7_R8, 
    /* 272 */ CSKY::R0_R1, CSKY::R1_R2, CSKY::R2_R3, CSKY::R3_R4, CSKY::R4_R5, CSKY::R5_R6, CSKY::R6_R7, 
    /* 279 */ CSKY::R14_R15, 
    /* 280 */ CSKY::R13_R14, 
    /* 281 */ CSKY::F0_128, CSKY::F1_128, CSKY::F2_128, CSKY::F3_128, CSKY::F4_128, CSKY::F5_128, CSKY::F6_128, CSKY::F7_128, CSKY::F8_128, CSKY::F9_128, CSKY::F10_128, CSKY::F11_128, CSKY::F12_128, CSKY::F13_128, CSKY::F14_128, CSKY::F15_128, CSKY::F16_128, CSKY::F17_128, CSKY::F18_128, CSKY::F19_128, CSKY::F20_128, CSKY::F21_128, CSKY::F22_128, CSKY::F23_128, CSKY::F24_128, CSKY::F25_128, CSKY::F26_128, CSKY::F27_128, CSKY::F28_128, CSKY::F29_128, CSKY::F30_128, CSKY::F31_128, 
    /* 313 */ CSKY::F0_128, CSKY::F1_128, CSKY::F2_128, CSKY::F3_128, CSKY::F4_128, CSKY::F5_128, CSKY::F6_128, CSKY::F7_128, CSKY::F8_128, CSKY::F9_128, CSKY::F10_128, CSKY::F11_128, CSKY::F12_128, CSKY::F13_128, CSKY::F14_128, CSKY::F15_128, 
  },
  {
    /* 0 */ 0x00, 0x00, 0x00, 0x00, 0x48, 0x92, 0x24, 0x49, 0x92, 0x24, 0x49, 0x92, 0x24, 0x49, 0x92, 0x24, 0x01, 
    /* 17 */ 0xfc, 0xff, 0xff, 0xff, 0x03, 
    /* 22 */ 0x00, 0x00, 0x00, 0x00, 0x48, 0x92, 0x24, 0x49, 0x92, 0x24, 0x01, 
    /* 33 */ 0xfc, 0xff, 0x03, 
    /* 36 */ 0xfc, 0x03, 
    /* 38 */ 0x02, 
    /* 39 */ 0x00, 0x00, 0x01, 
    /* 42 */ 0x00, 0x00, 0x00, 0x00, 0x90, 0x24, 0x49, 0x92, 0x24, 0x49, 0x92, 0x24, 0x49, 0x92, 0x24, 0x49, 0x02, 
    /* 59 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xff, 0xff, 0x07, 
    /* 80 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xff, 0xff, 0x03, 
    /* 101 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0x07, 
    /* 120 */ 0x00, 0x00, 0x00, 0x00, 0x90, 0x24, 0x49, 0x92, 0x24, 0x49, 0x02, 
    /* 131 */ 0x00, 0x00, 0x00, 0x00, 0x90, 0x24, 0x49, 0x92, 0x24, 0x49, 0x02, 
    /* 142 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0x03, 
    /* 161 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0x07, 
    /* 179 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0x03, 
    /* 197 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 
    /* 216 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 
    /* 235 */ 0x00, 0x00, 0x00, 0x00, 0x20, 0x49, 0x92, 0x24, 0x49, 0x92, 0x24, 0x49, 0x92, 0x24, 0x49, 0x92, 0x04, 
    /* 252 */ 0x00, 0x00, 0x00, 0x00, 0x20, 0x49, 0x92, 0x24, 0x49, 0x92, 0x04, 
  },
  {
    // 0 FPR32
    0x00000005, 
    0x000c1880, // sub32_0
    // 2 GPR
    0x0000005a, 
    0x0003e700, // sub32_0
    0x0003e600, // sub32_32
    // 5 sFPR32
    0x00000004, 
    0x00081800, // sub32_0
    // 7 sGPR
    0x00000058, 
    0x0003e400, // sub32_0
    0x0003e000, // sub32_32
    // 10 mGPR
    0x00000010, 
    0x0000c000, // sub32_0
    0x00008000, // sub32_32
    // 13 CARRY
    0x00000020, 
    // 14 GPRSP
    0x00000040, 
    0x00010000, // sub32_0
    0x00020000, // sub32_32
    // 17 FPR64
    0x00001880, 
    0x000c0000, // sub64_0
    // 19 GPRPair
    0x0003e700, 
    // 20 GPRPair_with_sub32_32_in_GPR
    0x0003e600, 
    // 21 GPRPair_with_sub32_0_in_sGPR
    0x0003e400, 
    // 22 sFPR64
    0x00001800, 
    0x00080000, // sub64_0
    // 24 sFPR64_V
    0x00001800, 
    0x00080000, // sub64_0
    // 26 GPRPair_with_sub32_32_in_sGPR
    0x0003e000, 
    // 27 GPRPair_with_sub32_0_in_mGPR
    0x0000c000, 
    // 28 GPRPair_with_sub32_32_in_mGPR
    0x00008000, 
    // 29 GPRPair_with_sub32_0_in_GPRSP
    0x00010000, 
    // 30 GPRPair_with_sub32_32_in_GPRSP
    0x00020000, 
    // 31 FPR128
    0x000c0000, 
    // 32 sFPR128
    0x00080000, 
  },
  {
  /* 0 */ 1, 0,
  /* 2 */ 1, 2, 0,
  /* 5 */ 3, 0,
  },
  {
    /* 0 FPR32 */ 
    /* 0 GPR */ 
    /* 0 sFPR32 */ CSKY::FPR32RegClassID, 
    /* 1 sGPR */ CSKY::GPRRegClassID, 
    /* 2 mGPR */ CSKY::GPRRegClassID, CSKY::sGPRRegClassID, 
    /* 4 CARRY */ 
    /* 4 GPRSP */ CSKY::GPRRegClassID, CSKY::sGPRRegClassID, 
    /* 6 FPR64 */ 
    /* 6 GPRPair */ 
    /* 6 GPRPair_with_sub32_32_in_GPR */ CSKY::GPRPairRegClassID, 
    /* 7 GPRPair_with_sub32_0_in_sGPR */ CSKY::GPRPairRegClassID, CSKY::GPRPair_with_sub32_32_in_GPRRegClassID, 
    /* 9 sFPR64 */ CSKY::FPR64RegClassID, CSKY::sFPR64_VRegClassID, 
    /* 11 sFPR64_V */ CSKY::FPR64RegClassID, CSKY::sFPR64RegClassID, 
    /* 13 GPRPair_with_sub32_32_in_sGPR */ CSKY::GPRPairRegClassID, CSKY::GPRPair_with_sub32_32_in_GPRRegClassID, CSKY::GPRPair_with_sub32_0_in_sGPRRegClassID, 
    /* 16 GPRPair_with_sub32_0_in_mGPR */ CSKY::GPRPairRegClassID, CSKY::GPRPair_with_sub32_32_in_GPRRegClassID, CSKY::GPRPair_with_sub32_0_in_sGPRRegClassID, CSKY::GPRPair_with_sub32_32_in_sGPRRegClassID, 
    /* 20 GPRPair_with_sub32_32_in_mGPR */ CSKY::GPRPairRegClassID, CSKY::GPRPair_with_sub32_32_in_GPRRegClassID, CSKY::GPRPair_with_sub32_0_in_sGPRRegClassID, CSKY::GPRPair_with_sub32_32_in_sGPRRegClassID, CSKY::GPRPair_with_sub32_0_in_mGPRRegClassID, 
    /* 25 GPRPair_with_sub32_0_in_GPRSP */ CSKY::GPRPairRegClassID, CSKY::GPRPair_with_sub32_32_in_GPRRegClassID, CSKY::GPRPair_with_sub32_0_in_sGPRRegClassID, CSKY::GPRPair_with_sub32_32_in_sGPRRegClassID, 
    /* 29 GPRPair_with_sub32_32_in_GPRSP */ CSKY::GPRPairRegClassID, CSKY::GPRPair_with_sub32_32_in_GPRRegClassID, CSKY::GPRPair_with_sub32_0_in_sGPRRegClassID, CSKY::GPRPair_with_sub32_32_in_sGPRRegClassID, 
    /* 33 FPR128 */ 
    /* 33 sFPR128 */ CSKY::FPR128RegClassID, 
  }
};

const MCRegisterClass &getCSKYMCRegisterClass(unsigned RC) {
  return CSKYMCRegisterClassStorage.Classes[RC];
}

// CSKY Dwarf<->LLVM register mappings.
extern const MCRegisterInfo::DwarfLLVMRegPair CSKYDwarfFlavour0Dwarf2L[] = {
  { 0U, CSKY::R0 },
  { 1U, CSKY::R1 },
  { 2U, CSKY::R2 },
  { 3U, CSKY::R3 },
  { 4U, CSKY::R4 },
  { 5U, CSKY::R5 },
  { 6U, CSKY::R6 },
  { 7U, CSKY::R7 },
  { 8U, CSKY::R8 },
  { 9U, CSKY::R9 },
  { 10U, CSKY::R10 },
  { 11U, CSKY::R11 },
  { 12U, CSKY::R12 },
  { 13U, CSKY::R13 },
  { 14U, CSKY::R14 },
  { 15U, CSKY::R15 },
  { 16U, CSKY::R16 },
  { 17U, CSKY::R17 },
  { 18U, CSKY::R18 },
  { 19U, CSKY::R19 },
  { 20U, CSKY::R20 },
  { 21U, CSKY::R21 },
  { 22U, CSKY::R22 },
  { 23U, CSKY::R23 },
  { 24U, CSKY::R24 },
  { 25U, CSKY::R25 },
  { 26U, CSKY::R26 },
  { 27U, CSKY::R27 },
  { 28U, CSKY::R28 },
  { 29U, CSKY::R29 },
  { 30U, CSKY::R30 },
  { 31U, CSKY::R31 },
  { 32U, CSKY::F0_128 },
  { 33U, CSKY::F1_128 },
  { 34U, CSKY::F2_128 },
  { 35U, CSKY::F3_128 },
  { 36U, CSKY::F4_128 },
  { 37U, CSKY::F5_128 },
  { 38U, CSKY::F6_128 },
  { 39U, CSKY::F7_128 },
  { 40U, CSKY::F8_128 },
  { 41U, CSKY::F9_128 },
  { 42U, CSKY::F10_128 },
  { 43U, CSKY::F11_128 },
  { 44U, CSKY::F12_128 },
  { 45U, CSKY::F13_128 },
  { 46U, CSKY::F14_128 },
  { 47U, CSKY::F15_128 },
  { 48U, CSKY::F16_128 },
  { 49U, CSKY::F17_128 },
  { 50U, CSKY::F18_128 },
  { 51U, CSKY::F19_128 },
  { 52U, CSKY::F20_128 },
  { 53U, CSKY::F21_128 },
  { 54U, CSKY::F22_128 },
  { 55U, CSKY::F23_128 },
  { 56U, CSKY::F24_128 },
  { 57U, CSKY::F25_128 },
  { 58U, CSKY::F26_128 },
  { 59U, CSKY::F27_128 },
  { 60U, CSKY::F28_128 },
  { 61U, CSKY::F29_128 },
  { 62U, CSKY::F30_128 },
  { 63U, CSKY::F31_128 },
};
extern const unsigned CSKYDwarfFlavour0Dwarf2LSize = std::size(CSKYDwarfFlavour0Dwarf2L);

extern const MCRegisterInfo::DwarfLLVMRegPair CSKYEHFlavour0Dwarf2L[] = {
  { 0U, CSKY::R0 },
  { 1U, CSKY::R1 },
  { 2U, CSKY::R2 },
  { 3U, CSKY::R3 },
  { 4U, CSKY::R4 },
  { 5U, CSKY::R5 },
  { 6U, CSKY::R6 },
  { 7U, CSKY::R7 },
  { 8U, CSKY::R8 },
  { 9U, CSKY::R9 },
  { 10U, CSKY::R10 },
  { 11U, CSKY::R11 },
  { 12U, CSKY::R12 },
  { 13U, CSKY::R13 },
  { 14U, CSKY::R14 },
  { 15U, CSKY::R15 },
  { 16U, CSKY::R16 },
  { 17U, CSKY::R17 },
  { 18U, CSKY::R18 },
  { 19U, CSKY::R19 },
  { 20U, CSKY::R20 },
  { 21U, CSKY::R21 },
  { 22U, CSKY::R22 },
  { 23U, CSKY::R23 },
  { 24U, CSKY::R24 },
  { 25U, CSKY::R25 },
  { 26U, CSKY::R26 },
  { 27U, CSKY::R27 },
  { 28U, CSKY::R28 },
  { 29U, CSKY::R29 },
  { 30U, CSKY::R30 },
  { 31U, CSKY::R31 },
  { 32U, CSKY::F0_128 },
  { 33U, CSKY::F1_128 },
  { 34U, CSKY::F2_128 },
  { 35U, CSKY::F3_128 },
  { 36U, CSKY::F4_128 },
  { 37U, CSKY::F5_128 },
  { 38U, CSKY::F6_128 },
  { 39U, CSKY::F7_128 },
  { 40U, CSKY::F8_128 },
  { 41U, CSKY::F9_128 },
  { 42U, CSKY::F10_128 },
  { 43U, CSKY::F11_128 },
  { 44U, CSKY::F12_128 },
  { 45U, CSKY::F13_128 },
  { 46U, CSKY::F14_128 },
  { 47U, CSKY::F15_128 },
  { 48U, CSKY::F16_128 },
  { 49U, CSKY::F17_128 },
  { 50U, CSKY::F18_128 },
  { 51U, CSKY::F19_128 },
  { 52U, CSKY::F20_128 },
  { 53U, CSKY::F21_128 },
  { 54U, CSKY::F22_128 },
  { 55U, CSKY::F23_128 },
  { 56U, CSKY::F24_128 },
  { 57U, CSKY::F25_128 },
  { 58U, CSKY::F26_128 },
  { 59U, CSKY::F27_128 },
  { 60U, CSKY::F28_128 },
  { 61U, CSKY::F29_128 },
  { 62U, CSKY::F30_128 },
  { 63U, CSKY::F31_128 },
};
extern const unsigned CSKYEHFlavour0Dwarf2LSize = std::size(CSKYEHFlavour0Dwarf2L);

extern const MCRegisterInfo::DwarfLLVMRegPair CSKYDwarfFlavour0L2Dwarf[] = {
  { CSKY::R0, 0U },
  { CSKY::R1, 1U },
  { CSKY::R2, 2U },
  { CSKY::R3, 3U },
  { CSKY::R4, 4U },
  { CSKY::R5, 5U },
  { CSKY::R6, 6U },
  { CSKY::R7, 7U },
  { CSKY::R8, 8U },
  { CSKY::R9, 9U },
  { CSKY::R10, 10U },
  { CSKY::R11, 11U },
  { CSKY::R12, 12U },
  { CSKY::R13, 13U },
  { CSKY::R14, 14U },
  { CSKY::R15, 15U },
  { CSKY::R16, 16U },
  { CSKY::R17, 17U },
  { CSKY::R18, 18U },
  { CSKY::R19, 19U },
  { CSKY::R20, 20U },
  { CSKY::R21, 21U },
  { CSKY::R22, 22U },
  { CSKY::R23, 23U },
  { CSKY::R24, 24U },
  { CSKY::R25, 25U },
  { CSKY::R26, 26U },
  { CSKY::R27, 27U },
  { CSKY::R28, 28U },
  { CSKY::R29, 29U },
  { CSKY::R30, 30U },
  { CSKY::R31, 31U },
  { CSKY::R32, 32U },
  { CSKY::F0_32, 32U },
  { CSKY::F0_64, 32U },
  { CSKY::F0_128, 32U },
  { CSKY::F1_32, 33U },
  { CSKY::F1_64, 33U },
  { CSKY::F1_128, 33U },
  { CSKY::F2_32, 34U },
  { CSKY::F2_64, 34U },
  { CSKY::F2_128, 34U },
  { CSKY::F3_32, 35U },
  { CSKY::F3_64, 35U },
  { CSKY::F3_128, 35U },
  { CSKY::F4_32, 36U },
  { CSKY::F4_64, 36U },
  { CSKY::F4_128, 36U },
  { CSKY::F5_32, 37U },
  { CSKY::F5_64, 37U },
  { CSKY::F5_128, 37U },
  { CSKY::F6_32, 38U },
  { CSKY::F6_64, 38U },
  { CSKY::F6_128, 38U },
  { CSKY::F7_32, 39U },
  { CSKY::F7_64, 39U },
  { CSKY::F7_128, 39U },
  { CSKY::F8_32, 40U },
  { CSKY::F8_64, 40U },
  { CSKY::F8_128, 40U },
  { CSKY::F9_32, 41U },
  { CSKY::F9_64, 41U },
  { CSKY::F9_128, 41U },
  { CSKY::F10_32, 42U },
  { CSKY::F10_64, 42U },
  { CSKY::F10_128, 42U },
  { CSKY::F11_32, 43U },
  { CSKY::F11_64, 43U },
  { CSKY::F11_128, 43U },
  { CSKY::F12_32, 44U },
  { CSKY::F12_64, 44U },
  { CSKY::F12_128, 44U },
  { CSKY::F13_32, 45U },
  { CSKY::F13_64, 45U },
  { CSKY::F13_128, 45U },
  { CSKY::F14_32, 46U },
  { CSKY::F14_64, 46U },
  { CSKY::F14_128, 46U },
  { CSKY::F15_32, 47U },
  { CSKY::F15_64, 47U },
  { CSKY::F15_128, 47U },
  { CSKY::F16_32, 48U },
  { CSKY::F16_64, 48U },
  { CSKY::F16_128, 48U },
  { CSKY::F17_32, 49U },
  { CSKY::F17_64, 49U },
  { CSKY::F17_128, 49U },
  { CSKY::F18_32, 50U },
  { CSKY::F18_64, 50U },
  { CSKY::F18_128, 50U },
  { CSKY::F19_32, 51U },
  { CSKY::F19_64, 51U },
  { CSKY::F19_128, 51U },
  { CSKY::F20_32, 52U },
  { CSKY::F20_64, 52U },
  { CSKY::F20_128, 52U },
  { CSKY::F21_32, 53U },
  { CSKY::F21_64, 53U },
  { CSKY::F21_128, 53U },
  { CSKY::F22_32, 54U },
  { CSKY::F22_64, 54U },
  { CSKY::F22_128, 54U },
  { CSKY::F23_32, 55U },
  { CSKY::F23_64, 55U },
  { CSKY::F23_128, 55U },
  { CSKY::F24_32, 56U },
  { CSKY::F24_64, 56U },
  { CSKY::F24_128, 56U },
  { CSKY::F25_32, 57U },
  { CSKY::F25_64, 57U },
  { CSKY::F25_128, 57U },
  { CSKY::F26_32, 58U },
  { CSKY::F26_64, 58U },
  { CSKY::F26_128, 58U },
  { CSKY::F27_32, 59U },
  { CSKY::F27_64, 59U },
  { CSKY::F27_128, 59U },
  { CSKY::F28_32, 60U },
  { CSKY::F28_64, 60U },
  { CSKY::F28_128, 60U },
  { CSKY::F29_32, 61U },
  { CSKY::F29_64, 61U },
  { CSKY::F29_128, 61U },
  { CSKY::F30_32, 62U },
  { CSKY::F30_64, 62U },
  { CSKY::F30_128, 62U },
  { CSKY::F31_32, 63U },
  { CSKY::F31_64, 63U },
  { CSKY::F31_128, 63U },
};
extern const unsigned CSKYDwarfFlavour0L2DwarfSize = std::size(CSKYDwarfFlavour0L2Dwarf);

extern const MCRegisterInfo::DwarfLLVMRegPair CSKYEHFlavour0L2Dwarf[] = {
  { CSKY::R0, 0U },
  { CSKY::R1, 1U },
  { CSKY::R2, 2U },
  { CSKY::R3, 3U },
  { CSKY::R4, 4U },
  { CSKY::R5, 5U },
  { CSKY::R6, 6U },
  { CSKY::R7, 7U },
  { CSKY::R8, 8U },
  { CSKY::R9, 9U },
  { CSKY::R10, 10U },
  { CSKY::R11, 11U },
  { CSKY::R12, 12U },
  { CSKY::R13, 13U },
  { CSKY::R14, 14U },
  { CSKY::R15, 15U },
  { CSKY::R16, 16U },
  { CSKY::R17, 17U },
  { CSKY::R18, 18U },
  { CSKY::R19, 19U },
  { CSKY::R20, 20U },
  { CSKY::R21, 21U },
  { CSKY::R22, 22U },
  { CSKY::R23, 23U },
  { CSKY::R24, 24U },
  { CSKY::R25, 25U },
  { CSKY::R26, 26U },
  { CSKY::R27, 27U },
  { CSKY::R28, 28U },
  { CSKY::R29, 29U },
  { CSKY::R30, 30U },
  { CSKY::R31, 31U },
  { CSKY::R32, 32U },
  { CSKY::F0_32, 32U },
  { CSKY::F0_64, 32U },
  { CSKY::F0_128, 32U },
  { CSKY::F1_32, 33U },
  { CSKY::F1_64, 33U },
  { CSKY::F1_128, 33U },
  { CSKY::F2_32, 34U },
  { CSKY::F2_64, 34U },
  { CSKY::F2_128, 34U },
  { CSKY::F3_32, 35U },
  { CSKY::F3_64, 35U },
  { CSKY::F3_128, 35U },
  { CSKY::F4_32, 36U },
  { CSKY::F4_64, 36U },
  { CSKY::F4_128, 36U },
  { CSKY::F5_32, 37U },
  { CSKY::F5_64, 37U },
  { CSKY::F5_128, 37U },
  { CSKY::F6_32, 38U },
  { CSKY::F6_64, 38U },
  { CSKY::F6_128, 38U },
  { CSKY::F7_32, 39U },
  { CSKY::F7_64, 39U },
  { CSKY::F7_128, 39U },
  { CSKY::F8_32, 40U },
  { CSKY::F8_64, 40U },
  { CSKY::F8_128, 40U },
  { CSKY::F9_32, 41U },
  { CSKY::F9_64, 41U },
  { CSKY::F9_128, 41U },
  { CSKY::F10_32, 42U },
  { CSKY::F10_64, 42U },
  { CSKY::F10_128, 42U },
  { CSKY::F11_32, 43U },
  { CSKY::F11_64, 43U },
  { CSKY::F11_128, 43U },
  { CSKY::F12_32, 44U },
  { CSKY::F12_64, 44U },
  { CSKY::F12_128, 44U },
  { CSKY::F13_32, 45U },
  { CSKY::F13_64, 45U },
  { CSKY::F13_128, 45U },
  { CSKY::F14_32, 46U },
  { CSKY::F14_64, 46U },
  { CSKY::F14_128, 46U },
  { CSKY::F15_32, 47U },
  { CSKY::F15_64, 47U },
  { CSKY::F15_128, 47U },
  { CSKY::F16_32, 48U },
  { CSKY::F16_64, 48U },
  { CSKY::F16_128, 48U },
  { CSKY::F17_32, 49U },
  { CSKY::F17_64, 49U },
  { CSKY::F17_128, 49U },
  { CSKY::F18_32, 50U },
  { CSKY::F18_64, 50U },
  { CSKY::F18_128, 50U },
  { CSKY::F19_32, 51U },
  { CSKY::F19_64, 51U },
  { CSKY::F19_128, 51U },
  { CSKY::F20_32, 52U },
  { CSKY::F20_64, 52U },
  { CSKY::F20_128, 52U },
  { CSKY::F21_32, 53U },
  { CSKY::F21_64, 53U },
  { CSKY::F21_128, 53U },
  { CSKY::F22_32, 54U },
  { CSKY::F22_64, 54U },
  { CSKY::F22_128, 54U },
  { CSKY::F23_32, 55U },
  { CSKY::F23_64, 55U },
  { CSKY::F23_128, 55U },
  { CSKY::F24_32, 56U },
  { CSKY::F24_64, 56U },
  { CSKY::F24_128, 56U },
  { CSKY::F25_32, 57U },
  { CSKY::F25_64, 57U },
  { CSKY::F25_128, 57U },
  { CSKY::F26_32, 58U },
  { CSKY::F26_64, 58U },
  { CSKY::F26_128, 58U },
  { CSKY::F27_32, 59U },
  { CSKY::F27_64, 59U },
  { CSKY::F27_128, 59U },
  { CSKY::F28_32, 60U },
  { CSKY::F28_64, 60U },
  { CSKY::F28_128, 60U },
  { CSKY::F29_32, 61U },
  { CSKY::F29_64, 61U },
  { CSKY::F29_128, 61U },
  { CSKY::F30_32, 62U },
  { CSKY::F30_64, 62U },
  { CSKY::F30_128, 62U },
  { CSKY::F31_32, 63U },
  { CSKY::F31_64, 63U },
  { CSKY::F31_128, 63U },
};
extern const unsigned CSKYEHFlavour0L2DwarfSize = std::size(CSKYEHFlavour0L2Dwarf);

extern const uint16_t CSKYRegEncodingTable[] = {
  0,
  33,
  0,
  1,
  2,
  3,
  4,
  5,
  6,
  7,
  8,
  9,
  10,
  11,
  12,
  13,
  14,
  15,
  16,
  17,
  18,
  19,
  20,
  21,
  22,
  23,
  24,
  25,
  26,
  27,
  28,
  29,
  30,
  31,
  32,
  0,
  0,
  0,
  1,
  1,
  1,
  2,
  2,
  2,
  3,
  3,
  3,
  4,
  4,
  4,
  5,
  5,
  5,
  6,
  6,
  6,
  7,
  7,
  7,
  8,
  8,
  8,
  9,
  9,
  9,
  10,
  10,
  10,
  11,
  11,
  11,
  12,
  12,
  12,
  13,
  13,
  13,
  14,
  14,
  14,
  15,
  15,
  15,
  16,
  16,
  16,
  17,
  17,
  17,
  18,
  18,
  18,
  19,
  19,
  19,
  20,
  20,
  20,
  21,
  21,
  21,
  22,
  22,
  22,
  23,
  23,
  23,
  24,
  24,
  24,
  25,
  25,
  25,
  26,
  26,
  26,
  27,
  27,
  27,
  28,
  28,
  28,
  29,
  29,
  29,
  30,
  30,
  30,
  31,
  31,
  31,
  0,
  1,
  2,
  3,
  4,
  5,
  6,
  7,
  8,
  9,
  10,
  11,
  12,
  13,
  14,
  15,
  16,
  17,
  18,
  19,
  20,
  21,
  22,
  23,
  24,
  25,
  26,
  27,
  28,
  29,
  30,
  31,
};
static inline void InitCSKYMCRegisterInfo(MCRegisterInfo *RI, unsigned RA, unsigned DwarfFlavour = 0, unsigned EHFlavour = 0, unsigned PC = 0) {
  RI->InitMCRegisterInfo(CSKYRegDesc, 163, RA, PC, CSKYMCRegisterClassStorage.Classes, 20, CSKYRegUnitRoots, 66, CSKYRegDiffLists, CSKYLaneMaskLists, CSKYRegStrings, CSKYRegClassStrings, CSKYSubRegIdxLists, 5,
CSKYRegEncodingTable, nullptr);

  switch (DwarfFlavour) {
  default:
    llvm_unreachable("Unknown DWARF flavour");
  case 0:
    RI->mapDwarfRegsToLLVMRegs(CSKYDwarfFlavour0Dwarf2L, CSKYDwarfFlavour0Dwarf2LSize, false);
    break;
  }
  switch (EHFlavour) {
  default:
    llvm_unreachable("Unknown DWARF flavour");
  case 0:
    RI->mapDwarfRegsToLLVMRegs(CSKYEHFlavour0Dwarf2L, CSKYEHFlavour0Dwarf2LSize, true);
    break;
  }
  switch (DwarfFlavour) {
  default:
    llvm_unreachable("Unknown DWARF flavour");
  case 0:
    RI->mapLLVMRegsToDwarfRegs(CSKYDwarfFlavour0L2Dwarf, CSKYDwarfFlavour0L2DwarfSize, false);
    break;
  }
  switch (EHFlavour) {
  default:
    llvm_unreachable("Unknown DWARF flavour");
  case 0:
    RI->mapLLVMRegsToDwarfRegs(CSKYEHFlavour0L2Dwarf, CSKYEHFlavour0L2DwarfSize, true);
    break;
  }
}


} // namespace llvm_ks
