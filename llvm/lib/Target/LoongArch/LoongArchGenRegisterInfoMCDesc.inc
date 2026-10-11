/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* MC Register Information                                                    *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

namespace llvm_ks {

extern const int16_t LoongArchRegDiffLists[] = {
  /* 0 */ -32, 64, -144, 0,
  /* 4 */ 144, -64, 32, 0,
};

extern const LaneBitmask LoongArchLaneMaskLists[] = {
  /* 0 */ LaneBitmask(0x0000000000000001), 
  /* 1 */ LaneBitmask(0xFFFFFFFFFFFFFFFF), 
};

extern const uint16_t LoongArchSubRegIdxLists[] = {
  /* 0 */ 3, 2, 1, 
};


#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"
#endif
extern const char LoongArchRegStrings[] = {
  /* 0 */ "F10\000"
  /* 4 */ "VR10\000"
  /* 9 */ "XR10\000"
  /* 14 */ "F20\000"
  /* 18 */ "VR20\000"
  /* 23 */ "XR20\000"
  /* 28 */ "F30\000"
  /* 32 */ "VR30\000"
  /* 37 */ "XR30\000"
  /* 42 */ "FCC0\000"
  /* 47 */ "F0\000"
  /* 50 */ "SCR0\000"
  /* 55 */ "FCSR0\000"
  /* 61 */ "VR0\000"
  /* 65 */ "XR0\000"
  /* 69 */ "F11\000"
  /* 73 */ "VR11\000"
  /* 78 */ "XR11\000"
  /* 83 */ "F21\000"
  /* 87 */ "VR21\000"
  /* 92 */ "XR21\000"
  /* 97 */ "F31\000"
  /* 101 */ "VR31\000"
  /* 106 */ "XR31\000"
  /* 111 */ "FCC1\000"
  /* 116 */ "F1\000"
  /* 119 */ "SCR1\000"
  /* 124 */ "FCSR1\000"
  /* 130 */ "VR1\000"
  /* 134 */ "XR1\000"
  /* 138 */ "F12\000"
  /* 142 */ "VR12\000"
  /* 147 */ "XR12\000"
  /* 152 */ "F22\000"
  /* 156 */ "VR22\000"
  /* 161 */ "XR22\000"
  /* 166 */ "FCC2\000"
  /* 171 */ "F2\000"
  /* 174 */ "SCR2\000"
  /* 179 */ "FCSR2\000"
  /* 185 */ "VR2\000"
  /* 189 */ "XR2\000"
  /* 193 */ "F13\000"
  /* 197 */ "VR13\000"
  /* 202 */ "XR13\000"
  /* 207 */ "F23\000"
  /* 211 */ "VR23\000"
  /* 216 */ "XR23\000"
  /* 221 */ "FCC3\000"
  /* 226 */ "F3\000"
  /* 229 */ "SCR3\000"
  /* 234 */ "FCSR3\000"
  /* 240 */ "VR3\000"
  /* 244 */ "XR3\000"
  /* 248 */ "F14\000"
  /* 252 */ "VR14\000"
  /* 257 */ "XR14\000"
  /* 262 */ "F24\000"
  /* 266 */ "VR24\000"
  /* 271 */ "XR24\000"
  /* 276 */ "F10_64\000"
  /* 283 */ "F20_64\000"
  /* 290 */ "F30_64\000"
  /* 297 */ "F0_64\000"
  /* 303 */ "F11_64\000"
  /* 310 */ "F21_64\000"
  /* 317 */ "F31_64\000"
  /* 324 */ "F1_64\000"
  /* 330 */ "F12_64\000"
  /* 337 */ "F22_64\000"
  /* 344 */ "F2_64\000"
  /* 350 */ "F13_64\000"
  /* 357 */ "F23_64\000"
  /* 364 */ "F3_64\000"
  /* 370 */ "F14_64\000"
  /* 377 */ "F24_64\000"
  /* 384 */ "F4_64\000"
  /* 390 */ "F15_64\000"
  /* 397 */ "F25_64\000"
  /* 404 */ "F5_64\000"
  /* 410 */ "F16_64\000"
  /* 417 */ "F26_64\000"
  /* 424 */ "F6_64\000"
  /* 430 */ "F17_64\000"
  /* 437 */ "F27_64\000"
  /* 444 */ "F7_64\000"
  /* 450 */ "F18_64\000"
  /* 457 */ "F28_64\000"
  /* 464 */ "F8_64\000"
  /* 470 */ "F19_64\000"
  /* 477 */ "F29_64\000"
  /* 484 */ "F9_64\000"
  /* 490 */ "FCC4\000"
  /* 495 */ "F4\000"
  /* 498 */ "VR4\000"
  /* 502 */ "XR4\000"
  /* 506 */ "F15\000"
  /* 510 */ "VR15\000"
  /* 515 */ "XR15\000"
  /* 520 */ "F25\000"
  /* 524 */ "VR25\000"
  /* 529 */ "XR25\000"
  /* 534 */ "FCC5\000"
  /* 539 */ "F5\000"
  /* 542 */ "VR5\000"
  /* 546 */ "XR5\000"
  /* 550 */ "F16\000"
  /* 554 */ "VR16\000"
  /* 559 */ "XR16\000"
  /* 564 */ "F26\000"
  /* 568 */ "VR26\000"
  /* 573 */ "XR26\000"
  /* 578 */ "FCC6\000"
  /* 583 */ "F6\000"
  /* 586 */ "VR6\000"
  /* 590 */ "XR6\000"
  /* 594 */ "F17\000"
  /* 598 */ "VR17\000"
  /* 603 */ "XR17\000"
  /* 608 */ "F27\000"
  /* 612 */ "VR27\000"
  /* 617 */ "XR27\000"
  /* 622 */ "FCC7\000"
  /* 627 */ "F7\000"
  /* 630 */ "VR7\000"
  /* 634 */ "XR7\000"
  /* 638 */ "F18\000"
  /* 642 */ "VR18\000"
  /* 647 */ "XR18\000"
  /* 652 */ "F28\000"
  /* 656 */ "VR28\000"
  /* 661 */ "XR28\000"
  /* 666 */ "F8\000"
  /* 669 */ "VR8\000"
  /* 673 */ "XR8\000"
  /* 677 */ "F19\000"
  /* 681 */ "VR19\000"
  /* 686 */ "XR19\000"
  /* 691 */ "F29\000"
  /* 695 */ "VR29\000"
  /* 700 */ "XR29\000"
  /* 705 */ "F9\000"
  /* 708 */ "VR9\000"
  /* 712 */ "XR9\000"
};
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

extern const MCRegisterDesc LoongArchRegDesc[] = { // Descriptors
  { 3, 0, 0, 0, 0, 0, 0, 0 },
  { 47, 3, 4, 3, 12288, 1, 0, 0 },
  { 116, 3, 4, 3, 12289, 1, 0, 0 },
  { 171, 3, 4, 3, 12290, 1, 0, 0 },
  { 226, 3, 4, 3, 12291, 1, 0, 0 },
  { 495, 3, 4, 3, 12292, 1, 0, 0 },
  { 539, 3, 4, 3, 12293, 1, 0, 0 },
  { 583, 3, 4, 3, 12294, 1, 0, 0 },
  { 627, 3, 4, 3, 12295, 1, 0, 0 },
  { 666, 3, 4, 3, 12296, 1, 0, 0 },
  { 705, 3, 4, 3, 12297, 1, 0, 0 },
  { 0, 3, 4, 3, 12298, 1, 0, 0 },
  { 69, 3, 4, 3, 12299, 1, 0, 0 },
  { 138, 3, 4, 3, 12300, 1, 0, 0 },
  { 193, 3, 4, 3, 12301, 1, 0, 0 },
  { 248, 3, 4, 3, 12302, 1, 0, 0 },
  { 506, 3, 4, 3, 12303, 1, 0, 0 },
  { 550, 3, 4, 3, 12304, 1, 0, 0 },
  { 594, 3, 4, 3, 12305, 1, 0, 0 },
  { 638, 3, 4, 3, 12306, 1, 0, 0 },
  { 677, 3, 4, 3, 12307, 1, 0, 0 },
  { 14, 3, 4, 3, 12308, 1, 0, 0 },
  { 83, 3, 4, 3, 12309, 1, 0, 0 },
  { 152, 3, 4, 3, 12310, 1, 0, 0 },
  { 207, 3, 4, 3, 12311, 1, 0, 0 },
  { 262, 3, 4, 3, 12312, 1, 0, 0 },
  { 520, 3, 4, 3, 12313, 1, 0, 0 },
  { 564, 3, 4, 3, 12314, 1, 0, 0 },
  { 608, 3, 4, 3, 12315, 1, 0, 0 },
  { 652, 3, 4, 3, 12316, 1, 0, 0 },
  { 691, 3, 4, 3, 12317, 1, 0, 0 },
  { 28, 3, 4, 3, 12318, 1, 0, 0 },
  { 97, 3, 4, 3, 12319, 1, 0, 0 },
  { 42, 3, 3, 3, 12320, 1, 0, 0 },
  { 111, 3, 3, 3, 12321, 1, 0, 0 },
  { 166, 3, 3, 3, 12322, 1, 0, 0 },
  { 221, 3, 3, 3, 12323, 1, 0, 0 },
  { 490, 3, 3, 3, 12324, 1, 0, 0 },
  { 534, 3, 3, 3, 12325, 1, 0, 0 },
  { 578, 3, 3, 3, 12326, 1, 0, 0 },
  { 622, 3, 3, 3, 12327, 1, 0, 0 },
  { 55, 3, 3, 3, 12328, 1, 0, 0 },
  { 124, 3, 3, 3, 12329, 1, 0, 0 },
  { 179, 3, 3, 3, 12330, 1, 0, 0 },
  { 234, 3, 3, 3, 12331, 1, 0, 0 },
  { 52, 3, 3, 3, 12332, 1, 1, 0 },
  { 121, 3, 3, 3, 12333, 1, 0, 0 },
  { 176, 3, 3, 3, 12334, 1, 0, 0 },
  { 231, 3, 3, 3, 12335, 1, 0, 0 },
  { 499, 3, 3, 3, 12336, 1, 0, 0 },
  { 543, 3, 3, 3, 12337, 1, 0, 0 },
  { 587, 3, 3, 3, 12338, 1, 0, 0 },
  { 631, 3, 3, 3, 12339, 1, 0, 0 },
  { 670, 3, 3, 3, 12340, 1, 0, 0 },
  { 709, 3, 3, 3, 12341, 1, 0, 0 },
  { 5, 3, 3, 3, 12342, 1, 0, 0 },
  { 74, 3, 3, 3, 12343, 1, 0, 0 },
  { 143, 3, 3, 3, 12344, 1, 0, 0 },
  { 198, 3, 3, 3, 12345, 1, 0, 0 },
  { 253, 3, 3, 3, 12346, 1, 0, 0 },
  { 511, 3, 3, 3, 12347, 1, 0, 0 },
  { 555, 3, 3, 3, 12348, 1, 0, 0 },
  { 599, 3, 3, 3, 12349, 1, 0, 0 },
  { 643, 3, 3, 3, 12350, 1, 0, 0 },
  { 682, 3, 3, 3, 12351, 1, 0, 0 },
  { 19, 3, 3, 3, 12352, 1, 0, 0 },
  { 88, 3, 3, 3, 12353, 1, 0, 0 },
  { 157, 3, 3, 3, 12354, 1, 0, 0 },
  { 212, 3, 3, 3, 12355, 1, 0, 0 },
  { 267, 3, 3, 3, 12356, 1, 0, 0 },
  { 525, 3, 3, 3, 12357, 1, 0, 0 },
  { 569, 3, 3, 3, 12358, 1, 0, 0 },
  { 613, 3, 3, 3, 12359, 1, 0, 0 },
  { 657, 3, 3, 3, 12360, 1, 0, 0 },
  { 696, 3, 3, 3, 12361, 1, 0, 0 },
  { 33, 3, 3, 3, 12362, 1, 0, 0 },
  { 102, 3, 3, 3, 12363, 1, 0, 0 },
  { 50, 3, 3, 3, 12364, 1, 0, 0 },
  { 119, 3, 3, 3, 12365, 1, 0, 0 },
  { 174, 3, 3, 3, 12366, 1, 0, 0 },
  { 229, 3, 3, 3, 12367, 1, 0, 0 },
  { 61, 1, 6, 1, 12288, 0, 0, 0 },
  { 130, 1, 6, 1, 12289, 0, 0, 0 },
  { 185, 1, 6, 1, 12290, 0, 0, 0 },
  { 240, 1, 6, 1, 12291, 0, 0, 0 },
  { 498, 1, 6, 1, 12292, 0, 0, 0 },
  { 542, 1, 6, 1, 12293, 0, 0, 0 },
  { 586, 1, 6, 1, 12294, 0, 0, 0 },
  { 630, 1, 6, 1, 12295, 0, 0, 0 },
  { 669, 1, 6, 1, 12296, 0, 0, 0 },
  { 708, 1, 6, 1, 12297, 0, 0, 0 },
  { 4, 1, 6, 1, 12298, 0, 0, 0 },
  { 73, 1, 6, 1, 12299, 0, 0, 0 },
  { 142, 1, 6, 1, 12300, 0, 0, 0 },
  { 197, 1, 6, 1, 12301, 0, 0, 0 },
  { 252, 1, 6, 1, 12302, 0, 0, 0 },
  { 510, 1, 6, 1, 12303, 0, 0, 0 },
  { 554, 1, 6, 1, 12304, 0, 0, 0 },
  { 598, 1, 6, 1, 12305, 0, 0, 0 },
  { 642, 1, 6, 1, 12306, 0, 0, 0 },
  { 681, 1, 6, 1, 12307, 0, 0, 0 },
  { 18, 1, 6, 1, 12308, 0, 0, 0 },
  { 87, 1, 6, 1, 12309, 0, 0, 0 },
  { 156, 1, 6, 1, 12310, 0, 0, 0 },
  { 211, 1, 6, 1, 12311, 0, 0, 0 },
  { 266, 1, 6, 1, 12312, 0, 0, 0 },
  { 524, 1, 6, 1, 12313, 0, 0, 0 },
  { 568, 1, 6, 1, 12314, 0, 0, 0 },
  { 612, 1, 6, 1, 12315, 0, 0, 0 },
  { 656, 1, 6, 1, 12316, 0, 0, 0 },
  { 695, 1, 6, 1, 12317, 0, 0, 0 },
  { 32, 1, 6, 1, 12318, 0, 0, 0 },
  { 101, 1, 6, 1, 12319, 0, 0, 0 },
  { 65, 0, 3, 0, 12288, 0, 0, 0 },
  { 134, 0, 3, 0, 12289, 0, 0, 0 },
  { 189, 0, 3, 0, 12290, 0, 0, 0 },
  { 244, 0, 3, 0, 12291, 0, 0, 0 },
  { 502, 0, 3, 0, 12292, 0, 0, 0 },
  { 546, 0, 3, 0, 12293, 0, 0, 0 },
  { 590, 0, 3, 0, 12294, 0, 0, 0 },
  { 634, 0, 3, 0, 12295, 0, 0, 0 },
  { 673, 0, 3, 0, 12296, 0, 0, 0 },
  { 712, 0, 3, 0, 12297, 0, 0, 0 },
  { 9, 0, 3, 0, 12298, 0, 0, 0 },
  { 78, 0, 3, 0, 12299, 0, 0, 0 },
  { 147, 0, 3, 0, 12300, 0, 0, 0 },
  { 202, 0, 3, 0, 12301, 0, 0, 0 },
  { 257, 0, 3, 0, 12302, 0, 0, 0 },
  { 515, 0, 3, 0, 12303, 0, 0, 0 },
  { 559, 0, 3, 0, 12304, 0, 0, 0 },
  { 603, 0, 3, 0, 12305, 0, 0, 0 },
  { 647, 0, 3, 0, 12306, 0, 0, 0 },
  { 686, 0, 3, 0, 12307, 0, 0, 0 },
  { 23, 0, 3, 0, 12308, 0, 0, 0 },
  { 92, 0, 3, 0, 12309, 0, 0, 0 },
  { 161, 0, 3, 0, 12310, 0, 0, 0 },
  { 216, 0, 3, 0, 12311, 0, 0, 0 },
  { 271, 0, 3, 0, 12312, 0, 0, 0 },
  { 529, 0, 3, 0, 12313, 0, 0, 0 },
  { 573, 0, 3, 0, 12314, 0, 0, 0 },
  { 617, 0, 3, 0, 12315, 0, 0, 0 },
  { 661, 0, 3, 0, 12316, 0, 0, 0 },
  { 700, 0, 3, 0, 12317, 0, 0, 0 },
  { 37, 0, 3, 0, 12318, 0, 0, 0 },
  { 106, 0, 3, 0, 12319, 0, 0, 0 },
  { 297, 2, 5, 2, 12288, 0, 0, 0 },
  { 324, 2, 5, 2, 12289, 0, 0, 0 },
  { 344, 2, 5, 2, 12290, 0, 0, 0 },
  { 364, 2, 5, 2, 12291, 0, 0, 0 },
  { 384, 2, 5, 2, 12292, 0, 0, 0 },
  { 404, 2, 5, 2, 12293, 0, 0, 0 },
  { 424, 2, 5, 2, 12294, 0, 0, 0 },
  { 444, 2, 5, 2, 12295, 0, 0, 0 },
  { 464, 2, 5, 2, 12296, 0, 0, 0 },
  { 484, 2, 5, 2, 12297, 0, 0, 0 },
  { 276, 2, 5, 2, 12298, 0, 0, 0 },
  { 303, 2, 5, 2, 12299, 0, 0, 0 },
  { 330, 2, 5, 2, 12300, 0, 0, 0 },
  { 350, 2, 5, 2, 12301, 0, 0, 0 },
  { 370, 2, 5, 2, 12302, 0, 0, 0 },
  { 390, 2, 5, 2, 12303, 0, 0, 0 },
  { 410, 2, 5, 2, 12304, 0, 0, 0 },
  { 430, 2, 5, 2, 12305, 0, 0, 0 },
  { 450, 2, 5, 2, 12306, 0, 0, 0 },
  { 470, 2, 5, 2, 12307, 0, 0, 0 },
  { 283, 2, 5, 2, 12308, 0, 0, 0 },
  { 310, 2, 5, 2, 12309, 0, 0, 0 },
  { 337, 2, 5, 2, 12310, 0, 0, 0 },
  { 357, 2, 5, 2, 12311, 0, 0, 0 },
  { 377, 2, 5, 2, 12312, 0, 0, 0 },
  { 397, 2, 5, 2, 12313, 0, 0, 0 },
  { 417, 2, 5, 2, 12314, 0, 0, 0 },
  { 437, 2, 5, 2, 12315, 0, 0, 0 },
  { 457, 2, 5, 2, 12316, 0, 0, 0 },
  { 477, 2, 5, 2, 12317, 0, 0, 0 },
  { 290, 2, 5, 2, 12318, 0, 0, 0 },
  { 317, 2, 5, 2, 12319, 0, 0, 0 },
};

extern const MCPhysReg LoongArchRegUnitRoots[][2] = {
  { LoongArch::F0 },
  { LoongArch::F1 },
  { LoongArch::F2 },
  { LoongArch::F3 },
  { LoongArch::F4 },
  { LoongArch::F5 },
  { LoongArch::F6 },
  { LoongArch::F7 },
  { LoongArch::F8 },
  { LoongArch::F9 },
  { LoongArch::F10 },
  { LoongArch::F11 },
  { LoongArch::F12 },
  { LoongArch::F13 },
  { LoongArch::F14 },
  { LoongArch::F15 },
  { LoongArch::F16 },
  { LoongArch::F17 },
  { LoongArch::F18 },
  { LoongArch::F19 },
  { LoongArch::F20 },
  { LoongArch::F21 },
  { LoongArch::F22 },
  { LoongArch::F23 },
  { LoongArch::F24 },
  { LoongArch::F25 },
  { LoongArch::F26 },
  { LoongArch::F27 },
  { LoongArch::F28 },
  { LoongArch::F29 },
  { LoongArch::F30 },
  { LoongArch::F31 },
  { LoongArch::FCC0 },
  { LoongArch::FCC1 },
  { LoongArch::FCC2 },
  { LoongArch::FCC3 },
  { LoongArch::FCC4 },
  { LoongArch::FCC5 },
  { LoongArch::FCC6 },
  { LoongArch::FCC7 },
  { LoongArch::FCSR0 },
  { LoongArch::FCSR1 },
  { LoongArch::FCSR2 },
  { LoongArch::FCSR3 },
  { LoongArch::R0 },
  { LoongArch::R1 },
  { LoongArch::R2 },
  { LoongArch::R3 },
  { LoongArch::R4 },
  { LoongArch::R5 },
  { LoongArch::R6 },
  { LoongArch::R7 },
  { LoongArch::R8 },
  { LoongArch::R9 },
  { LoongArch::R10 },
  { LoongArch::R11 },
  { LoongArch::R12 },
  { LoongArch::R13 },
  { LoongArch::R14 },
  { LoongArch::R15 },
  { LoongArch::R16 },
  { LoongArch::R17 },
  { LoongArch::R18 },
  { LoongArch::R19 },
  { LoongArch::R20 },
  { LoongArch::R21 },
  { LoongArch::R22 },
  { LoongArch::R23 },
  { LoongArch::R24 },
  { LoongArch::R25 },
  { LoongArch::R26 },
  { LoongArch::R27 },
  { LoongArch::R28 },
  { LoongArch::R29 },
  { LoongArch::R30 },
  { LoongArch::R31 },
  { LoongArch::SCR0 },
  { LoongArch::SCR1 },
  { LoongArch::SCR2 },
  { LoongArch::SCR3 },
};

// Register classes...

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"
#endif
extern const char LoongArchRegClassStrings[] = {
  /* 0 */ "GPRNoR0R1\000"
  /* 10 */ "FPR32\000"
  /* 16 */ "FPR64\000"
  /* 22 */ "LASX256\000"
  /* 30 */ "LSX128\000"
  /* 37 */ "SCR\000"
  /* 41 */ "CFR\000"
  /* 45 */ "GPRJR\000"
  /* 51 */ "GPR\000"
  /* 55 */ "FCSR\000"
  /* 60 */ "GPRT\000"
};
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

using LoongArchRegisterClassStorage = MCRegisterClassStorage<11, 254, 124, 14, 6, 6>;
extern const MCRegisterClassStorage<11, 254, 124, 14, 6, 6> LoongArchMCRegisterClassStorage = {
  {
    {
      offsetof(LoongArchRegisterClassStorage, Regs[0]) - 0 * sizeof(MCRegisterClass),
      offsetof(LoongArchRegisterClassStorage, BitSets[0]) - 0 * sizeof(MCRegisterClass),
      10,
      32,
      32,
      5,
      LoongArch::FPR32RegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(LoongArchRegisterClassStorage, SubClassMasks[0]) - 0 * sizeof(MCRegisterClass),
      offsetof(LoongArchRegisterClassStorage, SuperRegIdxSeqs[0]) - 0 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(LoongArchRegisterClassStorage, SuperClasses[0]) - 0 * sizeof(MCRegisterClass),
      0
    },
    {
      offsetof(LoongArchRegisterClassStorage, Regs[32]) - 1 * sizeof(MCRegisterClass),
      offsetof(LoongArchRegisterClassStorage, BitSets[5]) - 1 * sizeof(MCRegisterClass),
      51,
      0,
      32,
      10,
      LoongArch::GPRRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(LoongArchRegisterClassStorage, SubClassMasks[2]) - 1 * sizeof(MCRegisterClass),
      offsetof(LoongArchRegisterClassStorage, SuperRegIdxSeqs[1]) - 1 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(LoongArchRegisterClassStorage, SuperClasses[0]) - 1 * sizeof(MCRegisterClass),
      0
    },
    {
      offsetof(LoongArchRegisterClassStorage, Regs[64]) - 2 * sizeof(MCRegisterClass),
      offsetof(LoongArchRegisterClassStorage, BitSets[15]) - 2 * sizeof(MCRegisterClass),
      45,
      0,
      31,
      10,
      LoongArch::GPRJRRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(LoongArchRegisterClassStorage, SubClassMasks[3]) - 2 * sizeof(MCRegisterClass),
      offsetof(LoongArchRegisterClassStorage, SuperRegIdxSeqs[1]) - 2 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(LoongArchRegisterClassStorage, SuperClasses[0]) - 2 * sizeof(MCRegisterClass),
      1
    },
    {
      offsetof(LoongArchRegisterClassStorage, Regs[95]) - 3 * sizeof(MCRegisterClass),
      offsetof(LoongArchRegisterClassStorage, BitSets[25]) - 3 * sizeof(MCRegisterClass),
      0,
      0,
      30,
      10,
      LoongArch::GPRNoR0R1RegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(LoongArchRegisterClassStorage, SubClassMasks[4]) - 3 * sizeof(MCRegisterClass),
      offsetof(LoongArchRegisterClassStorage, SuperRegIdxSeqs[1]) - 3 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(LoongArchRegisterClassStorage, SuperClasses[1]) - 3 * sizeof(MCRegisterClass),
      2
    },
    {
      offsetof(LoongArchRegisterClassStorage, Regs[125]) - 4 * sizeof(MCRegisterClass),
      offsetof(LoongArchRegisterClassStorage, BitSets[35]) - 4 * sizeof(MCRegisterClass),
      60,
      0,
      17,
      9,
      LoongArch::GPRTRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(LoongArchRegisterClassStorage, SubClassMasks[5]) - 4 * sizeof(MCRegisterClass),
      offsetof(LoongArchRegisterClassStorage, SuperRegIdxSeqs[1]) - 4 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(LoongArchRegisterClassStorage, SuperClasses[3]) - 4 * sizeof(MCRegisterClass),
      3
    },
    {
      offsetof(LoongArchRegisterClassStorage, Regs[142]) - 5 * sizeof(MCRegisterClass),
      offsetof(LoongArchRegisterClassStorage, BitSets[44]) - 5 * sizeof(MCRegisterClass),
      41,
      0,
      8,
      6,
      LoongArch::CFRRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(LoongArchRegisterClassStorage, SubClassMasks[6]) - 5 * sizeof(MCRegisterClass),
      offsetof(LoongArchRegisterClassStorage, SuperRegIdxSeqs[1]) - 5 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(LoongArchRegisterClassStorage, SuperClasses[6]) - 5 * sizeof(MCRegisterClass),
      0
    },
    {
      offsetof(LoongArchRegisterClassStorage, Regs[150]) - 6 * sizeof(MCRegisterClass),
      offsetof(LoongArchRegisterClassStorage, BitSets[50]) - 6 * sizeof(MCRegisterClass),
      55,
      32,
      4,
      6,
      LoongArch::FCSRRegClassID,
      1, /* CopyCost */
      false, /* Allocatable */
      false,
      offsetof(LoongArchRegisterClassStorage, SubClassMasks[7]) - 6 * sizeof(MCRegisterClass),
      offsetof(LoongArchRegisterClassStorage, SuperRegIdxSeqs[1]) - 6 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(LoongArchRegisterClassStorage, SuperClasses[6]) - 6 * sizeof(MCRegisterClass),
      0
    },
    {
      offsetof(LoongArchRegisterClassStorage, Regs[154]) - 7 * sizeof(MCRegisterClass),
      offsetof(LoongArchRegisterClassStorage, BitSets[56]) - 7 * sizeof(MCRegisterClass),
      37,
      0,
      4,
      11,
      LoongArch::SCRRegClassID,
      1, /* CopyCost */
      false, /* Allocatable */
      false,
      offsetof(LoongArchRegisterClassStorage, SubClassMasks[8]) - 7 * sizeof(MCRegisterClass),
      offsetof(LoongArchRegisterClassStorage, SuperRegIdxSeqs[1]) - 7 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(LoongArchRegisterClassStorage, SuperClasses[6]) - 7 * sizeof(MCRegisterClass),
      0
    },
    {
      offsetof(LoongArchRegisterClassStorage, Regs[158]) - 8 * sizeof(MCRegisterClass),
      offsetof(LoongArchRegisterClassStorage, BitSets[67]) - 8 * sizeof(MCRegisterClass),
      16,
      64,
      32,
      23,
      LoongArch::FPR64RegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(LoongArchRegisterClassStorage, SubClassMasks[9]) - 8 * sizeof(MCRegisterClass),
      offsetof(LoongArchRegisterClassStorage, SuperRegIdxSeqs[2]) - 8 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(LoongArchRegisterClassStorage, SuperClasses[6]) - 8 * sizeof(MCRegisterClass),
      0
    },
    {
      offsetof(LoongArchRegisterClassStorage, Regs[190]) - 9 * sizeof(MCRegisterClass),
      offsetof(LoongArchRegisterClassStorage, BitSets[90]) - 9 * sizeof(MCRegisterClass),
      30,
      128,
      32,
      15,
      LoongArch::LSX128RegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(LoongArchRegisterClassStorage, SubClassMasks[11]) - 9 * sizeof(MCRegisterClass),
      offsetof(LoongArchRegisterClassStorage, SuperRegIdxSeqs[4]) - 9 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(LoongArchRegisterClassStorage, SuperClasses[6]) - 9 * sizeof(MCRegisterClass),
      0
    },
    {
      offsetof(LoongArchRegisterClassStorage, Regs[222]) - 10 * sizeof(MCRegisterClass),
      offsetof(LoongArchRegisterClassStorage, BitSets[105]) - 10 * sizeof(MCRegisterClass),
      22,
      256,
      32,
      19,
      LoongArch::LASX256RegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(LoongArchRegisterClassStorage, SubClassMasks[13]) - 10 * sizeof(MCRegisterClass),
      offsetof(LoongArchRegisterClassStorage, SuperRegIdxSeqs[1]) - 10 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(LoongArchRegisterClassStorage, SuperClasses[6]) - 10 * sizeof(MCRegisterClass),
      0
    },
  },
  {
    /* 0 */ LoongArch::F0, LoongArch::F1, LoongArch::F2, LoongArch::F3, LoongArch::F4, LoongArch::F5, LoongArch::F6, LoongArch::F7, LoongArch::F8, LoongArch::F9, LoongArch::F10, LoongArch::F11, LoongArch::F12, LoongArch::F13, LoongArch::F14, LoongArch::F15, LoongArch::F16, LoongArch::F17, LoongArch::F18, LoongArch::F19, LoongArch::F20, LoongArch::F21, LoongArch::F22, LoongArch::F23, LoongArch::F24, LoongArch::F25, LoongArch::F26, LoongArch::F27, LoongArch::F28, LoongArch::F29, LoongArch::F30, LoongArch::F31, 
    /* 32 */ LoongArch::R4, LoongArch::R5, LoongArch::R6, LoongArch::R7, LoongArch::R8, LoongArch::R9, LoongArch::R10, LoongArch::R11, LoongArch::R12, LoongArch::R13, LoongArch::R14, LoongArch::R15, LoongArch::R16, LoongArch::R17, LoongArch::R18, LoongArch::R19, LoongArch::R20, LoongArch::R22, LoongArch::R23, LoongArch::R24, LoongArch::R25, LoongArch::R26, LoongArch::R27, LoongArch::R28, LoongArch::R29, LoongArch::R30, LoongArch::R31, LoongArch::R0, LoongArch::R1, LoongArch::R2, LoongArch::R3, LoongArch::R21, 
    /* 64 */ LoongArch::R4, LoongArch::R5, LoongArch::R6, LoongArch::R7, LoongArch::R8, LoongArch::R9, LoongArch::R10, LoongArch::R11, LoongArch::R12, LoongArch::R13, LoongArch::R14, LoongArch::R15, LoongArch::R16, LoongArch::R17, LoongArch::R18, LoongArch::R19, LoongArch::R20, LoongArch::R22, LoongArch::R23, LoongArch::R24, LoongArch::R25, LoongArch::R26, LoongArch::R27, LoongArch::R28, LoongArch::R29, LoongArch::R30, LoongArch::R31, LoongArch::R0, LoongArch::R2, LoongArch::R3, LoongArch::R21, 
    /* 95 */ LoongArch::R4, LoongArch::R5, LoongArch::R6, LoongArch::R7, LoongArch::R8, LoongArch::R9, LoongArch::R10, LoongArch::R11, LoongArch::R12, LoongArch::R13, LoongArch::R14, LoongArch::R15, LoongArch::R16, LoongArch::R17, LoongArch::R18, LoongArch::R19, LoongArch::R20, LoongArch::R22, LoongArch::R23, LoongArch::R24, LoongArch::R25, LoongArch::R26, LoongArch::R27, LoongArch::R28, LoongArch::R29, LoongArch::R30, LoongArch::R31, LoongArch::R2, LoongArch::R3, LoongArch::R21, 
    /* 125 */ LoongArch::R4, LoongArch::R5, LoongArch::R6, LoongArch::R7, LoongArch::R8, LoongArch::R9, LoongArch::R10, LoongArch::R11, LoongArch::R12, LoongArch::R13, LoongArch::R14, LoongArch::R15, LoongArch::R16, LoongArch::R17, LoongArch::R18, LoongArch::R19, LoongArch::R20, 
    /* 142 */ LoongArch::FCC0, LoongArch::FCC1, LoongArch::FCC2, LoongArch::FCC3, LoongArch::FCC4, LoongArch::FCC5, LoongArch::FCC6, LoongArch::FCC7, 
    /* 150 */ LoongArch::FCSR0, LoongArch::FCSR1, LoongArch::FCSR2, LoongArch::FCSR3, 
    /* 154 */ LoongArch::SCR0, LoongArch::SCR1, LoongArch::SCR2, LoongArch::SCR3, 
    /* 158 */ LoongArch::F0_64, LoongArch::F1_64, LoongArch::F2_64, LoongArch::F3_64, LoongArch::F4_64, LoongArch::F5_64, LoongArch::F6_64, LoongArch::F7_64, LoongArch::F8_64, LoongArch::F9_64, LoongArch::F10_64, LoongArch::F11_64, LoongArch::F12_64, LoongArch::F13_64, LoongArch::F14_64, LoongArch::F15_64, LoongArch::F16_64, LoongArch::F17_64, LoongArch::F18_64, LoongArch::F19_64, LoongArch::F20_64, LoongArch::F21_64, LoongArch::F22_64, LoongArch::F23_64, LoongArch::F24_64, LoongArch::F25_64, LoongArch::F26_64, LoongArch::F27_64, LoongArch::F28_64, LoongArch::F29_64, LoongArch::F30_64, LoongArch::F31_64, 
    /* 190 */ LoongArch::VR0, LoongArch::VR1, LoongArch::VR2, LoongArch::VR3, LoongArch::VR4, LoongArch::VR5, LoongArch::VR6, LoongArch::VR7, LoongArch::VR8, LoongArch::VR9, LoongArch::VR10, LoongArch::VR11, LoongArch::VR12, LoongArch::VR13, LoongArch::VR14, LoongArch::VR15, LoongArch::VR16, LoongArch::VR17, LoongArch::VR18, LoongArch::VR19, LoongArch::VR20, LoongArch::VR21, LoongArch::VR22, LoongArch::VR23, LoongArch::VR24, LoongArch::VR25, LoongArch::VR26, LoongArch::VR27, LoongArch::VR28, LoongArch::VR29, LoongArch::VR30, LoongArch::VR31, 
    /* 222 */ LoongArch::XR0, LoongArch::XR1, LoongArch::XR2, LoongArch::XR3, LoongArch::XR4, LoongArch::XR5, LoongArch::XR6, LoongArch::XR7, LoongArch::XR8, LoongArch::XR9, LoongArch::XR10, LoongArch::XR11, LoongArch::XR12, LoongArch::XR13, LoongArch::XR14, LoongArch::XR15, LoongArch::XR16, LoongArch::XR17, LoongArch::XR18, LoongArch::XR19, LoongArch::XR20, LoongArch::XR21, LoongArch::XR22, LoongArch::XR23, LoongArch::XR24, LoongArch::XR25, LoongArch::XR26, LoongArch::XR27, LoongArch::XR28, LoongArch::XR29, LoongArch::XR30, LoongArch::XR31, 
  },
  {
    /* 0 */ 0xfe, 0xff, 0xff, 0xff, 0x01, 
    /* 5 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0xff, 0xff, 0x1f, 
    /* 15 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0xff, 0xff, 0xff, 0x1f, 
    /* 25 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xff, 0xff, 0xff, 0x1f, 
    /* 35 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xff, 0x03, 
    /* 44 */ 0x00, 0x00, 0x00, 0x00, 0xfe, 0x01, 
    /* 50 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x1e, 
    /* 56 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x01, 
    /* 67 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff, 0x01, 
    /* 90 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff, 0x01, 
    /* 105 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff, 0x01, 
  },
  {
    // 0 FPR32
    0x00000001, 
    0x00000700, // sub_32
    // 2 GPR
    0x0000001e, 
    // 3 GPRJR
    0x0000001c, 
    // 4 GPRNoR0R1
    0x00000018, 
    // 5 GPRT
    0x00000010, 
    // 6 CFR
    0x00000020, 
    // 7 FCSR
    0x00000040, 
    // 8 SCR
    0x00000080, 
    // 9 FPR64
    0x00000100, 
    0x00000600, // sub_64
    // 11 LSX128
    0x00000200, 
    0x00000400, // sub_128
    // 13 LASX256
    0x00000400, 
  },
  {
  /* 0 */ 1, 0,
  /* 2 */ 2, 0,
  /* 4 */ 3, 0,
  },
  {
    /* 0 FPR32 */ 
    /* 0 GPR */ 
    /* 0 GPRJR */ LoongArch::GPRRegClassID, 
    /* 1 GPRNoR0R1 */ LoongArch::GPRRegClassID, LoongArch::GPRJRRegClassID, 
    /* 3 GPRT */ LoongArch::GPRRegClassID, LoongArch::GPRJRRegClassID, LoongArch::GPRNoR0R1RegClassID, 
    /* 6 CFR */ 
    /* 6 FCSR */ 
    /* 6 SCR */ 
    /* 6 FPR64 */ 
    /* 6 LSX128 */ 
    /* 6 LASX256 */ 
  }
};

const MCRegisterClass &getLoongArchMCRegisterClass(unsigned RC) {
  return LoongArchMCRegisterClassStorage.Classes[RC];
}

// LoongArch Dwarf<->LLVM register mappings.
extern const MCRegisterInfo::DwarfLLVMRegPair LoongArchDwarfFlavour0Dwarf2L[] = {
  { 0U, LoongArch::R0 },
  { 1U, LoongArch::R1 },
  { 2U, LoongArch::R2 },
  { 3U, LoongArch::R3 },
  { 4U, LoongArch::R4 },
  { 5U, LoongArch::R5 },
  { 6U, LoongArch::R6 },
  { 7U, LoongArch::R7 },
  { 8U, LoongArch::R8 },
  { 9U, LoongArch::R9 },
  { 10U, LoongArch::R10 },
  { 11U, LoongArch::R11 },
  { 12U, LoongArch::R12 },
  { 13U, LoongArch::R13 },
  { 14U, LoongArch::R14 },
  { 15U, LoongArch::R15 },
  { 16U, LoongArch::R16 },
  { 17U, LoongArch::R17 },
  { 18U, LoongArch::R18 },
  { 19U, LoongArch::R19 },
  { 20U, LoongArch::R20 },
  { 21U, LoongArch::R21 },
  { 22U, LoongArch::R22 },
  { 23U, LoongArch::R23 },
  { 24U, LoongArch::R24 },
  { 25U, LoongArch::R25 },
  { 26U, LoongArch::R26 },
  { 27U, LoongArch::R27 },
  { 28U, LoongArch::R28 },
  { 29U, LoongArch::R29 },
  { 30U, LoongArch::R30 },
  { 31U, LoongArch::R31 },
  { 32U, LoongArch::F0_64 },
  { 33U, LoongArch::F1_64 },
  { 34U, LoongArch::F2_64 },
  { 35U, LoongArch::F3_64 },
  { 36U, LoongArch::F4_64 },
  { 37U, LoongArch::F5_64 },
  { 38U, LoongArch::F6_64 },
  { 39U, LoongArch::F7_64 },
  { 40U, LoongArch::F8_64 },
  { 41U, LoongArch::F9_64 },
  { 42U, LoongArch::F10_64 },
  { 43U, LoongArch::F11_64 },
  { 44U, LoongArch::F12_64 },
  { 45U, LoongArch::F13_64 },
  { 46U, LoongArch::F14_64 },
  { 47U, LoongArch::F15_64 },
  { 48U, LoongArch::F16_64 },
  { 49U, LoongArch::F17_64 },
  { 50U, LoongArch::F18_64 },
  { 51U, LoongArch::F19_64 },
  { 52U, LoongArch::F20_64 },
  { 53U, LoongArch::F21_64 },
  { 54U, LoongArch::F22_64 },
  { 55U, LoongArch::F23_64 },
  { 56U, LoongArch::F24_64 },
  { 57U, LoongArch::F25_64 },
  { 58U, LoongArch::F26_64 },
  { 59U, LoongArch::F27_64 },
  { 60U, LoongArch::F28_64 },
  { 61U, LoongArch::F29_64 },
  { 62U, LoongArch::F30_64 },
  { 63U, LoongArch::F31_64 },
};
extern const unsigned LoongArchDwarfFlavour0Dwarf2LSize = std::size(LoongArchDwarfFlavour0Dwarf2L);

extern const MCRegisterInfo::DwarfLLVMRegPair LoongArchEHFlavour0Dwarf2L[] = {
  { 0U, LoongArch::R0 },
  { 1U, LoongArch::R1 },
  { 2U, LoongArch::R2 },
  { 3U, LoongArch::R3 },
  { 4U, LoongArch::R4 },
  { 5U, LoongArch::R5 },
  { 6U, LoongArch::R6 },
  { 7U, LoongArch::R7 },
  { 8U, LoongArch::R8 },
  { 9U, LoongArch::R9 },
  { 10U, LoongArch::R10 },
  { 11U, LoongArch::R11 },
  { 12U, LoongArch::R12 },
  { 13U, LoongArch::R13 },
  { 14U, LoongArch::R14 },
  { 15U, LoongArch::R15 },
  { 16U, LoongArch::R16 },
  { 17U, LoongArch::R17 },
  { 18U, LoongArch::R18 },
  { 19U, LoongArch::R19 },
  { 20U, LoongArch::R20 },
  { 21U, LoongArch::R21 },
  { 22U, LoongArch::R22 },
  { 23U, LoongArch::R23 },
  { 24U, LoongArch::R24 },
  { 25U, LoongArch::R25 },
  { 26U, LoongArch::R26 },
  { 27U, LoongArch::R27 },
  { 28U, LoongArch::R28 },
  { 29U, LoongArch::R29 },
  { 30U, LoongArch::R30 },
  { 31U, LoongArch::R31 },
  { 32U, LoongArch::F0_64 },
  { 33U, LoongArch::F1_64 },
  { 34U, LoongArch::F2_64 },
  { 35U, LoongArch::F3_64 },
  { 36U, LoongArch::F4_64 },
  { 37U, LoongArch::F5_64 },
  { 38U, LoongArch::F6_64 },
  { 39U, LoongArch::F7_64 },
  { 40U, LoongArch::F8_64 },
  { 41U, LoongArch::F9_64 },
  { 42U, LoongArch::F10_64 },
  { 43U, LoongArch::F11_64 },
  { 44U, LoongArch::F12_64 },
  { 45U, LoongArch::F13_64 },
  { 46U, LoongArch::F14_64 },
  { 47U, LoongArch::F15_64 },
  { 48U, LoongArch::F16_64 },
  { 49U, LoongArch::F17_64 },
  { 50U, LoongArch::F18_64 },
  { 51U, LoongArch::F19_64 },
  { 52U, LoongArch::F20_64 },
  { 53U, LoongArch::F21_64 },
  { 54U, LoongArch::F22_64 },
  { 55U, LoongArch::F23_64 },
  { 56U, LoongArch::F24_64 },
  { 57U, LoongArch::F25_64 },
  { 58U, LoongArch::F26_64 },
  { 59U, LoongArch::F27_64 },
  { 60U, LoongArch::F28_64 },
  { 61U, LoongArch::F29_64 },
  { 62U, LoongArch::F30_64 },
  { 63U, LoongArch::F31_64 },
};
extern const unsigned LoongArchEHFlavour0Dwarf2LSize = std::size(LoongArchEHFlavour0Dwarf2L);

extern const MCRegisterInfo::DwarfLLVMRegPair LoongArchDwarfFlavour0L2Dwarf[] = {
  { LoongArch::F0, 32U },
  { LoongArch::F1, 33U },
  { LoongArch::F2, 34U },
  { LoongArch::F3, 35U },
  { LoongArch::F4, 36U },
  { LoongArch::F5, 37U },
  { LoongArch::F6, 38U },
  { LoongArch::F7, 39U },
  { LoongArch::F8, 40U },
  { LoongArch::F9, 41U },
  { LoongArch::F10, 42U },
  { LoongArch::F11, 43U },
  { LoongArch::F12, 44U },
  { LoongArch::F13, 45U },
  { LoongArch::F14, 46U },
  { LoongArch::F15, 47U },
  { LoongArch::F16, 48U },
  { LoongArch::F17, 49U },
  { LoongArch::F18, 50U },
  { LoongArch::F19, 51U },
  { LoongArch::F20, 52U },
  { LoongArch::F21, 53U },
  { LoongArch::F22, 54U },
  { LoongArch::F23, 55U },
  { LoongArch::F24, 56U },
  { LoongArch::F25, 57U },
  { LoongArch::F26, 58U },
  { LoongArch::F27, 59U },
  { LoongArch::F28, 60U },
  { LoongArch::F29, 61U },
  { LoongArch::F30, 62U },
  { LoongArch::F31, 63U },
  { LoongArch::R0, 0U },
  { LoongArch::R1, 1U },
  { LoongArch::R2, 2U },
  { LoongArch::R3, 3U },
  { LoongArch::R4, 4U },
  { LoongArch::R5, 5U },
  { LoongArch::R6, 6U },
  { LoongArch::R7, 7U },
  { LoongArch::R8, 8U },
  { LoongArch::R9, 9U },
  { LoongArch::R10, 10U },
  { LoongArch::R11, 11U },
  { LoongArch::R12, 12U },
  { LoongArch::R13, 13U },
  { LoongArch::R14, 14U },
  { LoongArch::R15, 15U },
  { LoongArch::R16, 16U },
  { LoongArch::R17, 17U },
  { LoongArch::R18, 18U },
  { LoongArch::R19, 19U },
  { LoongArch::R20, 20U },
  { LoongArch::R21, 21U },
  { LoongArch::R22, 22U },
  { LoongArch::R23, 23U },
  { LoongArch::R24, 24U },
  { LoongArch::R25, 25U },
  { LoongArch::R26, 26U },
  { LoongArch::R27, 27U },
  { LoongArch::R28, 28U },
  { LoongArch::R29, 29U },
  { LoongArch::R30, 30U },
  { LoongArch::R31, 31U },
  { LoongArch::VR0, 32U },
  { LoongArch::VR1, 33U },
  { LoongArch::VR2, 34U },
  { LoongArch::VR3, 35U },
  { LoongArch::VR4, 36U },
  { LoongArch::VR5, 37U },
  { LoongArch::VR6, 38U },
  { LoongArch::VR7, 39U },
  { LoongArch::VR8, 40U },
  { LoongArch::VR9, 41U },
  { LoongArch::VR10, 42U },
  { LoongArch::VR11, 43U },
  { LoongArch::VR12, 44U },
  { LoongArch::VR13, 45U },
  { LoongArch::VR14, 46U },
  { LoongArch::VR15, 47U },
  { LoongArch::VR16, 48U },
  { LoongArch::VR17, 49U },
  { LoongArch::VR18, 50U },
  { LoongArch::VR19, 51U },
  { LoongArch::VR20, 52U },
  { LoongArch::VR21, 53U },
  { LoongArch::VR22, 54U },
  { LoongArch::VR23, 55U },
  { LoongArch::VR24, 56U },
  { LoongArch::VR25, 57U },
  { LoongArch::VR26, 58U },
  { LoongArch::VR27, 59U },
  { LoongArch::VR28, 60U },
  { LoongArch::VR29, 61U },
  { LoongArch::VR30, 62U },
  { LoongArch::VR31, 63U },
  { LoongArch::XR0, 32U },
  { LoongArch::XR1, 33U },
  { LoongArch::XR2, 34U },
  { LoongArch::XR3, 35U },
  { LoongArch::XR4, 36U },
  { LoongArch::XR5, 37U },
  { LoongArch::XR6, 38U },
  { LoongArch::XR7, 39U },
  { LoongArch::XR8, 40U },
  { LoongArch::XR9, 41U },
  { LoongArch::XR10, 42U },
  { LoongArch::XR11, 43U },
  { LoongArch::XR12, 44U },
  { LoongArch::XR13, 45U },
  { LoongArch::XR14, 46U },
  { LoongArch::XR15, 47U },
  { LoongArch::XR16, 48U },
  { LoongArch::XR17, 49U },
  { LoongArch::XR18, 50U },
  { LoongArch::XR19, 51U },
  { LoongArch::XR20, 52U },
  { LoongArch::XR21, 53U },
  { LoongArch::XR22, 54U },
  { LoongArch::XR23, 55U },
  { LoongArch::XR24, 56U },
  { LoongArch::XR25, 57U },
  { LoongArch::XR26, 58U },
  { LoongArch::XR27, 59U },
  { LoongArch::XR28, 60U },
  { LoongArch::XR29, 61U },
  { LoongArch::XR30, 62U },
  { LoongArch::XR31, 63U },
  { LoongArch::F0_64, 32U },
  { LoongArch::F1_64, 33U },
  { LoongArch::F2_64, 34U },
  { LoongArch::F3_64, 35U },
  { LoongArch::F4_64, 36U },
  { LoongArch::F5_64, 37U },
  { LoongArch::F6_64, 38U },
  { LoongArch::F7_64, 39U },
  { LoongArch::F8_64, 40U },
  { LoongArch::F9_64, 41U },
  { LoongArch::F10_64, 42U },
  { LoongArch::F11_64, 43U },
  { LoongArch::F12_64, 44U },
  { LoongArch::F13_64, 45U },
  { LoongArch::F14_64, 46U },
  { LoongArch::F15_64, 47U },
  { LoongArch::F16_64, 48U },
  { LoongArch::F17_64, 49U },
  { LoongArch::F18_64, 50U },
  { LoongArch::F19_64, 51U },
  { LoongArch::F20_64, 52U },
  { LoongArch::F21_64, 53U },
  { LoongArch::F22_64, 54U },
  { LoongArch::F23_64, 55U },
  { LoongArch::F24_64, 56U },
  { LoongArch::F25_64, 57U },
  { LoongArch::F26_64, 58U },
  { LoongArch::F27_64, 59U },
  { LoongArch::F28_64, 60U },
  { LoongArch::F29_64, 61U },
  { LoongArch::F30_64, 62U },
  { LoongArch::F31_64, 63U },
};
extern const unsigned LoongArchDwarfFlavour0L2DwarfSize = std::size(LoongArchDwarfFlavour0L2Dwarf);

extern const MCRegisterInfo::DwarfLLVMRegPair LoongArchEHFlavour0L2Dwarf[] = {
  { LoongArch::F0, 32U },
  { LoongArch::F1, 33U },
  { LoongArch::F2, 34U },
  { LoongArch::F3, 35U },
  { LoongArch::F4, 36U },
  { LoongArch::F5, 37U },
  { LoongArch::F6, 38U },
  { LoongArch::F7, 39U },
  { LoongArch::F8, 40U },
  { LoongArch::F9, 41U },
  { LoongArch::F10, 42U },
  { LoongArch::F11, 43U },
  { LoongArch::F12, 44U },
  { LoongArch::F13, 45U },
  { LoongArch::F14, 46U },
  { LoongArch::F15, 47U },
  { LoongArch::F16, 48U },
  { LoongArch::F17, 49U },
  { LoongArch::F18, 50U },
  { LoongArch::F19, 51U },
  { LoongArch::F20, 52U },
  { LoongArch::F21, 53U },
  { LoongArch::F22, 54U },
  { LoongArch::F23, 55U },
  { LoongArch::F24, 56U },
  { LoongArch::F25, 57U },
  { LoongArch::F26, 58U },
  { LoongArch::F27, 59U },
  { LoongArch::F28, 60U },
  { LoongArch::F29, 61U },
  { LoongArch::F30, 62U },
  { LoongArch::F31, 63U },
  { LoongArch::R0, 0U },
  { LoongArch::R1, 1U },
  { LoongArch::R2, 2U },
  { LoongArch::R3, 3U },
  { LoongArch::R4, 4U },
  { LoongArch::R5, 5U },
  { LoongArch::R6, 6U },
  { LoongArch::R7, 7U },
  { LoongArch::R8, 8U },
  { LoongArch::R9, 9U },
  { LoongArch::R10, 10U },
  { LoongArch::R11, 11U },
  { LoongArch::R12, 12U },
  { LoongArch::R13, 13U },
  { LoongArch::R14, 14U },
  { LoongArch::R15, 15U },
  { LoongArch::R16, 16U },
  { LoongArch::R17, 17U },
  { LoongArch::R18, 18U },
  { LoongArch::R19, 19U },
  { LoongArch::R20, 20U },
  { LoongArch::R21, 21U },
  { LoongArch::R22, 22U },
  { LoongArch::R23, 23U },
  { LoongArch::R24, 24U },
  { LoongArch::R25, 25U },
  { LoongArch::R26, 26U },
  { LoongArch::R27, 27U },
  { LoongArch::R28, 28U },
  { LoongArch::R29, 29U },
  { LoongArch::R30, 30U },
  { LoongArch::R31, 31U },
  { LoongArch::VR0, 32U },
  { LoongArch::VR1, 33U },
  { LoongArch::VR2, 34U },
  { LoongArch::VR3, 35U },
  { LoongArch::VR4, 36U },
  { LoongArch::VR5, 37U },
  { LoongArch::VR6, 38U },
  { LoongArch::VR7, 39U },
  { LoongArch::VR8, 40U },
  { LoongArch::VR9, 41U },
  { LoongArch::VR10, 42U },
  { LoongArch::VR11, 43U },
  { LoongArch::VR12, 44U },
  { LoongArch::VR13, 45U },
  { LoongArch::VR14, 46U },
  { LoongArch::VR15, 47U },
  { LoongArch::VR16, 48U },
  { LoongArch::VR17, 49U },
  { LoongArch::VR18, 50U },
  { LoongArch::VR19, 51U },
  { LoongArch::VR20, 52U },
  { LoongArch::VR21, 53U },
  { LoongArch::VR22, 54U },
  { LoongArch::VR23, 55U },
  { LoongArch::VR24, 56U },
  { LoongArch::VR25, 57U },
  { LoongArch::VR26, 58U },
  { LoongArch::VR27, 59U },
  { LoongArch::VR28, 60U },
  { LoongArch::VR29, 61U },
  { LoongArch::VR30, 62U },
  { LoongArch::VR31, 63U },
  { LoongArch::XR0, 32U },
  { LoongArch::XR1, 33U },
  { LoongArch::XR2, 34U },
  { LoongArch::XR3, 35U },
  { LoongArch::XR4, 36U },
  { LoongArch::XR5, 37U },
  { LoongArch::XR6, 38U },
  { LoongArch::XR7, 39U },
  { LoongArch::XR8, 40U },
  { LoongArch::XR9, 41U },
  { LoongArch::XR10, 42U },
  { LoongArch::XR11, 43U },
  { LoongArch::XR12, 44U },
  { LoongArch::XR13, 45U },
  { LoongArch::XR14, 46U },
  { LoongArch::XR15, 47U },
  { LoongArch::XR16, 48U },
  { LoongArch::XR17, 49U },
  { LoongArch::XR18, 50U },
  { LoongArch::XR19, 51U },
  { LoongArch::XR20, 52U },
  { LoongArch::XR21, 53U },
  { LoongArch::XR22, 54U },
  { LoongArch::XR23, 55U },
  { LoongArch::XR24, 56U },
  { LoongArch::XR25, 57U },
  { LoongArch::XR26, 58U },
  { LoongArch::XR27, 59U },
  { LoongArch::XR28, 60U },
  { LoongArch::XR29, 61U },
  { LoongArch::XR30, 62U },
  { LoongArch::XR31, 63U },
  { LoongArch::F0_64, 32U },
  { LoongArch::F1_64, 33U },
  { LoongArch::F2_64, 34U },
  { LoongArch::F3_64, 35U },
  { LoongArch::F4_64, 36U },
  { LoongArch::F5_64, 37U },
  { LoongArch::F6_64, 38U },
  { LoongArch::F7_64, 39U },
  { LoongArch::F8_64, 40U },
  { LoongArch::F9_64, 41U },
  { LoongArch::F10_64, 42U },
  { LoongArch::F11_64, 43U },
  { LoongArch::F12_64, 44U },
  { LoongArch::F13_64, 45U },
  { LoongArch::F14_64, 46U },
  { LoongArch::F15_64, 47U },
  { LoongArch::F16_64, 48U },
  { LoongArch::F17_64, 49U },
  { LoongArch::F18_64, 50U },
  { LoongArch::F19_64, 51U },
  { LoongArch::F20_64, 52U },
  { LoongArch::F21_64, 53U },
  { LoongArch::F22_64, 54U },
  { LoongArch::F23_64, 55U },
  { LoongArch::F24_64, 56U },
  { LoongArch::F25_64, 57U },
  { LoongArch::F26_64, 58U },
  { LoongArch::F27_64, 59U },
  { LoongArch::F28_64, 60U },
  { LoongArch::F29_64, 61U },
  { LoongArch::F30_64, 62U },
  { LoongArch::F31_64, 63U },
};
extern const unsigned LoongArchEHFlavour0L2DwarfSize = std::size(LoongArchEHFlavour0L2Dwarf);

extern const uint16_t LoongArchRegEncodingTable[] = {
  0,
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
  0,
  1,
  2,
  3,
  4,
  5,
  6,
  7,
  0,
  1,
  2,
  3,
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
  0,
  1,
  2,
  3,
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
static inline void InitLoongArchMCRegisterInfo(MCRegisterInfo *RI, unsigned RA, unsigned DwarfFlavour = 0, unsigned EHFlavour = 0, unsigned PC = 0) {
  RI->InitMCRegisterInfo(LoongArchRegDesc, 177, RA, PC, LoongArchMCRegisterClassStorage.Classes, 11, LoongArchRegUnitRoots, 80, LoongArchRegDiffLists, LoongArchLaneMaskLists, LoongArchRegStrings, LoongArchRegClassStrings, LoongArchSubRegIdxLists, 4,
LoongArchRegEncodingTable, nullptr);

  switch (DwarfFlavour) {
  default:
    llvm_unreachable("Unknown DWARF flavour");
  case 0:
    RI->mapDwarfRegsToLLVMRegs(LoongArchDwarfFlavour0Dwarf2L, LoongArchDwarfFlavour0Dwarf2LSize, false);
    break;
  }
  switch (EHFlavour) {
  default:
    llvm_unreachable("Unknown DWARF flavour");
  case 0:
    RI->mapDwarfRegsToLLVMRegs(LoongArchEHFlavour0Dwarf2L, LoongArchEHFlavour0Dwarf2LSize, true);
    break;
  }
  switch (DwarfFlavour) {
  default:
    llvm_unreachable("Unknown DWARF flavour");
  case 0:
    RI->mapLLVMRegsToDwarfRegs(LoongArchDwarfFlavour0L2Dwarf, LoongArchDwarfFlavour0L2DwarfSize, false);
    break;
  }
  switch (EHFlavour) {
  default:
    llvm_unreachable("Unknown DWARF flavour");
  case 0:
    RI->mapLLVMRegsToDwarfRegs(LoongArchEHFlavour0L2Dwarf, LoongArchEHFlavour0L2DwarfSize, true);
    break;
  }
}


} // namespace llvm_ks
