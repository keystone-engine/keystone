/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* MC Register Information                                                    *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

namespace llvm_ks {

extern const int16_t SystemZRegDiffLists[] = {
  /* 0 */ -64, 72, -40, -30, 72, -40, 0,
  /* 7 */ -62, 72, -40, -30, 72, -40, 0,
  /* 14 */ -60, 72, -40, -30, 72, -40, 0,
  /* 21 */ -58, 72, -40, -30, 72, -40, 0,
  /* 28 */ 32, 72, -40, 0,
  /* 32 */ 40, -72, -32, 0,
  /* 36 */ -48, 32, -16, -15, 32, -16, 0,
  /* 43 */ -47, 32, -16, -15, 32, -16, 0,
  /* 50 */ -46, 32, -16, -15, 32, -16, 0,
  /* 57 */ -45, 32, -16, -15, 32, -16, 0,
  /* 64 */ -44, 32, -16, -15, 32, -16, 0,
  /* 71 */ -43, 32, -16, -15, 32, -16, 0,
  /* 78 */ -42, 32, -16, -15, 32, -16, 0,
  /* 85 */ -41, 32, -16, -15, 32, -16, 0,
  /* 92 */ 1, 1, 1, 0,
  /* 96 */ 2, 0,
  /* 98 */ -32, 40, 0,
  /* 101 */ -16, 40, 0,
  /* 104 */ -32, 41, 0,
  /* 107 */ -16, 41, 0,
  /* 110 */ -32, 42, 0,
  /* 113 */ -16, 42, 0,
  /* 116 */ -32, 43, 0,
  /* 119 */ -16, 43, 0,
  /* 122 */ -32, 44, 0,
  /* 125 */ -16, 44, 0,
  /* 128 */ -32, 45, 0,
  /* 131 */ -16, 45, 0,
  /* 134 */ -32, 46, 0,
  /* 137 */ -16, 46, 0,
  /* 140 */ -32, 47, 0,
  /* 143 */ -16, 47, 0,
  /* 146 */ -32, 48, 0,
  /* 149 */ -16, 48, 0,
  /* 152 */ 40, -72, -32, 88, 0,
  /* 157 */ 40, -72, -32, 90, 0,
  /* 162 */ 40, -72, -32, 92, 0,
  /* 167 */ 40, -72, -32, 94, 0,
  /* 172 */ 40, -72, -32, 96, 0,
};

extern const LaneBitmask SystemZLaneMaskLists[] = {
  /* 0 */ LaneBitmask(0x0000000000000002), LaneBitmask(0x0000000000000001), 
  /* 2 */ LaneBitmask(0x0000000000000001), LaneBitmask(0x0000000000000008), 
  /* 4 */ LaneBitmask(0x0000000000000002), LaneBitmask(0x0000000000000001), LaneBitmask(0x0000000000000004), LaneBitmask(0x0000000000000008), 
  /* 8 */ LaneBitmask(0xFFFFFFFFFFFFFFFF), 
};

extern const uint16_t SystemZSubRegIdxLists[] = {
  /* 0 */ 3, 2, 1, 
  /* 3 */ 4, 2, 
  /* 5 */ 3, 4, 2, 5, 7, 6, 
  /* 11 */ 3, 2, 1, 5, 6, 8, 
};


#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"
#endif
extern const char SystemZRegStrings[] = {
  /* 0 */ "A10\000"
  /* 4 */ "C10\000"
  /* 8 */ "V10\000"
  /* 12 */ "V20\000"
  /* 16 */ "V30\000"
  /* 20 */ "A0\000"
  /* 23 */ "C0\000"
  /* 26 */ "V0\000"
  /* 29 */ "A11\000"
  /* 33 */ "C11\000"
  /* 37 */ "V11\000"
  /* 41 */ "V21\000"
  /* 45 */ "V31\000"
  /* 49 */ "A1\000"
  /* 52 */ "C1\000"
  /* 55 */ "V1\000"
  /* 58 */ "A12\000"
  /* 62 */ "C12\000"
  /* 66 */ "V12\000"
  /* 70 */ "V22\000"
  /* 74 */ "A2\000"
  /* 77 */ "C2\000"
  /* 80 */ "V2\000"
  /* 83 */ "A13\000"
  /* 87 */ "C13\000"
  /* 91 */ "V13\000"
  /* 95 */ "V23\000"
  /* 99 */ "A3\000"
  /* 102 */ "C3\000"
  /* 105 */ "V3\000"
  /* 108 */ "A14\000"
  /* 112 */ "C14\000"
  /* 116 */ "V14\000"
  /* 120 */ "V24\000"
  /* 124 */ "A4\000"
  /* 127 */ "C4\000"
  /* 130 */ "V4\000"
  /* 133 */ "A15\000"
  /* 137 */ "C15\000"
  /* 141 */ "V15\000"
  /* 145 */ "V25\000"
  /* 149 */ "A5\000"
  /* 152 */ "C5\000"
  /* 155 */ "V5\000"
  /* 158 */ "V16\000"
  /* 162 */ "V26\000"
  /* 166 */ "A6\000"
  /* 169 */ "C6\000"
  /* 172 */ "V6\000"
  /* 175 */ "V17\000"
  /* 179 */ "V27\000"
  /* 183 */ "A7\000"
  /* 186 */ "C7\000"
  /* 189 */ "V7\000"
  /* 192 */ "V18\000"
  /* 196 */ "V28\000"
  /* 200 */ "A8\000"
  /* 203 */ "C8\000"
  /* 206 */ "V8\000"
  /* 209 */ "V19\000"
  /* 213 */ "V29\000"
  /* 217 */ "A9\000"
  /* 220 */ "C9\000"
  /* 223 */ "V9\000"
  /* 226 */ "CC\000"
  /* 229 */ "FPC\000"
  /* 233 */ "F10D\000"
  /* 238 */ "R10D\000"
  /* 243 */ "F20D\000"
  /* 248 */ "F30D\000"
  /* 253 */ "F0D\000"
  /* 257 */ "R0D\000"
  /* 261 */ "F11D\000"
  /* 266 */ "R11D\000"
  /* 271 */ "F21D\000"
  /* 276 */ "F31D\000"
  /* 281 */ "F1D\000"
  /* 285 */ "R1D\000"
  /* 289 */ "F12D\000"
  /* 294 */ "R12D\000"
  /* 299 */ "F22D\000"
  /* 304 */ "F2D\000"
  /* 308 */ "R2D\000"
  /* 312 */ "F13D\000"
  /* 317 */ "R13D\000"
  /* 322 */ "F23D\000"
  /* 327 */ "F3D\000"
  /* 331 */ "R3D\000"
  /* 335 */ "F14D\000"
  /* 340 */ "R14D\000"
  /* 345 */ "F24D\000"
  /* 350 */ "F4D\000"
  /* 354 */ "R4D\000"
  /* 358 */ "F15D\000"
  /* 363 */ "R15D\000"
  /* 368 */ "F25D\000"
  /* 373 */ "F5D\000"
  /* 377 */ "R5D\000"
  /* 381 */ "F16D\000"
  /* 386 */ "F26D\000"
  /* 391 */ "F6D\000"
  /* 395 */ "R6D\000"
  /* 399 */ "F17D\000"
  /* 404 */ "F27D\000"
  /* 409 */ "F7D\000"
  /* 413 */ "R7D\000"
  /* 417 */ "F18D\000"
  /* 422 */ "F28D\000"
  /* 427 */ "F8D\000"
  /* 431 */ "R8D\000"
  /* 435 */ "F19D\000"
  /* 440 */ "F29D\000"
  /* 445 */ "F9D\000"
  /* 449 */ "R9D\000"
  /* 453 */ "F10H\000"
  /* 458 */ "R10H\000"
  /* 463 */ "F20H\000"
  /* 468 */ "F30H\000"
  /* 473 */ "F0H\000"
  /* 477 */ "R0H\000"
  /* 481 */ "F11H\000"
  /* 486 */ "R11H\000"
  /* 491 */ "F21H\000"
  /* 496 */ "F31H\000"
  /* 501 */ "F1H\000"
  /* 505 */ "R1H\000"
  /* 509 */ "F12H\000"
  /* 514 */ "R12H\000"
  /* 519 */ "F22H\000"
  /* 524 */ "F2H\000"
  /* 528 */ "R2H\000"
  /* 532 */ "F13H\000"
  /* 537 */ "R13H\000"
  /* 542 */ "F23H\000"
  /* 547 */ "F3H\000"
  /* 551 */ "R3H\000"
  /* 555 */ "F14H\000"
  /* 560 */ "R14H\000"
  /* 565 */ "F24H\000"
  /* 570 */ "F4H\000"
  /* 574 */ "R4H\000"
  /* 578 */ "F15H\000"
  /* 583 */ "R15H\000"
  /* 588 */ "F25H\000"
  /* 593 */ "F5H\000"
  /* 597 */ "R5H\000"
  /* 601 */ "F16H\000"
  /* 606 */ "F26H\000"
  /* 611 */ "F6H\000"
  /* 615 */ "R6H\000"
  /* 619 */ "F17H\000"
  /* 624 */ "F27H\000"
  /* 629 */ "F7H\000"
  /* 633 */ "R7H\000"
  /* 637 */ "F18H\000"
  /* 642 */ "F28H\000"
  /* 647 */ "F8H\000"
  /* 651 */ "R8H\000"
  /* 655 */ "F19H\000"
  /* 660 */ "F29H\000"
  /* 665 */ "F9H\000"
  /* 669 */ "R9H\000"
  /* 673 */ "R10L\000"
  /* 678 */ "R0L\000"
  /* 682 */ "R11L\000"
  /* 687 */ "R1L\000"
  /* 691 */ "R12L\000"
  /* 696 */ "R2L\000"
  /* 700 */ "R13L\000"
  /* 705 */ "R3L\000"
  /* 709 */ "R14L\000"
  /* 714 */ "R4L\000"
  /* 718 */ "R15L\000"
  /* 723 */ "R5L\000"
  /* 727 */ "R6L\000"
  /* 731 */ "R7L\000"
  /* 735 */ "R8L\000"
  /* 739 */ "R9L\000"
  /* 743 */ "R10Q\000"
  /* 748 */ "F0Q\000"
  /* 752 */ "R0Q\000"
  /* 756 */ "F1Q\000"
  /* 760 */ "F12Q\000"
  /* 765 */ "R12Q\000"
  /* 770 */ "R2Q\000"
  /* 774 */ "F13Q\000"
  /* 779 */ "R14Q\000"
  /* 784 */ "F4Q\000"
  /* 788 */ "R4Q\000"
  /* 792 */ "F5Q\000"
  /* 796 */ "R6Q\000"
  /* 800 */ "F8Q\000"
  /* 804 */ "R8Q\000"
  /* 808 */ "F9Q\000"
  /* 812 */ "F10S\000"
  /* 817 */ "F20S\000"
  /* 822 */ "F30S\000"
  /* 827 */ "F0S\000"
  /* 831 */ "F11S\000"
  /* 836 */ "F21S\000"
  /* 841 */ "F31S\000"
  /* 846 */ "F1S\000"
  /* 850 */ "F12S\000"
  /* 855 */ "F22S\000"
  /* 860 */ "F2S\000"
  /* 864 */ "F13S\000"
  /* 869 */ "F23S\000"
  /* 874 */ "F3S\000"
  /* 878 */ "F14S\000"
  /* 883 */ "F24S\000"
  /* 888 */ "F4S\000"
  /* 892 */ "F15S\000"
  /* 897 */ "F25S\000"
  /* 902 */ "F5S\000"
  /* 906 */ "F16S\000"
  /* 911 */ "F26S\000"
  /* 916 */ "F6S\000"
  /* 920 */ "F17S\000"
  /* 925 */ "F27S\000"
  /* 930 */ "F7S\000"
  /* 934 */ "F18S\000"
  /* 939 */ "F28S\000"
  /* 944 */ "F8S\000"
  /* 948 */ "F19S\000"
  /* 953 */ "F29S\000"
  /* 958 */ "F9S\000"
};
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

extern const MCRegisterDesc SystemZRegDesc[] = { // Descriptors
  { 3, 0, 0, 0, 0, 0, 0, 0 },
  { 226, 6, 6, 3, 24576, 8, 0, 0 },
  { 229, 6, 6, 3, 24577, 8, 0, 0 },
  { 20, 6, 6, 3, 24578, 8, 0, 0 },
  { 49, 6, 6, 3, 24579, 8, 0, 0 },
  { 74, 6, 6, 3, 24580, 8, 0, 0 },
  { 99, 6, 6, 3, 24581, 8, 0, 0 },
  { 124, 6, 6, 3, 24582, 8, 0, 0 },
  { 149, 6, 6, 3, 24583, 8, 0, 0 },
  { 166, 6, 6, 3, 24584, 8, 0, 0 },
  { 183, 6, 6, 3, 24585, 8, 0, 0 },
  { 200, 6, 6, 3, 24586, 8, 0, 0 },
  { 217, 6, 6, 3, 24587, 8, 0, 0 },
  { 0, 6, 6, 3, 24588, 8, 0, 0 },
  { 29, 6, 6, 3, 24589, 8, 0, 0 },
  { 58, 6, 6, 3, 24590, 8, 0, 0 },
  { 83, 6, 6, 3, 24591, 8, 0, 0 },
  { 108, 6, 6, 3, 24592, 8, 0, 0 },
  { 133, 6, 6, 3, 24593, 8, 0, 0 },
  { 23, 6, 6, 3, 24594, 8, 0, 0 },
  { 52, 6, 6, 3, 24595, 8, 0, 0 },
  { 77, 6, 6, 3, 24596, 8, 0, 0 },
  { 102, 6, 6, 3, 24597, 8, 0, 0 },
  { 127, 6, 6, 3, 24598, 8, 0, 0 },
  { 152, 6, 6, 3, 24599, 8, 0, 0 },
  { 169, 6, 6, 3, 24600, 8, 0, 0 },
  { 186, 6, 6, 3, 24601, 8, 0, 0 },
  { 203, 6, 6, 3, 24602, 8, 0, 0 },
  { 220, 6, 6, 3, 24603, 8, 0, 0 },
  { 4, 6, 6, 3, 24604, 8, 0, 0 },
  { 33, 6, 6, 3, 24605, 8, 0, 0 },
  { 62, 6, 6, 3, 24606, 8, 0, 0 },
  { 87, 6, 6, 3, 24607, 8, 0, 0 },
  { 112, 6, 6, 3, 24608, 8, 0, 0 },
  { 137, 6, 6, 3, 24609, 8, 0, 0 },
  { 26, 28, 6, 0, 24610, 1, 0, 0 },
  { 55, 28, 6, 0, 24611, 1, 0, 0 },
  { 80, 28, 6, 0, 24612, 1, 0, 0 },
  { 105, 28, 6, 0, 24613, 1, 0, 0 },
  { 130, 28, 6, 0, 24614, 1, 0, 0 },
  { 155, 28, 6, 0, 24615, 1, 0, 0 },
  { 172, 28, 6, 0, 24616, 1, 0, 0 },
  { 189, 28, 6, 0, 24617, 1, 0, 0 },
  { 206, 28, 6, 0, 24618, 1, 0, 0 },
  { 223, 28, 6, 0, 24619, 1, 0, 0 },
  { 8, 28, 6, 0, 24620, 1, 0, 0 },
  { 37, 28, 6, 0, 24621, 1, 0, 0 },
  { 66, 28, 6, 0, 24622, 1, 0, 0 },
  { 91, 28, 6, 0, 24623, 1, 0, 0 },
  { 116, 28, 6, 0, 24624, 1, 0, 0 },
  { 141, 28, 6, 0, 24625, 1, 0, 0 },
  { 158, 28, 6, 0, 24626, 1, 0, 0 },
  { 175, 28, 6, 0, 24627, 1, 0, 0 },
  { 192, 28, 6, 0, 24628, 1, 0, 0 },
  { 209, 28, 6, 0, 24629, 1, 0, 0 },
  { 12, 28, 6, 0, 24630, 1, 0, 0 },
  { 41, 28, 6, 0, 24631, 1, 0, 0 },
  { 70, 28, 6, 0, 24632, 1, 0, 0 },
  { 95, 28, 6, 0, 24633, 1, 0, 0 },
  { 120, 28, 6, 0, 24634, 1, 0, 0 },
  { 145, 28, 6, 0, 24635, 1, 0, 0 },
  { 162, 28, 6, 0, 24636, 1, 0, 0 },
  { 179, 28, 6, 0, 24637, 1, 0, 0 },
  { 196, 28, 6, 0, 24638, 1, 0, 0 },
  { 213, 28, 6, 0, 24639, 1, 0, 0 },
  { 16, 28, 6, 0, 24640, 1, 0, 0 },
  { 45, 28, 6, 0, 24641, 1, 0, 0 },
  { 253, 4, 174, 1, 24610, 1, 0, 0 },
  { 281, 4, 174, 1, 24611, 1, 0, 0 },
  { 304, 4, 169, 1, 24612, 1, 0, 0 },
  { 327, 4, 169, 1, 24613, 1, 0, 0 },
  { 350, 4, 169, 1, 24614, 1, 0, 0 },
  { 373, 4, 169, 1, 24615, 1, 0, 0 },
  { 391, 4, 164, 1, 24616, 1, 0, 0 },
  { 409, 4, 164, 1, 24617, 1, 0, 0 },
  { 427, 4, 164, 1, 24618, 1, 0, 0 },
  { 445, 4, 164, 1, 24619, 1, 0, 0 },
  { 233, 4, 159, 1, 24620, 1, 0, 0 },
  { 261, 4, 159, 1, 24621, 1, 0, 0 },
  { 289, 4, 159, 1, 24622, 1, 0, 0 },
  { 312, 4, 159, 1, 24623, 1, 0, 0 },
  { 335, 4, 154, 1, 24624, 1, 0, 0 },
  { 358, 4, 154, 1, 24625, 1, 0, 0 },
  { 381, 4, 34, 1, 24626, 1, 0, 0 },
  { 399, 4, 34, 1, 24627, 1, 0, 0 },
  { 417, 4, 34, 1, 24628, 1, 0, 0 },
  { 435, 4, 34, 1, 24629, 1, 0, 0 },
  { 243, 4, 34, 1, 24630, 1, 0, 0 },
  { 271, 4, 34, 1, 24631, 1, 0, 0 },
  { 299, 4, 34, 1, 24632, 1, 0, 0 },
  { 322, 4, 34, 1, 24633, 1, 0, 0 },
  { 345, 4, 34, 1, 24634, 1, 0, 0 },
  { 368, 4, 34, 1, 24635, 1, 0, 0 },
  { 386, 4, 34, 1, 24636, 1, 0, 0 },
  { 404, 4, 34, 1, 24637, 1, 0, 0 },
  { 422, 4, 34, 1, 24638, 1, 0, 0 },
  { 440, 4, 34, 1, 24639, 1, 0, 0 },
  { 248, 4, 34, 1, 24640, 1, 0, 0 },
  { 276, 4, 34, 1, 24641, 1, 0, 0 },
  { 473, 6, 172, 3, 24610, 8, 0, 0 },
  { 501, 6, 172, 3, 24611, 8, 0, 0 },
  { 524, 6, 167, 3, 24612, 8, 0, 0 },
  { 547, 6, 167, 3, 24613, 8, 0, 0 },
  { 570, 6, 167, 3, 24614, 8, 0, 0 },
  { 593, 6, 167, 3, 24615, 8, 0, 0 },
  { 611, 6, 162, 3, 24616, 8, 0, 0 },
  { 629, 6, 162, 3, 24617, 8, 0, 0 },
  { 647, 6, 162, 3, 24618, 8, 0, 0 },
  { 665, 6, 162, 3, 24619, 8, 0, 0 },
  { 453, 6, 157, 3, 24620, 8, 0, 0 },
  { 481, 6, 157, 3, 24621, 8, 0, 0 },
  { 509, 6, 157, 3, 24622, 8, 0, 0 },
  { 532, 6, 157, 3, 24623, 8, 0, 0 },
  { 555, 6, 152, 3, 24624, 8, 0, 0 },
  { 578, 6, 152, 3, 24625, 8, 0, 0 },
  { 601, 6, 32, 3, 24626, 8, 0, 0 },
  { 619, 6, 32, 3, 24627, 8, 0, 0 },
  { 637, 6, 32, 3, 24628, 8, 0, 0 },
  { 655, 6, 32, 3, 24629, 8, 0, 0 },
  { 463, 6, 32, 3, 24630, 8, 0, 0 },
  { 491, 6, 32, 3, 24631, 8, 0, 0 },
  { 519, 6, 32, 3, 24632, 8, 0, 0 },
  { 542, 6, 32, 3, 24633, 8, 0, 0 },
  { 565, 6, 32, 3, 24634, 8, 0, 0 },
  { 588, 6, 32, 3, 24635, 8, 0, 0 },
  { 606, 6, 32, 3, 24636, 8, 0, 0 },
  { 624, 6, 32, 3, 24637, 8, 0, 0 },
  { 642, 6, 32, 3, 24638, 8, 0, 0 },
  { 660, 6, 32, 3, 24639, 8, 0, 0 },
  { 468, 6, 32, 3, 24640, 8, 0, 0 },
  { 496, 6, 32, 3, 24641, 8, 0, 0 },
  { 748, 0, 6, 11, 393250, 2, 0, 0 },
  { 756, 0, 6, 11, 393251, 2, 0, 0 },
  { 784, 7, 6, 11, 393254, 2, 0, 0 },
  { 792, 7, 6, 11, 393255, 2, 0, 0 },
  { 800, 14, 6, 11, 393258, 2, 0, 0 },
  { 808, 14, 6, 11, 393259, 2, 0, 0 },
  { 760, 21, 6, 11, 393262, 2, 0, 0 },
  { 774, 21, 6, 11, 393263, 2, 0, 0 },
  { 827, 5, 173, 2, 24610, 1, 0, 0 },
  { 846, 5, 173, 2, 24611, 1, 0, 0 },
  { 860, 5, 168, 2, 24612, 1, 0, 0 },
  { 874, 5, 168, 2, 24613, 1, 0, 0 },
  { 888, 5, 168, 2, 24614, 1, 0, 0 },
  { 902, 5, 168, 2, 24615, 1, 0, 0 },
  { 916, 5, 163, 2, 24616, 1, 0, 0 },
  { 930, 5, 163, 2, 24617, 1, 0, 0 },
  { 944, 5, 163, 2, 24618, 1, 0, 0 },
  { 958, 5, 163, 2, 24619, 1, 0, 0 },
  { 812, 5, 158, 2, 24620, 1, 0, 0 },
  { 831, 5, 158, 2, 24621, 1, 0, 0 },
  { 850, 5, 158, 2, 24622, 1, 0, 0 },
  { 864, 5, 158, 2, 24623, 1, 0, 0 },
  { 878, 5, 153, 2, 24624, 1, 0, 0 },
  { 892, 5, 153, 2, 24625, 1, 0, 0 },
  { 906, 5, 33, 2, 24626, 1, 0, 0 },
  { 920, 5, 33, 2, 24627, 1, 0, 0 },
  { 934, 5, 33, 2, 24628, 1, 0, 0 },
  { 948, 5, 33, 2, 24629, 1, 0, 0 },
  { 817, 5, 33, 2, 24630, 1, 0, 0 },
  { 836, 5, 33, 2, 24631, 1, 0, 0 },
  { 855, 5, 33, 2, 24632, 1, 0, 0 },
  { 869, 5, 33, 2, 24633, 1, 0, 0 },
  { 883, 5, 33, 2, 24634, 1, 0, 0 },
  { 897, 5, 33, 2, 24635, 1, 0, 0 },
  { 911, 5, 33, 2, 24636, 1, 0, 0 },
  { 925, 5, 33, 2, 24637, 1, 0, 0 },
  { 939, 5, 33, 2, 24638, 1, 0, 0 },
  { 953, 5, 33, 2, 24639, 1, 0, 0 },
  { 822, 5, 33, 2, 24640, 1, 0, 0 },
  { 841, 5, 33, 2, 24641, 1, 0, 0 },
  { 257, 40, 147, 3, 385090, 0, 0, 0 },
  { 285, 40, 141, 3, 385092, 0, 0, 0 },
  { 308, 40, 141, 3, 385094, 0, 0, 0 },
  { 331, 40, 135, 3, 385096, 0, 0, 0 },
  { 354, 40, 135, 3, 385098, 0, 0, 0 },
  { 377, 40, 129, 3, 385100, 0, 0, 0 },
  { 395, 40, 129, 3, 385102, 0, 0, 0 },
  { 413, 40, 123, 3, 385104, 0, 0, 0 },
  { 431, 40, 123, 3, 385106, 0, 0, 0 },
  { 449, 40, 117, 3, 385108, 0, 0, 0 },
  { 238, 40, 117, 3, 385110, 0, 0, 0 },
  { 266, 40, 111, 3, 385112, 0, 0, 0 },
  { 294, 40, 111, 3, 385114, 0, 0, 0 },
  { 317, 40, 105, 3, 385116, 0, 0, 0 },
  { 340, 40, 105, 3, 385118, 0, 0, 0 },
  { 363, 40, 99, 3, 385120, 0, 0, 0 },
  { 477, 6, 149, 3, 24643, 8, 0, 0 },
  { 505, 6, 143, 3, 24645, 8, 0, 0 },
  { 528, 6, 143, 3, 24647, 8, 0, 0 },
  { 551, 6, 137, 3, 24649, 8, 0, 0 },
  { 574, 6, 137, 3, 24651, 8, 0, 0 },
  { 597, 6, 131, 3, 24653, 8, 0, 0 },
  { 615, 6, 131, 3, 24655, 8, 0, 0 },
  { 633, 6, 125, 3, 24657, 8, 0, 0 },
  { 651, 6, 125, 3, 24659, 8, 0, 0 },
  { 669, 6, 119, 3, 24661, 8, 0, 0 },
  { 458, 6, 119, 3, 24663, 8, 0, 0 },
  { 486, 6, 113, 3, 24665, 8, 0, 0 },
  { 514, 6, 113, 3, 24667, 8, 0, 0 },
  { 537, 6, 107, 3, 24669, 8, 0, 0 },
  { 560, 6, 107, 3, 24671, 8, 0, 0 },
  { 583, 6, 101, 3, 24673, 8, 0, 0 },
  { 678, 6, 146, 3, 24642, 8, 0, 0 },
  { 687, 6, 140, 3, 24644, 8, 0, 0 },
  { 696, 6, 140, 3, 24646, 8, 0, 0 },
  { 705, 6, 134, 3, 24648, 8, 0, 0 },
  { 714, 6, 134, 3, 24650, 8, 0, 0 },
  { 723, 6, 128, 3, 24652, 8, 0, 0 },
  { 727, 6, 128, 3, 24654, 8, 0, 0 },
  { 731, 6, 122, 3, 24656, 8, 0, 0 },
  { 735, 6, 122, 3, 24658, 8, 0, 0 },
  { 739, 6, 116, 3, 24660, 8, 0, 0 },
  { 673, 6, 116, 3, 24662, 8, 0, 0 },
  { 682, 6, 110, 3, 24664, 8, 0, 0 },
  { 691, 6, 110, 3, 24666, 8, 0, 0 },
  { 700, 6, 104, 3, 24668, 8, 0, 0 },
  { 709, 6, 104, 3, 24670, 8, 0, 0 },
  { 718, 6, 98, 3, 24672, 8, 0, 0 },
  { 752, 36, 6, 5, 376898, 4, 0, 0 },
  { 770, 43, 6, 5, 376902, 4, 0, 0 },
  { 788, 50, 6, 5, 376906, 4, 0, 0 },
  { 796, 57, 6, 5, 376910, 4, 0, 0 },
  { 804, 64, 6, 5, 376914, 4, 0, 0 },
  { 743, 71, 6, 5, 376918, 4, 0, 0 },
  { 765, 78, 6, 5, 376922, 4, 0, 0 },
  { 779, 85, 6, 5, 376926, 4, 0, 0 },
};

extern const MCPhysReg SystemZRegUnitRoots[][2] = {
  { SystemZ::CC },
  { SystemZ::FPC },
  { SystemZ::A0 },
  { SystemZ::A1 },
  { SystemZ::A2 },
  { SystemZ::A3 },
  { SystemZ::A4 },
  { SystemZ::A5 },
  { SystemZ::A6 },
  { SystemZ::A7 },
  { SystemZ::A8 },
  { SystemZ::A9 },
  { SystemZ::A10 },
  { SystemZ::A11 },
  { SystemZ::A12 },
  { SystemZ::A13 },
  { SystemZ::A14 },
  { SystemZ::A15 },
  { SystemZ::C0 },
  { SystemZ::C1 },
  { SystemZ::C2 },
  { SystemZ::C3 },
  { SystemZ::C4 },
  { SystemZ::C5 },
  { SystemZ::C6 },
  { SystemZ::C7 },
  { SystemZ::C8 },
  { SystemZ::C9 },
  { SystemZ::C10 },
  { SystemZ::C11 },
  { SystemZ::C12 },
  { SystemZ::C13 },
  { SystemZ::C14 },
  { SystemZ::C15 },
  { SystemZ::F0H },
  { SystemZ::F1H },
  { SystemZ::F2H },
  { SystemZ::F3H },
  { SystemZ::F4H },
  { SystemZ::F5H },
  { SystemZ::F6H },
  { SystemZ::F7H },
  { SystemZ::F8H },
  { SystemZ::F9H },
  { SystemZ::F10H },
  { SystemZ::F11H },
  { SystemZ::F12H },
  { SystemZ::F13H },
  { SystemZ::F14H },
  { SystemZ::F15H },
  { SystemZ::F16H },
  { SystemZ::F17H },
  { SystemZ::F18H },
  { SystemZ::F19H },
  { SystemZ::F20H },
  { SystemZ::F21H },
  { SystemZ::F22H },
  { SystemZ::F23H },
  { SystemZ::F24H },
  { SystemZ::F25H },
  { SystemZ::F26H },
  { SystemZ::F27H },
  { SystemZ::F28H },
  { SystemZ::F29H },
  { SystemZ::F30H },
  { SystemZ::F31H },
  { SystemZ::R0L },
  { SystemZ::R0H },
  { SystemZ::R1L },
  { SystemZ::R1H },
  { SystemZ::R2L },
  { SystemZ::R2H },
  { SystemZ::R3L },
  { SystemZ::R3H },
  { SystemZ::R4L },
  { SystemZ::R4H },
  { SystemZ::R5L },
  { SystemZ::R5H },
  { SystemZ::R6L },
  { SystemZ::R6H },
  { SystemZ::R7L },
  { SystemZ::R7H },
  { SystemZ::R8L },
  { SystemZ::R8H },
  { SystemZ::R9L },
  { SystemZ::R9H },
  { SystemZ::R10L },
  { SystemZ::R10H },
  { SystemZ::R11L },
  { SystemZ::R11H },
  { SystemZ::R12L },
  { SystemZ::R12H },
  { SystemZ::R13L },
  { SystemZ::R13H },
  { SystemZ::R14L },
  { SystemZ::R14H },
  { SystemZ::R15L },
  { SystemZ::R15H },
};

// Register classes...

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"
#endif
extern const char SystemZRegClassStrings[] = {
  /* 0 */ "AnyRegBit_with_subreg_h64\000"
  /* 26 */ "AnyRegBit_with_subreg_h16\000"
  /* 52 */ "CCR\000"
  /* 56 */ "FPCRegs\000"
  /* 64 */ "GRH32Bit\000"
  /* 73 */ "FP32Bit\000"
  /* 81 */ "AR32Bit\000"
  /* 89 */ "ADDR32Bit\000"
  /* 99 */ "GR32Bit\000"
  /* 107 */ "VR32Bit\000"
  /* 115 */ "GRX32Bit\000"
  /* 124 */ "FP64Bit\000"
  /* 132 */ "CR64Bit\000"
  /* 140 */ "ADDR64Bit\000"
  /* 150 */ "GR64Bit\000"
  /* 158 */ "VR64Bit\000"
  /* 166 */ "FP16Bit\000"
  /* 174 */ "VR16Bit\000"
  /* 182 */ "VF128Bit\000"
  /* 191 */ "FP128Bit\000"
  /* 200 */ "ADDR128Bit\000"
  /* 211 */ "GR128Bit\000"
  /* 220 */ "VR128Bit\000"
  /* 229 */ "AnyRegBit\000"
};
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

using SystemZRegisterClassStorage = MCRegisterClassStorage<24, 455, 400, 54, 17, 20>;
extern const MCRegisterClassStorage<24, 455, 400, 54, 17, 20> SystemZMCRegisterClassStorage = {
  {
    {
      offsetof(SystemZRegisterClassStorage, Regs[0]) - 0 * sizeof(MCRegisterClass),
      offsetof(SystemZRegisterClassStorage, BitSets[0]) - 0 * sizeof(MCRegisterClass),
      174,
      16,
      32,
      17,
      SystemZ::VR16BitRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(SystemZRegisterClassStorage, SubClassMasks[0]) - 0 * sizeof(MCRegisterClass),
      offsetof(SystemZRegisterClassStorage, SuperRegIdxSeqs[14]) - 0 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(SystemZRegisterClassStorage, SuperClasses[0]) - 0 * sizeof(MCRegisterClass),
      0
    },
    {
      offsetof(SystemZRegisterClassStorage, Regs[32]) - 1 * sizeof(MCRegisterClass),
      offsetof(SystemZRegisterClassStorage, BitSets[17]) - 1 * sizeof(MCRegisterClass),
      166,
      0,
      16,
      15,
      SystemZ::FP16BitRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(SystemZRegisterClassStorage, SubClassMasks[3]) - 1 * sizeof(MCRegisterClass),
      offsetof(SystemZRegisterClassStorage, SuperRegIdxSeqs[14]) - 1 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(SystemZRegisterClassStorage, SuperClasses[0]) - 1 * sizeof(MCRegisterClass),
      1
    },
    {
      offsetof(SystemZRegisterClassStorage, Regs[48]) - 2 * sizeof(MCRegisterClass),
      offsetof(SystemZRegisterClassStorage, BitSets[32]) - 2 * sizeof(MCRegisterClass),
      115,
      32,
      32,
      28,
      SystemZ::GRX32BitRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(SystemZRegisterClassStorage, SubClassMasks[6]) - 2 * sizeof(MCRegisterClass),
      offsetof(SystemZRegisterClassStorage, SuperRegIdxSeqs[9]) - 2 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(SystemZRegisterClassStorage, SuperClasses[1]) - 2 * sizeof(MCRegisterClass),
      0
    },
    {
      offsetof(SystemZRegisterClassStorage, Regs[80]) - 3 * sizeof(MCRegisterClass),
      offsetof(SystemZRegisterClassStorage, BitSets[60]) - 3 * sizeof(MCRegisterClass),
      107,
      32,
      32,
      22,
      SystemZ::VR32BitRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(SystemZRegisterClassStorage, SubClassMasks[11]) - 3 * sizeof(MCRegisterClass),
      offsetof(SystemZRegisterClassStorage, SuperRegIdxSeqs[3]) - 3 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(SystemZRegisterClassStorage, SuperClasses[1]) - 3 * sizeof(MCRegisterClass),
      0
    },
    {
      offsetof(SystemZRegisterClassStorage, Regs[112]) - 4 * sizeof(MCRegisterClass),
      offsetof(SystemZRegisterClassStorage, BitSets[82]) - 4 * sizeof(MCRegisterClass),
      81,
      32,
      16,
      3,
      SystemZ::AR32BitRegClassID,
      1, /* CopyCost */
      false, /* Allocatable */
      false,
      offsetof(SystemZRegisterClassStorage, SubClassMasks[14]) - 4 * sizeof(MCRegisterClass),
      offsetof(SystemZRegisterClassStorage, SuperRegIdxSeqs[2]) - 4 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(SystemZRegisterClassStorage, SuperClasses[1]) - 4 * sizeof(MCRegisterClass),
      0
    },
    {
      offsetof(SystemZRegisterClassStorage, Regs[128]) - 5 * sizeof(MCRegisterClass),
      offsetof(SystemZRegisterClassStorage, BitSets[85]) - 5 * sizeof(MCRegisterClass),
      73,
      32,
      16,
      20,
      SystemZ::FP32BitRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(SystemZRegisterClassStorage, SubClassMasks[15]) - 5 * sizeof(MCRegisterClass),
      offsetof(SystemZRegisterClassStorage, SuperRegIdxSeqs[3]) - 5 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(SystemZRegisterClassStorage, SuperClasses[1]) - 5 * sizeof(MCRegisterClass),
      1
    },
    {
      offsetof(SystemZRegisterClassStorage, Regs[144]) - 6 * sizeof(MCRegisterClass),
      offsetof(SystemZRegisterClassStorage, BitSets[105]) - 6 * sizeof(MCRegisterClass),
      99,
      32,
      16,
      28,
      SystemZ::GR32BitRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(SystemZRegisterClassStorage, SubClassMasks[18]) - 6 * sizeof(MCRegisterClass),
      offsetof(SystemZRegisterClassStorage, SuperRegIdxSeqs[6]) - 6 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(SystemZRegisterClassStorage, SuperClasses[2]) - 6 * sizeof(MCRegisterClass),
      1
    },
    {
      offsetof(SystemZRegisterClassStorage, Regs[160]) - 7 * sizeof(MCRegisterClass),
      offsetof(SystemZRegisterClassStorage, BitSets[133]) - 7 * sizeof(MCRegisterClass),
      64,
      32,
      16,
      26,
      SystemZ::GRH32BitRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(SystemZRegisterClassStorage, SubClassMasks[21]) - 7 * sizeof(MCRegisterClass),
      offsetof(SystemZRegisterClassStorage, SuperRegIdxSeqs[3]) - 7 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(SystemZRegisterClassStorage, SuperClasses[3]) - 7 * sizeof(MCRegisterClass),
      1
    },
    {
      offsetof(SystemZRegisterClassStorage, Regs[176]) - 8 * sizeof(MCRegisterClass),
      offsetof(SystemZRegisterClassStorage, BitSets[159]) - 8 * sizeof(MCRegisterClass),
      89,
      32,
      15,
      28,
      SystemZ::ADDR32BitRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(SystemZRegisterClassStorage, SubClassMasks[24]) - 8 * sizeof(MCRegisterClass),
      offsetof(SystemZRegisterClassStorage, SuperRegIdxSeqs[6]) - 8 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(SystemZRegisterClassStorage, SuperClasses[4]) - 8 * sizeof(MCRegisterClass),
      2
    },
    {
      offsetof(SystemZRegisterClassStorage, Regs[191]) - 9 * sizeof(MCRegisterClass),
      offsetof(SystemZRegisterClassStorage, BitSets[187]) - 9 * sizeof(MCRegisterClass),
      52,
      32,
      1,
      1,
      SystemZ::CCRRegClassID,
      255, /* CopyCost */
      false, /* Allocatable */
      false,
      offsetof(SystemZRegisterClassStorage, SubClassMasks[27]) - 9 * sizeof(MCRegisterClass),
      offsetof(SystemZRegisterClassStorage, SuperRegIdxSeqs[2]) - 9 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(SystemZRegisterClassStorage, SuperClasses[6]) - 9 * sizeof(MCRegisterClass),
      0
    },
    {
      offsetof(SystemZRegisterClassStorage, Regs[192]) - 10 * sizeof(MCRegisterClass),
      offsetof(SystemZRegisterClassStorage, BitSets[188]) - 10 * sizeof(MCRegisterClass),
      56,
      32,
      1,
      1,
      SystemZ::FPCRegsRegClassID,
      1, /* CopyCost */
      false, /* Allocatable */
      false,
      offsetof(SystemZRegisterClassStorage, SubClassMasks[28]) - 10 * sizeof(MCRegisterClass),
      offsetof(SystemZRegisterClassStorage, SuperRegIdxSeqs[2]) - 10 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(SystemZRegisterClassStorage, SuperClasses[6]) - 10 * sizeof(MCRegisterClass),
      0
    },
    {
      offsetof(SystemZRegisterClassStorage, Regs[193]) - 11 * sizeof(MCRegisterClass),
      offsetof(SystemZRegisterClassStorage, BitSets[189]) - 11 * sizeof(MCRegisterClass),
      229,
      64,
      48,
      24,
      SystemZ::AnyRegBitRegClassID,
      1, /* CopyCost */
      false, /* Allocatable */
      false,
      offsetof(SystemZRegisterClassStorage, SubClassMasks[29]) - 11 * sizeof(MCRegisterClass),
      offsetof(SystemZRegisterClassStorage, SuperRegIdxSeqs[0]) - 11 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000003),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      true, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(SystemZRegisterClassStorage, SuperClasses[6]) - 11 * sizeof(MCRegisterClass),
      0
    },
    {
      offsetof(SystemZRegisterClassStorage, Regs[241]) - 12 * sizeof(MCRegisterClass),
      offsetof(SystemZRegisterClassStorage, BitSets[213]) - 12 * sizeof(MCRegisterClass),
      26,
      64,
      32,
      11,
      SystemZ::AnyRegBit_with_subreg_h16RegClassID,
      1, /* CopyCost */
      false, /* Allocatable */
      false,
      offsetof(SystemZRegisterClassStorage, SubClassMasks[32]) - 12 * sizeof(MCRegisterClass),
      offsetof(SystemZRegisterClassStorage, SuperRegIdxSeqs[0]) - 12 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000003),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(SystemZRegisterClassStorage, SuperClasses[6]) - 12 * sizeof(MCRegisterClass),
      1
    },
    {
      offsetof(SystemZRegisterClassStorage, Regs[273]) - 13 * sizeof(MCRegisterClass),
      offsetof(SystemZRegisterClassStorage, BitSets[224]) - 13 * sizeof(MCRegisterClass),
      158,
      64,
      32,
      13,
      SystemZ::VR64BitRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(SystemZRegisterClassStorage, SubClassMasks[35]) - 13 * sizeof(MCRegisterClass),
      offsetof(SystemZRegisterClassStorage, SuperRegIdxSeqs[0]) - 13 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(SystemZRegisterClassStorage, SuperClasses[7]) - 13 * sizeof(MCRegisterClass),
      0
    },
    {
      offsetof(SystemZRegisterClassStorage, Regs[305]) - 14 * sizeof(MCRegisterClass),
      offsetof(SystemZRegisterClassStorage, BitSets[237]) - 14 * sizeof(MCRegisterClass),
      0,
      64,
      16,
      7,
      SystemZ::AnyRegBit_with_subreg_h64RegClassID,
      1, /* CopyCost */
      false, /* Allocatable */
      false,
      offsetof(SystemZRegisterClassStorage, SubClassMasks[38]) - 14 * sizeof(MCRegisterClass),
      offsetof(SystemZRegisterClassStorage, SuperRegIdxSeqs[2]) - 14 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000003),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(SystemZRegisterClassStorage, SuperClasses[7]) - 14 * sizeof(MCRegisterClass),
      2
    },
    {
      offsetof(SystemZRegisterClassStorage, Regs[321]) - 15 * sizeof(MCRegisterClass),
      offsetof(SystemZRegisterClassStorage, BitSets[244]) - 15 * sizeof(MCRegisterClass),
      132,
      64,
      16,
      5,
      SystemZ::CR64BitRegClassID,
      1, /* CopyCost */
      false, /* Allocatable */
      false,
      offsetof(SystemZRegisterClassStorage, SubClassMasks[39]) - 15 * sizeof(MCRegisterClass),
      offsetof(SystemZRegisterClassStorage, SuperRegIdxSeqs[2]) - 15 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(SystemZRegisterClassStorage, SuperClasses[9]) - 15 * sizeof(MCRegisterClass),
      0
    },
    {
      offsetof(SystemZRegisterClassStorage, Regs[337]) - 16 * sizeof(MCRegisterClass),
      offsetof(SystemZRegisterClassStorage, BitSets[249]) - 16 * sizeof(MCRegisterClass),
      124,
      64,
      16,
      11,
      SystemZ::FP64BitRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(SystemZRegisterClassStorage, SubClassMasks[40]) - 16 * sizeof(MCRegisterClass),
      offsetof(SystemZRegisterClassStorage, SuperRegIdxSeqs[0]) - 16 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000001),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(SystemZRegisterClassStorage, SuperClasses[9]) - 16 * sizeof(MCRegisterClass),
      3
    },
    {
      offsetof(SystemZRegisterClassStorage, Regs[353]) - 17 * sizeof(MCRegisterClass),
      offsetof(SystemZRegisterClassStorage, BitSets[260]) - 17 * sizeof(MCRegisterClass),
      150,
      64,
      16,
      24,
      SystemZ::GR64BitRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(SystemZRegisterClassStorage, SubClassMasks[43]) - 17 * sizeof(MCRegisterClass),
      offsetof(SystemZRegisterClassStorage, SuperRegIdxSeqs[0]) - 17 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000003),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      true, /* HasDisjunctSubRegs */
      true, /* CoveredBySubRegs */
      offsetof(SystemZRegisterClassStorage, SuperClasses[12]) - 17 * sizeof(MCRegisterClass),
      1
    },
    {
      offsetof(SystemZRegisterClassStorage, Regs[369]) - 18 * sizeof(MCRegisterClass),
      offsetof(SystemZRegisterClassStorage, BitSets[284]) - 18 * sizeof(MCRegisterClass),
      140,
      64,
      15,
      24,
      SystemZ::ADDR64BitRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(SystemZRegisterClassStorage, SubClassMasks[46]) - 18 * sizeof(MCRegisterClass),
      offsetof(SystemZRegisterClassStorage, SuperRegIdxSeqs[0]) - 18 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000003),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      true, /* HasDisjunctSubRegs */
      true, /* CoveredBySubRegs */
      offsetof(SystemZRegisterClassStorage, SuperClasses[13]) - 18 * sizeof(MCRegisterClass),
      2
    },
    {
      offsetof(SystemZRegisterClassStorage, Regs[384]) - 19 * sizeof(MCRegisterClass),
      offsetof(SystemZRegisterClassStorage, BitSets[308]) - 19 * sizeof(MCRegisterClass),
      220,
      128,
      32,
      9,
      SystemZ::VR128BitRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(SystemZRegisterClassStorage, SubClassMasks[49]) - 19 * sizeof(MCRegisterClass),
      offsetof(SystemZRegisterClassStorage, SuperRegIdxSeqs[2]) - 19 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000003),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(SystemZRegisterClassStorage, SuperClasses[15]) - 19 * sizeof(MCRegisterClass),
      0
    },
    {
      offsetof(SystemZRegisterClassStorage, Regs[416]) - 20 * sizeof(MCRegisterClass),
      offsetof(SystemZRegisterClassStorage, BitSets[317]) - 20 * sizeof(MCRegisterClass),
      182,
      128,
      16,
      7,
      SystemZ::VF128BitRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(SystemZRegisterClassStorage, SubClassMasks[50]) - 20 * sizeof(MCRegisterClass),
      offsetof(SystemZRegisterClassStorage, SuperRegIdxSeqs[2]) - 20 * sizeof(MCRegisterClass),
      LaneBitmask(0x0000000000000003),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      false, /* HasDisjunctSubRegs */
      false, /* CoveredBySubRegs */
      offsetof(SystemZRegisterClassStorage, SuperClasses[15]) - 20 * sizeof(MCRegisterClass),
      4
    },
    {
      offsetof(SystemZRegisterClassStorage, Regs[432]) - 21 * sizeof(MCRegisterClass),
      offsetof(SystemZRegisterClassStorage, BitSets[324]) - 21 * sizeof(MCRegisterClass),
      191,
      128,
      8,
      18,
      SystemZ::FP128BitRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(SystemZRegisterClassStorage, SubClassMasks[51]) - 21 * sizeof(MCRegisterClass),
      offsetof(SystemZRegisterClassStorage, SuperRegIdxSeqs[2]) - 21 * sizeof(MCRegisterClass),
      LaneBitmask(0x000000000000000F),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      true, /* HasDisjunctSubRegs */
      true, /* CoveredBySubRegs */
      offsetof(SystemZRegisterClassStorage, SuperClasses[19]) - 21 * sizeof(MCRegisterClass),
      0
    },
    {
      offsetof(SystemZRegisterClassStorage, Regs[440]) - 22 * sizeof(MCRegisterClass),
      offsetof(SystemZRegisterClassStorage, BitSets[342]) - 22 * sizeof(MCRegisterClass),
      211,
      128,
      8,
      29,
      SystemZ::GR128BitRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(SystemZRegisterClassStorage, SubClassMasks[52]) - 22 * sizeof(MCRegisterClass),
      offsetof(SystemZRegisterClassStorage, SuperRegIdxSeqs[2]) - 22 * sizeof(MCRegisterClass),
      LaneBitmask(0x000000000000000F),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      true, /* HasDisjunctSubRegs */
      true, /* CoveredBySubRegs */
      offsetof(SystemZRegisterClassStorage, SuperClasses[19]) - 22 * sizeof(MCRegisterClass),
      0
    },
    {
      offsetof(SystemZRegisterClassStorage, Regs[448]) - 23 * sizeof(MCRegisterClass),
      offsetof(SystemZRegisterClassStorage, BitSets[371]) - 23 * sizeof(MCRegisterClass),
      200,
      128,
      7,
      29,
      SystemZ::ADDR128BitRegClassID,
      1, /* CopyCost */
      true, /* Allocatable */
      false,
      offsetof(SystemZRegisterClassStorage, SubClassMasks[53]) - 23 * sizeof(MCRegisterClass),
      offsetof(SystemZRegisterClassStorage, SuperRegIdxSeqs[2]) - 23 * sizeof(MCRegisterClass),
      LaneBitmask(0x000000000000000F),
      0,
      false,
      0x00, /* TSFlags */
      0, /* SpillStackID */
      true, /* HasDisjunctSubRegs */
      true, /* CoveredBySubRegs */
      offsetof(SystemZRegisterClassStorage, SuperClasses[19]) - 23 * sizeof(MCRegisterClass),
      1
    },
  },
  {
    /* 0 */ SystemZ::F0H, SystemZ::F1H, SystemZ::F2H, SystemZ::F3H, SystemZ::F4H, SystemZ::F5H, SystemZ::F6H, SystemZ::F7H, SystemZ::F16H, SystemZ::F17H, SystemZ::F18H, SystemZ::F19H, SystemZ::F20H, SystemZ::F21H, SystemZ::F22H, SystemZ::F23H, SystemZ::F24H, SystemZ::F25H, SystemZ::F26H, SystemZ::F27H, SystemZ::F28H, SystemZ::F29H, SystemZ::F30H, SystemZ::F31H, SystemZ::F8H, SystemZ::F9H, SystemZ::F10H, SystemZ::F11H, SystemZ::F12H, SystemZ::F13H, SystemZ::F14H, SystemZ::F15H, 
    /* 32 */ SystemZ::F0H, SystemZ::F1H, SystemZ::F2H, SystemZ::F3H, SystemZ::F4H, SystemZ::F5H, SystemZ::F6H, SystemZ::F7H, SystemZ::F8H, SystemZ::F9H, SystemZ::F10H, SystemZ::F11H, SystemZ::F12H, SystemZ::F13H, SystemZ::F14H, SystemZ::F15H, 
    /* 48 */ SystemZ::R0L, SystemZ::R1L, SystemZ::R2L, SystemZ::R3L, SystemZ::R4L, SystemZ::R5L, SystemZ::R0H, SystemZ::R1H, SystemZ::R2H, SystemZ::R3H, SystemZ::R4H, SystemZ::R5H, SystemZ::R15L, SystemZ::R15H, SystemZ::R14L, SystemZ::R14H, SystemZ::R13L, SystemZ::R13H, SystemZ::R12L, SystemZ::R12H, SystemZ::R11L, SystemZ::R11H, SystemZ::R10L, SystemZ::R10H, SystemZ::R9L, SystemZ::R9H, SystemZ::R8L, SystemZ::R8H, SystemZ::R7L, SystemZ::R7H, SystemZ::R6L, SystemZ::R6H, 
    /* 80 */ SystemZ::F0S, SystemZ::F1S, SystemZ::F2S, SystemZ::F3S, SystemZ::F4S, SystemZ::F5S, SystemZ::F6S, SystemZ::F7S, SystemZ::F16S, SystemZ::F17S, SystemZ::F18S, SystemZ::F19S, SystemZ::F20S, SystemZ::F21S, SystemZ::F22S, SystemZ::F23S, SystemZ::F24S, SystemZ::F25S, SystemZ::F26S, SystemZ::F27S, SystemZ::F28S, SystemZ::F29S, SystemZ::F30S, SystemZ::F31S, SystemZ::F8S, SystemZ::F9S, SystemZ::F10S, SystemZ::F11S, SystemZ::F12S, SystemZ::F13S, SystemZ::F14S, SystemZ::F15S, 
    /* 112 */ SystemZ::A0, SystemZ::A1, SystemZ::A2, SystemZ::A3, SystemZ::A4, SystemZ::A5, SystemZ::A6, SystemZ::A7, SystemZ::A8, SystemZ::A9, SystemZ::A10, SystemZ::A11, SystemZ::A12, SystemZ::A13, SystemZ::A14, SystemZ::A15, 
    /* 128 */ SystemZ::F0S, SystemZ::F1S, SystemZ::F2S, SystemZ::F3S, SystemZ::F4S, SystemZ::F5S, SystemZ::F6S, SystemZ::F7S, SystemZ::F8S, SystemZ::F9S, SystemZ::F10S, SystemZ::F11S, SystemZ::F12S, SystemZ::F13S, SystemZ::F14S, SystemZ::F15S, 
    /* 144 */ SystemZ::R0L, SystemZ::R1L, SystemZ::R2L, SystemZ::R3L, SystemZ::R4L, SystemZ::R5L, SystemZ::R15L, SystemZ::R14L, SystemZ::R13L, SystemZ::R12L, SystemZ::R11L, SystemZ::R10L, SystemZ::R9L, SystemZ::R8L, SystemZ::R7L, SystemZ::R6L, 
    /* 160 */ SystemZ::R0H, SystemZ::R1H, SystemZ::R2H, SystemZ::R3H, SystemZ::R4H, SystemZ::R5H, SystemZ::R15H, SystemZ::R14H, SystemZ::R13H, SystemZ::R12H, SystemZ::R11H, SystemZ::R10H, SystemZ::R9H, SystemZ::R8H, SystemZ::R7H, SystemZ::R6H, 
    /* 176 */ SystemZ::R1L, SystemZ::R2L, SystemZ::R3L, SystemZ::R4L, SystemZ::R5L, SystemZ::R15L, SystemZ::R14L, SystemZ::R13L, SystemZ::R12L, SystemZ::R11L, SystemZ::R10L, SystemZ::R9L, SystemZ::R8L, SystemZ::R7L, SystemZ::R6L, 
    /* 191 */ SystemZ::CC, 
    /* 192 */ SystemZ::FPC, 
    /* 193 */ SystemZ::R0D, SystemZ::R1D, SystemZ::R2D, SystemZ::R3D, SystemZ::R4D, SystemZ::R5D, SystemZ::R6D, SystemZ::R7D, SystemZ::R8D, SystemZ::R9D, SystemZ::R10D, SystemZ::R11D, SystemZ::R12D, SystemZ::R13D, SystemZ::R14D, SystemZ::R15D, SystemZ::F0D, SystemZ::F1D, SystemZ::F2D, SystemZ::F3D, SystemZ::F4D, SystemZ::F5D, SystemZ::F6D, SystemZ::F7D, SystemZ::F8D, SystemZ::F9D, SystemZ::F10D, SystemZ::F11D, SystemZ::F12D, SystemZ::F13D, SystemZ::F14D, SystemZ::F15D, SystemZ::V0, SystemZ::V1, SystemZ::V2, SystemZ::V3, SystemZ::V4, SystemZ::V5, SystemZ::V6, SystemZ::V7, SystemZ::V8, SystemZ::V9, SystemZ::V10, SystemZ::V11, SystemZ::V12, SystemZ::V13, SystemZ::V14, SystemZ::V15, 
    /* 241 */ SystemZ::F0D, SystemZ::F1D, SystemZ::F2D, SystemZ::F3D, SystemZ::F4D, SystemZ::F5D, SystemZ::F6D, SystemZ::F7D, SystemZ::F8D, SystemZ::F9D, SystemZ::F10D, SystemZ::F11D, SystemZ::F12D, SystemZ::F13D, SystemZ::F14D, SystemZ::F15D, SystemZ::V0, SystemZ::V1, SystemZ::V2, SystemZ::V3, SystemZ::V4, SystemZ::V5, SystemZ::V6, SystemZ::V7, SystemZ::V8, SystemZ::V9, SystemZ::V10, SystemZ::V11, SystemZ::V12, SystemZ::V13, SystemZ::V14, SystemZ::V15, 
    /* 273 */ SystemZ::F0D, SystemZ::F1D, SystemZ::F2D, SystemZ::F3D, SystemZ::F4D, SystemZ::F5D, SystemZ::F6D, SystemZ::F7D, SystemZ::F16D, SystemZ::F17D, SystemZ::F18D, SystemZ::F19D, SystemZ::F20D, SystemZ::F21D, SystemZ::F22D, SystemZ::F23D, SystemZ::F24D, SystemZ::F25D, SystemZ::F26D, SystemZ::F27D, SystemZ::F28D, SystemZ::F29D, SystemZ::F30D, SystemZ::F31D, SystemZ::F8D, SystemZ::F9D, SystemZ::F10D, SystemZ::F11D, SystemZ::F12D, SystemZ::F13D, SystemZ::F14D, SystemZ::F15D, 
    /* 305 */ SystemZ::V0, SystemZ::V1, SystemZ::V2, SystemZ::V3, SystemZ::V4, SystemZ::V5, SystemZ::V6, SystemZ::V7, SystemZ::V8, SystemZ::V9, SystemZ::V10, SystemZ::V11, SystemZ::V12, SystemZ::V13, SystemZ::V14, SystemZ::V15, 
    /* 321 */ SystemZ::C0, SystemZ::C1, SystemZ::C2, SystemZ::C3, SystemZ::C4, SystemZ::C5, SystemZ::C6, SystemZ::C7, SystemZ::C8, SystemZ::C9, SystemZ::C10, SystemZ::C11, SystemZ::C12, SystemZ::C13, SystemZ::C14, SystemZ::C15, 
    /* 337 */ SystemZ::F0D, SystemZ::F1D, SystemZ::F2D, SystemZ::F3D, SystemZ::F4D, SystemZ::F5D, SystemZ::F6D, SystemZ::F7D, SystemZ::F8D, SystemZ::F9D, SystemZ::F10D, SystemZ::F11D, SystemZ::F12D, SystemZ::F13D, SystemZ::F14D, SystemZ::F15D, 
    /* 353 */ SystemZ::R0D, SystemZ::R1D, SystemZ::R2D, SystemZ::R3D, SystemZ::R4D, SystemZ::R5D, SystemZ::R15D, SystemZ::R14D, SystemZ::R13D, SystemZ::R12D, SystemZ::R11D, SystemZ::R10D, SystemZ::R9D, SystemZ::R8D, SystemZ::R7D, SystemZ::R6D, 
    /* 369 */ SystemZ::R1D, SystemZ::R2D, SystemZ::R3D, SystemZ::R4D, SystemZ::R5D, SystemZ::R15D, SystemZ::R14D, SystemZ::R13D, SystemZ::R12D, SystemZ::R11D, SystemZ::R10D, SystemZ::R9D, SystemZ::R8D, SystemZ::R7D, SystemZ::R6D, 
    /* 384 */ SystemZ::V0, SystemZ::V1, SystemZ::V2, SystemZ::V3, SystemZ::V4, SystemZ::V5, SystemZ::V6, SystemZ::V7, SystemZ::V16, SystemZ::V17, SystemZ::V18, SystemZ::V19, SystemZ::V20, SystemZ::V21, SystemZ::V22, SystemZ::V23, SystemZ::V24, SystemZ::V25, SystemZ::V26, SystemZ::V27, SystemZ::V28, SystemZ::V29, SystemZ::V30, SystemZ::V31, SystemZ::V8, SystemZ::V9, SystemZ::V10, SystemZ::V11, SystemZ::V12, SystemZ::V13, SystemZ::V14, SystemZ::V15, 
    /* 416 */ SystemZ::V0, SystemZ::V1, SystemZ::V2, SystemZ::V3, SystemZ::V4, SystemZ::V5, SystemZ::V6, SystemZ::V7, SystemZ::V8, SystemZ::V9, SystemZ::V10, SystemZ::V11, SystemZ::V12, SystemZ::V13, SystemZ::V14, SystemZ::V15, 
    /* 432 */ SystemZ::F0Q, SystemZ::F1Q, SystemZ::F4Q, SystemZ::F5Q, SystemZ::F8Q, SystemZ::F9Q, SystemZ::F12Q, SystemZ::F13Q, 
    /* 440 */ SystemZ::R0Q, SystemZ::R2Q, SystemZ::R4Q, SystemZ::R12Q, SystemZ::R10Q, SystemZ::R8Q, SystemZ::R6Q, SystemZ::R14Q, 
    /* 448 */ SystemZ::R2Q, SystemZ::R4Q, SystemZ::R12Q, SystemZ::R10Q, SystemZ::R8Q, SystemZ::R6Q, SystemZ::R14Q, 
  },
  {
    /* 0 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xff, 0xff, 0x07, 
    /* 17 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0x07, 
    /* 32 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xff, 0xff, 0x07, 
    /* 60 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xff, 0xff, 0x07, 
    /* 82 */ 0xf8, 0xff, 0x07, 
    /* 85 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0x07, 
    /* 105 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0x07, 
    /* 133 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0x07, 
    /* 159 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x07, 
    /* 187 */ 0x02, 
    /* 188 */ 0x04, 
    /* 189 */ 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0x07, 0x00, 0xf8, 0xff, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0x07, 
    /* 213 */ 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0x07, 0x00, 0xf8, 0xff, 0x07, 
    /* 224 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xff, 0xff, 0x07, 
    /* 237 */ 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0x07, 
    /* 244 */ 0x00, 0x00, 0xf8, 0xff, 0x07, 
    /* 249 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0x07, 
    /* 260 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0x07, 
    /* 284 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x07, 
    /* 308 */ 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xff, 0xff, 0x07, 
    /* 317 */ 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0x07, 
    /* 324 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0x07, 
    /* 342 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0x07, 
    /* 371 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x07, 
  },
  {
    // 0 VR16Bit
    0x00000003, 
    0x00397028, // subreg_h16
    0x00200000, // subreg_lh32_then_subreg_h16
    // 3 FP16Bit
    0x00000002, 
    0x00315020, // subreg_h16
    0x00200000, // subreg_lh32_then_subreg_h16
    // 6 GRX32Bit
    0x000001c4, 
    0x00c60000, // subreg_h32
    0x00c60000, // subreg_l32
    0x00c00000, // subreg_lh32
    0x00c00000, // subreg_ll32
    // 11 VR32Bit
    0x00000028, 
    0x00397000, // subreg_h32
    0x00200000, // subreg_lh32
    // 14 AR32Bit
    0x00000010, 
    // 15 FP32Bit
    0x00000020, 
    0x00315000, // subreg_h32
    0x00200000, // subreg_lh32
    // 18 GR32Bit
    0x00000140, 
    0x00c60000, // subreg_l32
    0x00c00000, // subreg_ll32
    // 21 GRH32Bit
    0x00000080, 
    0x00c60000, // subreg_h32
    0x00c00000, // subreg_lh32
    // 24 ADDR32Bit
    0x00000100, 
    0x00840000, // subreg_l32
    0x00c00000, // subreg_ll32
    // 27 CCR
    0x00000200, 
    // 28 FPCRegs
    0x00000400, 
    // 29 AnyRegBit
    0x00175800, 
    0x00f04000, // subreg_h64
    0x00e00000, // subreg_l64
    // 32 AnyRegBit_with_subreg_h16
    0x00115000, 
    0x00304000, // subreg_h64
    0x00200000, // subreg_l64
    // 35 VR64Bit
    0x00012000, 
    0x00384000, // subreg_h64
    0x00200000, // subreg_l64
    // 38 AnyRegBit_with_subreg_h64
    0x00104000, 
    // 39 CR64Bit
    0x00008000, 
    // 40 FP64Bit
    0x00010000, 
    0x00304000, // subreg_h64
    0x00200000, // subreg_l64
    // 43 GR64Bit
    0x00060000, 
    0x00c00000, // subreg_h64
    0x00c00000, // subreg_l64
    // 46 ADDR64Bit
    0x00040000, 
    0x00800000, // subreg_h64
    0x00c00000, // subreg_l64
    // 49 VR128Bit
    0x00180000, 
    // 50 VF128Bit
    0x00100000, 
    // 51 FP128Bit
    0x00200000, 
    // 52 GR128Bit
    0x00c00000, 
    // 53 ADDR128Bit
    0x00800000, 
  },
  {
  /* 0 */ 3, 5, 0,
  /* 3 */ 2, 6, 0,
  /* 6 */ 4, 7, 0,
  /* 9 */ 2, 4, 6, 7, 0,
  /* 14 */ 1, 8, 0,
  },
  {
    /* 0 VR16Bit */ 
    /* 0 FP16Bit */ SystemZ::VR16BitRegClassID, 
    /* 1 GRX32Bit */ 
    /* 1 VR32Bit */ 
    /* 1 AR32Bit */ 
    /* 1 FP32Bit */ SystemZ::VR32BitRegClassID, 
    /* 2 GR32Bit */ SystemZ::GRX32BitRegClassID, 
    /* 3 GRH32Bit */ SystemZ::GRX32BitRegClassID, 
    /* 4 ADDR32Bit */ SystemZ::GRX32BitRegClassID, SystemZ::GR32BitRegClassID, 
    /* 6 CCR */ 
    /* 6 FPCRegs */ 
    /* 6 AnyRegBit */ 
    /* 6 AnyRegBit_with_subreg_h16 */ SystemZ::AnyRegBitRegClassID, 
    /* 7 VR64Bit */ 
    /* 7 AnyRegBit_with_subreg_h64 */ SystemZ::AnyRegBitRegClassID, SystemZ::AnyRegBit_with_subreg_h16RegClassID, 
    /* 9 CR64Bit */ 
    /* 9 FP64Bit */ SystemZ::AnyRegBitRegClassID, SystemZ::AnyRegBit_with_subreg_h16RegClassID, SystemZ::VR64BitRegClassID, 
    /* 12 GR64Bit */ SystemZ::AnyRegBitRegClassID, 
    /* 13 ADDR64Bit */ SystemZ::AnyRegBitRegClassID, SystemZ::GR64BitRegClassID, 
    /* 15 VR128Bit */ 
    /* 15 VF128Bit */ SystemZ::AnyRegBitRegClassID, SystemZ::AnyRegBit_with_subreg_h16RegClassID, SystemZ::AnyRegBit_with_subreg_h64RegClassID, SystemZ::VR128BitRegClassID, 
    /* 19 FP128Bit */ 
    /* 19 GR128Bit */ 
    /* 19 ADDR128Bit */ SystemZ::GR128BitRegClassID, 
  }
};

const MCRegisterClass &getSystemZMCRegisterClass(unsigned RC) {
  return SystemZMCRegisterClassStorage.Classes[RC];
}

// SystemZ Dwarf<->LLVM register mappings.
extern const MCRegisterInfo::DwarfLLVMRegPair SystemZDwarfFlavour0Dwarf2L[] = {
  { 0U, SystemZ::R0D },
  { 1U, SystemZ::R1D },
  { 2U, SystemZ::R2D },
  { 3U, SystemZ::R3D },
  { 4U, SystemZ::R4D },
  { 5U, SystemZ::R5D },
  { 6U, SystemZ::R6D },
  { 7U, SystemZ::R7D },
  { 8U, SystemZ::R8D },
  { 9U, SystemZ::R9D },
  { 10U, SystemZ::R10D },
  { 11U, SystemZ::R11D },
  { 12U, SystemZ::R12D },
  { 13U, SystemZ::R13D },
  { 14U, SystemZ::R14D },
  { 15U, SystemZ::R15D },
  { 16U, SystemZ::F0D },
  { 17U, SystemZ::F2D },
  { 18U, SystemZ::F4D },
  { 19U, SystemZ::F6D },
  { 20U, SystemZ::F1D },
  { 21U, SystemZ::F3D },
  { 22U, SystemZ::F5D },
  { 23U, SystemZ::F7D },
  { 24U, SystemZ::F8D },
  { 25U, SystemZ::F10D },
  { 26U, SystemZ::F12D },
  { 27U, SystemZ::F14D },
  { 28U, SystemZ::F9D },
  { 29U, SystemZ::F11D },
  { 30U, SystemZ::F13D },
  { 31U, SystemZ::F15D },
  { 32U, SystemZ::C0 },
  { 33U, SystemZ::C1 },
  { 34U, SystemZ::C2 },
  { 35U, SystemZ::C3 },
  { 36U, SystemZ::C4 },
  { 37U, SystemZ::C5 },
  { 38U, SystemZ::C6 },
  { 39U, SystemZ::C7 },
  { 40U, SystemZ::C8 },
  { 41U, SystemZ::C9 },
  { 42U, SystemZ::C10 },
  { 43U, SystemZ::C11 },
  { 44U, SystemZ::C12 },
  { 45U, SystemZ::C13 },
  { 46U, SystemZ::C14 },
  { 47U, SystemZ::C15 },
  { 48U, SystemZ::A0 },
  { 49U, SystemZ::A1 },
  { 50U, SystemZ::A2 },
  { 51U, SystemZ::A3 },
  { 52U, SystemZ::A4 },
  { 53U, SystemZ::A5 },
  { 54U, SystemZ::A6 },
  { 55U, SystemZ::A7 },
  { 56U, SystemZ::A8 },
  { 57U, SystemZ::A9 },
  { 58U, SystemZ::A10 },
  { 59U, SystemZ::A11 },
  { 60U, SystemZ::A12 },
  { 61U, SystemZ::A13 },
  { 62U, SystemZ::A14 },
  { 63U, SystemZ::A15 },
  { 68U, SystemZ::F16D },
  { 69U, SystemZ::F18D },
  { 70U, SystemZ::F20D },
  { 71U, SystemZ::F22D },
  { 72U, SystemZ::F17D },
  { 73U, SystemZ::F19D },
  { 74U, SystemZ::F21D },
  { 75U, SystemZ::F23D },
  { 76U, SystemZ::F24D },
  { 77U, SystemZ::F26D },
  { 78U, SystemZ::F28D },
  { 79U, SystemZ::F30D },
  { 80U, SystemZ::F25D },
  { 81U, SystemZ::F27D },
  { 82U, SystemZ::F29D },
  { 83U, SystemZ::F31D },
};
extern const unsigned SystemZDwarfFlavour0Dwarf2LSize = std::size(SystemZDwarfFlavour0Dwarf2L);

extern const MCRegisterInfo::DwarfLLVMRegPair SystemZEHFlavour0Dwarf2L[] = {
  { 0U, SystemZ::R0D },
  { 1U, SystemZ::R1D },
  { 2U, SystemZ::R2D },
  { 3U, SystemZ::R3D },
  { 4U, SystemZ::R4D },
  { 5U, SystemZ::R5D },
  { 6U, SystemZ::R6D },
  { 7U, SystemZ::R7D },
  { 8U, SystemZ::R8D },
  { 9U, SystemZ::R9D },
  { 10U, SystemZ::R10D },
  { 11U, SystemZ::R11D },
  { 12U, SystemZ::R12D },
  { 13U, SystemZ::R13D },
  { 14U, SystemZ::R14D },
  { 15U, SystemZ::R15D },
  { 16U, SystemZ::F0D },
  { 17U, SystemZ::F2D },
  { 18U, SystemZ::F4D },
  { 19U, SystemZ::F6D },
  { 20U, SystemZ::F1D },
  { 21U, SystemZ::F3D },
  { 22U, SystemZ::F5D },
  { 23U, SystemZ::F7D },
  { 24U, SystemZ::F8D },
  { 25U, SystemZ::F10D },
  { 26U, SystemZ::F12D },
  { 27U, SystemZ::F14D },
  { 28U, SystemZ::F9D },
  { 29U, SystemZ::F11D },
  { 30U, SystemZ::F13D },
  { 31U, SystemZ::F15D },
  { 32U, SystemZ::C0 },
  { 33U, SystemZ::C1 },
  { 34U, SystemZ::C2 },
  { 35U, SystemZ::C3 },
  { 36U, SystemZ::C4 },
  { 37U, SystemZ::C5 },
  { 38U, SystemZ::C6 },
  { 39U, SystemZ::C7 },
  { 40U, SystemZ::C8 },
  { 41U, SystemZ::C9 },
  { 42U, SystemZ::C10 },
  { 43U, SystemZ::C11 },
  { 44U, SystemZ::C12 },
  { 45U, SystemZ::C13 },
  { 46U, SystemZ::C14 },
  { 47U, SystemZ::C15 },
  { 48U, SystemZ::A0 },
  { 49U, SystemZ::A1 },
  { 50U, SystemZ::A2 },
  { 51U, SystemZ::A3 },
  { 52U, SystemZ::A4 },
  { 53U, SystemZ::A5 },
  { 54U, SystemZ::A6 },
  { 55U, SystemZ::A7 },
  { 56U, SystemZ::A8 },
  { 57U, SystemZ::A9 },
  { 58U, SystemZ::A10 },
  { 59U, SystemZ::A11 },
  { 60U, SystemZ::A12 },
  { 61U, SystemZ::A13 },
  { 62U, SystemZ::A14 },
  { 63U, SystemZ::A15 },
  { 68U, SystemZ::F16D },
  { 69U, SystemZ::F18D },
  { 70U, SystemZ::F20D },
  { 71U, SystemZ::F22D },
  { 72U, SystemZ::F17D },
  { 73U, SystemZ::F19D },
  { 74U, SystemZ::F21D },
  { 75U, SystemZ::F23D },
  { 76U, SystemZ::F24D },
  { 77U, SystemZ::F26D },
  { 78U, SystemZ::F28D },
  { 79U, SystemZ::F30D },
  { 80U, SystemZ::F25D },
  { 81U, SystemZ::F27D },
  { 82U, SystemZ::F29D },
  { 83U, SystemZ::F31D },
};
extern const unsigned SystemZEHFlavour0Dwarf2LSize = std::size(SystemZEHFlavour0Dwarf2L);

extern const MCRegisterInfo::DwarfLLVMRegPair SystemZDwarfFlavour0L2Dwarf[] = {
  { SystemZ::A0, 48U },
  { SystemZ::A1, 49U },
  { SystemZ::A2, 50U },
  { SystemZ::A3, 51U },
  { SystemZ::A4, 52U },
  { SystemZ::A5, 53U },
  { SystemZ::A6, 54U },
  { SystemZ::A7, 55U },
  { SystemZ::A8, 56U },
  { SystemZ::A9, 57U },
  { SystemZ::A10, 58U },
  { SystemZ::A11, 59U },
  { SystemZ::A12, 60U },
  { SystemZ::A13, 61U },
  { SystemZ::A14, 62U },
  { SystemZ::A15, 63U },
  { SystemZ::C0, 32U },
  { SystemZ::C1, 33U },
  { SystemZ::C2, 34U },
  { SystemZ::C3, 35U },
  { SystemZ::C4, 36U },
  { SystemZ::C5, 37U },
  { SystemZ::C6, 38U },
  { SystemZ::C7, 39U },
  { SystemZ::C8, 40U },
  { SystemZ::C9, 41U },
  { SystemZ::C10, 42U },
  { SystemZ::C11, 43U },
  { SystemZ::C12, 44U },
  { SystemZ::C13, 45U },
  { SystemZ::C14, 46U },
  { SystemZ::C15, 47U },
  { SystemZ::V0, 16U },
  { SystemZ::V1, 20U },
  { SystemZ::V2, 17U },
  { SystemZ::V3, 21U },
  { SystemZ::V4, 18U },
  { SystemZ::V5, 22U },
  { SystemZ::V6, 19U },
  { SystemZ::V7, 23U },
  { SystemZ::V8, 24U },
  { SystemZ::V9, 28U },
  { SystemZ::V10, 25U },
  { SystemZ::V11, 29U },
  { SystemZ::V12, 26U },
  { SystemZ::V13, 30U },
  { SystemZ::V14, 27U },
  { SystemZ::V15, 31U },
  { SystemZ::V16, 68U },
  { SystemZ::V17, 72U },
  { SystemZ::V18, 69U },
  { SystemZ::V19, 73U },
  { SystemZ::V20, 70U },
  { SystemZ::V21, 74U },
  { SystemZ::V22, 71U },
  { SystemZ::V23, 75U },
  { SystemZ::V24, 76U },
  { SystemZ::V25, 80U },
  { SystemZ::V26, 77U },
  { SystemZ::V27, 81U },
  { SystemZ::V28, 78U },
  { SystemZ::V29, 82U },
  { SystemZ::V30, 79U },
  { SystemZ::V31, 83U },
  { SystemZ::F0D, 16U },
  { SystemZ::F1D, 20U },
  { SystemZ::F2D, 17U },
  { SystemZ::F3D, 21U },
  { SystemZ::F4D, 18U },
  { SystemZ::F5D, 22U },
  { SystemZ::F6D, 19U },
  { SystemZ::F7D, 23U },
  { SystemZ::F8D, 24U },
  { SystemZ::F9D, 28U },
  { SystemZ::F10D, 25U },
  { SystemZ::F11D, 29U },
  { SystemZ::F12D, 26U },
  { SystemZ::F13D, 30U },
  { SystemZ::F14D, 27U },
  { SystemZ::F15D, 31U },
  { SystemZ::F16D, 68U },
  { SystemZ::F17D, 72U },
  { SystemZ::F18D, 69U },
  { SystemZ::F19D, 73U },
  { SystemZ::F20D, 70U },
  { SystemZ::F21D, 74U },
  { SystemZ::F22D, 71U },
  { SystemZ::F23D, 75U },
  { SystemZ::F24D, 76U },
  { SystemZ::F25D, 80U },
  { SystemZ::F26D, 77U },
  { SystemZ::F27D, 81U },
  { SystemZ::F28D, 78U },
  { SystemZ::F29D, 82U },
  { SystemZ::F30D, 79U },
  { SystemZ::F31D, 83U },
  { SystemZ::R0D, 0U },
  { SystemZ::R1D, 1U },
  { SystemZ::R2D, 2U },
  { SystemZ::R3D, 3U },
  { SystemZ::R4D, 4U },
  { SystemZ::R5D, 5U },
  { SystemZ::R6D, 6U },
  { SystemZ::R7D, 7U },
  { SystemZ::R8D, 8U },
  { SystemZ::R9D, 9U },
  { SystemZ::R10D, 10U },
  { SystemZ::R11D, 11U },
  { SystemZ::R12D, 12U },
  { SystemZ::R13D, 13U },
  { SystemZ::R14D, 14U },
  { SystemZ::R15D, 15U },
};
extern const unsigned SystemZDwarfFlavour0L2DwarfSize = std::size(SystemZDwarfFlavour0L2Dwarf);

extern const MCRegisterInfo::DwarfLLVMRegPair SystemZEHFlavour0L2Dwarf[] = {
  { SystemZ::A0, 48U },
  { SystemZ::A1, 49U },
  { SystemZ::A2, 50U },
  { SystemZ::A3, 51U },
  { SystemZ::A4, 52U },
  { SystemZ::A5, 53U },
  { SystemZ::A6, 54U },
  { SystemZ::A7, 55U },
  { SystemZ::A8, 56U },
  { SystemZ::A9, 57U },
  { SystemZ::A10, 58U },
  { SystemZ::A11, 59U },
  { SystemZ::A12, 60U },
  { SystemZ::A13, 61U },
  { SystemZ::A14, 62U },
  { SystemZ::A15, 63U },
  { SystemZ::C0, 32U },
  { SystemZ::C1, 33U },
  { SystemZ::C2, 34U },
  { SystemZ::C3, 35U },
  { SystemZ::C4, 36U },
  { SystemZ::C5, 37U },
  { SystemZ::C6, 38U },
  { SystemZ::C7, 39U },
  { SystemZ::C8, 40U },
  { SystemZ::C9, 41U },
  { SystemZ::C10, 42U },
  { SystemZ::C11, 43U },
  { SystemZ::C12, 44U },
  { SystemZ::C13, 45U },
  { SystemZ::C14, 46U },
  { SystemZ::C15, 47U },
  { SystemZ::V0, 16U },
  { SystemZ::V1, 20U },
  { SystemZ::V2, 17U },
  { SystemZ::V3, 21U },
  { SystemZ::V4, 18U },
  { SystemZ::V5, 22U },
  { SystemZ::V6, 19U },
  { SystemZ::V7, 23U },
  { SystemZ::V8, 24U },
  { SystemZ::V9, 28U },
  { SystemZ::V10, 25U },
  { SystemZ::V11, 29U },
  { SystemZ::V12, 26U },
  { SystemZ::V13, 30U },
  { SystemZ::V14, 27U },
  { SystemZ::V15, 31U },
  { SystemZ::V16, 68U },
  { SystemZ::V17, 72U },
  { SystemZ::V18, 69U },
  { SystemZ::V19, 73U },
  { SystemZ::V20, 70U },
  { SystemZ::V21, 74U },
  { SystemZ::V22, 71U },
  { SystemZ::V23, 75U },
  { SystemZ::V24, 76U },
  { SystemZ::V25, 80U },
  { SystemZ::V26, 77U },
  { SystemZ::V27, 81U },
  { SystemZ::V28, 78U },
  { SystemZ::V29, 82U },
  { SystemZ::V30, 79U },
  { SystemZ::V31, 83U },
  { SystemZ::F0D, 16U },
  { SystemZ::F1D, 20U },
  { SystemZ::F2D, 17U },
  { SystemZ::F3D, 21U },
  { SystemZ::F4D, 18U },
  { SystemZ::F5D, 22U },
  { SystemZ::F6D, 19U },
  { SystemZ::F7D, 23U },
  { SystemZ::F8D, 24U },
  { SystemZ::F9D, 28U },
  { SystemZ::F10D, 25U },
  { SystemZ::F11D, 29U },
  { SystemZ::F12D, 26U },
  { SystemZ::F13D, 30U },
  { SystemZ::F14D, 27U },
  { SystemZ::F15D, 31U },
  { SystemZ::F16D, 68U },
  { SystemZ::F17D, 72U },
  { SystemZ::F18D, 69U },
  { SystemZ::F19D, 73U },
  { SystemZ::F20D, 70U },
  { SystemZ::F21D, 74U },
  { SystemZ::F22D, 71U },
  { SystemZ::F23D, 75U },
  { SystemZ::F24D, 76U },
  { SystemZ::F25D, 80U },
  { SystemZ::F26D, 77U },
  { SystemZ::F27D, 81U },
  { SystemZ::F28D, 78U },
  { SystemZ::F29D, 82U },
  { SystemZ::F30D, 79U },
  { SystemZ::F31D, 83U },
  { SystemZ::R0D, 0U },
  { SystemZ::R1D, 1U },
  { SystemZ::R2D, 2U },
  { SystemZ::R3D, 3U },
  { SystemZ::R4D, 4U },
  { SystemZ::R5D, 5U },
  { SystemZ::R6D, 6U },
  { SystemZ::R7D, 7U },
  { SystemZ::R8D, 8U },
  { SystemZ::R9D, 9U },
  { SystemZ::R10D, 10U },
  { SystemZ::R11D, 11U },
  { SystemZ::R12D, 12U },
  { SystemZ::R13D, 13U },
  { SystemZ::R14D, 14U },
  { SystemZ::R15D, 15U },
};
extern const unsigned SystemZEHFlavour0L2DwarfSize = std::size(SystemZEHFlavour0L2Dwarf);

extern const uint16_t SystemZRegEncodingTable[] = {
  0,
  0,
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
  0,
  1,
  4,
  5,
  8,
  9,
  12,
  13,
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
  0,
  2,
  4,
  6,
  8,
  10,
  12,
  14,
};
static inline void InitSystemZMCRegisterInfo(MCRegisterInfo *RI, unsigned RA, unsigned DwarfFlavour = 0, unsigned EHFlavour = 0, unsigned PC = 0) {
  RI->InitMCRegisterInfo(SystemZRegDesc, 227, RA, PC, SystemZMCRegisterClassStorage.Classes, 24, SystemZRegUnitRoots, 98, SystemZRegDiffLists, SystemZLaneMaskLists, SystemZRegStrings, SystemZRegClassStrings, SystemZSubRegIdxLists, 9,
SystemZRegEncodingTable, nullptr);

  switch (DwarfFlavour) {
  default:
    llvm_unreachable("Unknown DWARF flavour");
  case 0:
    RI->mapDwarfRegsToLLVMRegs(SystemZDwarfFlavour0Dwarf2L, SystemZDwarfFlavour0Dwarf2LSize, false);
    break;
  }
  switch (EHFlavour) {
  default:
    llvm_unreachable("Unknown DWARF flavour");
  case 0:
    RI->mapDwarfRegsToLLVMRegs(SystemZEHFlavour0Dwarf2L, SystemZEHFlavour0Dwarf2LSize, true);
    break;
  }
  switch (DwarfFlavour) {
  default:
    llvm_unreachable("Unknown DWARF flavour");
  case 0:
    RI->mapLLVMRegsToDwarfRegs(SystemZDwarfFlavour0L2Dwarf, SystemZDwarfFlavour0L2DwarfSize, false);
    break;
  }
  switch (EHFlavour) {
  default:
    llvm_unreachable("Unknown DWARF flavour");
  case 0:
    RI->mapLLVMRegsToDwarfRegs(SystemZEHFlavour0L2Dwarf, SystemZEHFlavour0L2DwarfSize, true);
    break;
  }
}


} // namespace llvm_ks
