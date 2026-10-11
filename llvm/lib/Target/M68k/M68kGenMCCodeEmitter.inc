/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Machine Code Emitter                                                       *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

void M68kMCCodeEmitter::getBinaryCodeForInstr(const MCInst &MI,
    SmallVectorImpl<MCFixup> &Fixups,
    APInt &Inst,
    APInt &Scratch,
    const MCSubtargetInfo &STI) const {
  static const unsigned Index[][2] = {
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/0, /*Index*/0},
    {/*NumBits*/16, /*Index*/0},	// ADD16dd
    {/*NumBits*/32, /*Index*/1},	// ADD16df
    {/*NumBits*/32, /*Index*/2},	// ADD16di
    {/*NumBits*/16, /*Index*/3},	// ADD16dj
    {/*NumBits*/32, /*Index*/4},	// ADD16dk
    {/*NumBits*/32, /*Index*/5},	// ADD16dp
    {/*NumBits*/32, /*Index*/6},	// ADD16dq
    {/*NumBits*/16, /*Index*/7},	// ADD16dr
    {/*NumBits*/32, /*Index*/8},	// ADD16fd
    {/*NumBits*/48, /*Index*/9},	// ADD16fi
    {/*NumBits*/16, /*Index*/10},	// ADD16jd
    {/*NumBits*/32, /*Index*/11},	// ADD16ji
    {/*NumBits*/32, /*Index*/12},	// ADD16pd
    {/*NumBits*/48, /*Index*/13},	// ADD16pi
    {/*NumBits*/48, /*Index*/14},	// ADD32ab
    {/*NumBits*/32, /*Index*/15},	// ADD32af
    {/*NumBits*/48, /*Index*/16},	// ADD32ai
    {/*NumBits*/16, /*Index*/17},	// ADD32aj
    {/*NumBits*/32, /*Index*/18},	// ADD32ak
    {/*NumBits*/32, /*Index*/19},	// ADD32ap
    {/*NumBits*/32, /*Index*/20},	// ADD32aq
    {/*NumBits*/16, /*Index*/21},	// ADD32ar
    {/*NumBits*/16, /*Index*/22},	// ADD32dd
    {/*NumBits*/32, /*Index*/23},	// ADD32df
    {/*NumBits*/48, /*Index*/24},	// ADD32di
    {/*NumBits*/16, /*Index*/25},	// ADD32dj
    {/*NumBits*/32, /*Index*/26},	// ADD32dk
    {/*NumBits*/32, /*Index*/27},	// ADD32dp
    {/*NumBits*/32, /*Index*/28},	// ADD32dq
    {/*NumBits*/16, /*Index*/29},	// ADD32dr
    {/*NumBits*/32, /*Index*/30},	// ADD32fd
    {/*NumBits*/64, /*Index*/31},	// ADD32fi
    {/*NumBits*/16, /*Index*/32},	// ADD32jd
    {/*NumBits*/48, /*Index*/33},	// ADD32ji
    {/*NumBits*/32, /*Index*/34},	// ADD32pd
    {/*NumBits*/64, /*Index*/35},	// ADD32pi
    {/*NumBits*/16, /*Index*/36},	// ADD8dd
    {/*NumBits*/32, /*Index*/37},	// ADD8df
    {/*NumBits*/32, /*Index*/38},	// ADD8di
    {/*NumBits*/16, /*Index*/39},	// ADD8dj
    {/*NumBits*/32, /*Index*/40},	// ADD8dk
    {/*NumBits*/32, /*Index*/41},	// ADD8dp
    {/*NumBits*/32, /*Index*/42},	// ADD8dq
    {/*NumBits*/32, /*Index*/43},	// ADD8fd
    {/*NumBits*/48, /*Index*/44},	// ADD8fi
    {/*NumBits*/16, /*Index*/45},	// ADD8jd
    {/*NumBits*/32, /*Index*/46},	// ADD8ji
    {/*NumBits*/32, /*Index*/47},	// ADD8pd
    {/*NumBits*/48, /*Index*/48},	// ADD8pi
    {/*NumBits*/16, /*Index*/49},	// ADDX16dd
    {/*NumBits*/16, /*Index*/50},	// ADDX32dd
    {/*NumBits*/16, /*Index*/51},	// ADDX8dd
    {/*NumBits*/16, /*Index*/52},	// AND16dd
    {/*NumBits*/32, /*Index*/53},	// AND16df
    {/*NumBits*/32, /*Index*/54},	// AND16di
    {/*NumBits*/16, /*Index*/55},	// AND16dj
    {/*NumBits*/32, /*Index*/56},	// AND16dk
    {/*NumBits*/32, /*Index*/57},	// AND16dp
    {/*NumBits*/32, /*Index*/58},	// AND16dq
    {/*NumBits*/16, /*Index*/59},	// AND16dr
    {/*NumBits*/32, /*Index*/60},	// AND16fd
    {/*NumBits*/48, /*Index*/61},	// AND16fi
    {/*NumBits*/16, /*Index*/62},	// AND16jd
    {/*NumBits*/32, /*Index*/63},	// AND16ji
    {/*NumBits*/32, /*Index*/64},	// AND16pd
    {/*NumBits*/48, /*Index*/65},	// AND16pi
    {/*NumBits*/16, /*Index*/66},	// AND32dd
    {/*NumBits*/32, /*Index*/67},	// AND32df
    {/*NumBits*/48, /*Index*/68},	// AND32di
    {/*NumBits*/16, /*Index*/69},	// AND32dj
    {/*NumBits*/32, /*Index*/70},	// AND32dk
    {/*NumBits*/32, /*Index*/71},	// AND32dp
    {/*NumBits*/32, /*Index*/72},	// AND32dq
    {/*NumBits*/16, /*Index*/73},	// AND32dr
    {/*NumBits*/32, /*Index*/74},	// AND32fd
    {/*NumBits*/64, /*Index*/75},	// AND32fi
    {/*NumBits*/16, /*Index*/76},	// AND32jd
    {/*NumBits*/48, /*Index*/77},	// AND32ji
    {/*NumBits*/32, /*Index*/78},	// AND32pd
    {/*NumBits*/64, /*Index*/79},	// AND32pi
    {/*NumBits*/16, /*Index*/80},	// AND8dd
    {/*NumBits*/32, /*Index*/81},	// AND8df
    {/*NumBits*/32, /*Index*/82},	// AND8di
    {/*NumBits*/16, /*Index*/83},	// AND8dj
    {/*NumBits*/32, /*Index*/84},	// AND8dk
    {/*NumBits*/32, /*Index*/85},	// AND8dp
    {/*NumBits*/32, /*Index*/86},	// AND8dq
    {/*NumBits*/32, /*Index*/87},	// AND8fd
    {/*NumBits*/48, /*Index*/88},	// AND8fi
    {/*NumBits*/16, /*Index*/89},	// AND8jd
    {/*NumBits*/32, /*Index*/90},	// AND8ji
    {/*NumBits*/32, /*Index*/91},	// AND8pd
    {/*NumBits*/48, /*Index*/92},	// AND8pi
    {/*NumBits*/16, /*Index*/93},	// ASR16dd
    {/*NumBits*/16, /*Index*/94},	// ASR16di
    {/*NumBits*/16, /*Index*/95},	// ASR32dd
    {/*NumBits*/16, /*Index*/96},	// ASR32di
    {/*NumBits*/16, /*Index*/97},	// ASR8dd
    {/*NumBits*/16, /*Index*/98},	// ASR8di
    {/*NumBits*/16, /*Index*/99},	// BCHG32dd
    {/*NumBits*/32, /*Index*/100},	// BCHG32di
    {/*NumBits*/16, /*Index*/101},	// BCHG8ed
    {/*NumBits*/32, /*Index*/102},	// BCHG8ei
    {/*NumBits*/32, /*Index*/103},	// BCHG8fd
    {/*NumBits*/48, /*Index*/104},	// BCHG8fi
    {/*NumBits*/16, /*Index*/105},	// BCHG8jd
    {/*NumBits*/32, /*Index*/106},	// BCHG8ji
    {/*NumBits*/16, /*Index*/107},	// BCHG8od
    {/*NumBits*/32, /*Index*/108},	// BCHG8oi
    {/*NumBits*/32, /*Index*/109},	// BCHG8pd
    {/*NumBits*/48, /*Index*/110},	// BCHG8pi
    {/*NumBits*/16, /*Index*/111},	// BCLR32dd
    {/*NumBits*/32, /*Index*/112},	// BCLR32di
    {/*NumBits*/16, /*Index*/113},	// BCLR8ed
    {/*NumBits*/32, /*Index*/114},	// BCLR8ei
    {/*NumBits*/32, /*Index*/115},	// BCLR8fd
    {/*NumBits*/48, /*Index*/116},	// BCLR8fi
    {/*NumBits*/16, /*Index*/117},	// BCLR8jd
    {/*NumBits*/32, /*Index*/118},	// BCLR8ji
    {/*NumBits*/16, /*Index*/119},	// BCLR8od
    {/*NumBits*/32, /*Index*/120},	// BCLR8oi
    {/*NumBits*/32, /*Index*/121},	// BCLR8pd
    {/*NumBits*/48, /*Index*/122},	// BCLR8pi
    {/*NumBits*/16, /*Index*/123},	// BKPT
    {/*NumBits*/32, /*Index*/124},	// BRA16
    {/*NumBits*/48, /*Index*/125},	// BRA32
    {/*NumBits*/16, /*Index*/126},	// BRA8
    {/*NumBits*/16, /*Index*/127},	// BSET32dd
    {/*NumBits*/32, /*Index*/128},	// BSET32di
    {/*NumBits*/16, /*Index*/129},	// BSET8ed
    {/*NumBits*/32, /*Index*/130},	// BSET8ei
    {/*NumBits*/32, /*Index*/131},	// BSET8fd
    {/*NumBits*/48, /*Index*/132},	// BSET8fi
    {/*NumBits*/16, /*Index*/133},	// BSET8jd
    {/*NumBits*/32, /*Index*/134},	// BSET8ji
    {/*NumBits*/16, /*Index*/135},	// BSET8od
    {/*NumBits*/32, /*Index*/136},	// BSET8oi
    {/*NumBits*/32, /*Index*/137},	// BSET8pd
    {/*NumBits*/48, /*Index*/138},	// BSET8pi
    {/*NumBits*/32, /*Index*/139},	// BSR16
    {/*NumBits*/48, /*Index*/140},	// BSR32
    {/*NumBits*/16, /*Index*/141},	// BSR8
    {/*NumBits*/16, /*Index*/142},	// BTST32dd
    {/*NumBits*/32, /*Index*/143},	// BTST32di
    {/*NumBits*/16, /*Index*/144},	// BTST8ed
    {/*NumBits*/32, /*Index*/145},	// BTST8ei
    {/*NumBits*/32, /*Index*/146},	// BTST8fd
    {/*NumBits*/48, /*Index*/147},	// BTST8fi
    {/*NumBits*/16, /*Index*/148},	// BTST8jd
    {/*NumBits*/32, /*Index*/149},	// BTST8ji
    {/*NumBits*/32, /*Index*/150},	// BTST8kd
    {/*NumBits*/48, /*Index*/151},	// BTST8ki
    {/*NumBits*/16, /*Index*/152},	// BTST8od
    {/*NumBits*/32, /*Index*/153},	// BTST8oi
    {/*NumBits*/32, /*Index*/154},	// BTST8pd
    {/*NumBits*/48, /*Index*/155},	// BTST8pi
    {/*NumBits*/32, /*Index*/156},	// BTST8qd
    {/*NumBits*/48, /*Index*/157},	// BTST8qi
    {/*NumBits*/32, /*Index*/158},	// Bcc16
    {/*NumBits*/48, /*Index*/159},	// Bcc32
    {/*NumBits*/16, /*Index*/160},	// Bcc8
    {/*NumBits*/32, /*Index*/161},	// Bcs16
    {/*NumBits*/48, /*Index*/162},	// Bcs32
    {/*NumBits*/16, /*Index*/163},	// Bcs8
    {/*NumBits*/32, /*Index*/164},	// Beq16
    {/*NumBits*/48, /*Index*/165},	// Beq32
    {/*NumBits*/16, /*Index*/166},	// Beq8
    {/*NumBits*/32, /*Index*/167},	// Bge16
    {/*NumBits*/48, /*Index*/168},	// Bge32
    {/*NumBits*/16, /*Index*/169},	// Bge8
    {/*NumBits*/32, /*Index*/170},	// Bgt16
    {/*NumBits*/48, /*Index*/171},	// Bgt32
    {/*NumBits*/16, /*Index*/172},	// Bgt8
    {/*NumBits*/32, /*Index*/173},	// Bhi16
    {/*NumBits*/48, /*Index*/174},	// Bhi32
    {/*NumBits*/16, /*Index*/175},	// Bhi8
    {/*NumBits*/32, /*Index*/176},	// Ble16
    {/*NumBits*/48, /*Index*/177},	// Ble32
    {/*NumBits*/16, /*Index*/178},	// Ble8
    {/*NumBits*/32, /*Index*/179},	// Bls16
    {/*NumBits*/48, /*Index*/180},	// Bls32
    {/*NumBits*/16, /*Index*/181},	// Bls8
    {/*NumBits*/32, /*Index*/182},	// Blt16
    {/*NumBits*/48, /*Index*/183},	// Blt32
    {/*NumBits*/16, /*Index*/184},	// Blt8
    {/*NumBits*/32, /*Index*/185},	// Bmi16
    {/*NumBits*/48, /*Index*/186},	// Bmi32
    {/*NumBits*/16, /*Index*/187},	// Bmi8
    {/*NumBits*/32, /*Index*/188},	// Bne16
    {/*NumBits*/48, /*Index*/189},	// Bne32
    {/*NumBits*/16, /*Index*/190},	// Bne8
    {/*NumBits*/32, /*Index*/191},	// Bpl16
    {/*NumBits*/48, /*Index*/192},	// Bpl32
    {/*NumBits*/16, /*Index*/193},	// Bpl8
    {/*NumBits*/32, /*Index*/194},	// Bvc16
    {/*NumBits*/48, /*Index*/195},	// Bvc32
    {/*NumBits*/16, /*Index*/196},	// Bvc8
    {/*NumBits*/32, /*Index*/197},	// Bvs16
    {/*NumBits*/48, /*Index*/198},	// Bvs32
    {/*NumBits*/16, /*Index*/199},	// Bvs8
    {/*NumBits*/48, /*Index*/200},	// CALLb
    {/*NumBits*/32, /*Index*/201},	// CALLf
    {/*NumBits*/16, /*Index*/202},	// CALLj
    {/*NumBits*/32, /*Index*/203},	// CALLk
    {/*NumBits*/64, /*Index*/204},	// CALLl
    {/*NumBits*/32, /*Index*/205},	// CALLp
    {/*NumBits*/32, /*Index*/206},	// CALLq
    {/*NumBits*/64, /*Index*/207},	// CASAL16
    {/*NumBits*/64, /*Index*/208},	// CASAL32
    {/*NumBits*/64, /*Index*/209},	// CASAL8
    {/*NumBits*/32, /*Index*/210},	// CASARI16
    {/*NumBits*/32, /*Index*/211},	// CASARI32
    {/*NumBits*/32, /*Index*/212},	// CASARI8
    {/*NumBits*/48, /*Index*/213},	// CASARID16
    {/*NumBits*/48, /*Index*/214},	// CASARID32
    {/*NumBits*/48, /*Index*/215},	// CASARID8
    {/*NumBits*/48, /*Index*/216},	// CASARII16
    {/*NumBits*/48, /*Index*/217},	// CASARII32
    {/*NumBits*/48, /*Index*/218},	// CASARII8
    {/*NumBits*/64, /*Index*/219},	// CMP16bi
    {/*NumBits*/32, /*Index*/220},	// CMP16df
    {/*NumBits*/32, /*Index*/221},	// CMP16di
    {/*NumBits*/16, /*Index*/222},	// CMP16dj
    {/*NumBits*/32, /*Index*/223},	// CMP16dk
    {/*NumBits*/32, /*Index*/224},	// CMP16dp
    {/*NumBits*/32, /*Index*/225},	// CMP16dq
    {/*NumBits*/16, /*Index*/226},	// CMP16dr
    {/*NumBits*/48, /*Index*/227},	// CMP16fi
    {/*NumBits*/32, /*Index*/228},	// CMP16ji
    {/*NumBits*/48, /*Index*/229},	// CMP16ki
    {/*NumBits*/48, /*Index*/230},	// CMP16pi
    {/*NumBits*/48, /*Index*/231},	// CMP16qi
    {/*NumBits*/80, /*Index*/232},	// CMP32bi
    {/*NumBits*/32, /*Index*/234},	// CMP32df
    {/*NumBits*/48, /*Index*/235},	// CMP32di
    {/*NumBits*/16, /*Index*/236},	// CMP32dj
    {/*NumBits*/32, /*Index*/237},	// CMP32dk
    {/*NumBits*/32, /*Index*/238},	// CMP32dp
    {/*NumBits*/32, /*Index*/239},	// CMP32dq
    {/*NumBits*/16, /*Index*/240},	// CMP32dr
    {/*NumBits*/64, /*Index*/241},	// CMP32fi
    {/*NumBits*/48, /*Index*/242},	// CMP32ji
    {/*NumBits*/64, /*Index*/243},	// CMP32ki
    {/*NumBits*/64, /*Index*/244},	// CMP32pi
    {/*NumBits*/64, /*Index*/245},	// CMP32qi
    {/*NumBits*/64, /*Index*/246},	// CMP8bi
    {/*NumBits*/16, /*Index*/247},	// CMP8dd
    {/*NumBits*/32, /*Index*/248},	// CMP8df
    {/*NumBits*/32, /*Index*/249},	// CMP8di
    {/*NumBits*/16, /*Index*/250},	// CMP8dj
    {/*NumBits*/32, /*Index*/251},	// CMP8dk
    {/*NumBits*/32, /*Index*/252},	// CMP8dp
    {/*NumBits*/32, /*Index*/253},	// CMP8dq
    {/*NumBits*/48, /*Index*/254},	// CMP8fi
    {/*NumBits*/32, /*Index*/255},	// CMP8ji
    {/*NumBits*/48, /*Index*/256},	// CMP8ki
    {/*NumBits*/48, /*Index*/257},	// CMP8pi
    {/*NumBits*/48, /*Index*/258},	// CMP8qi
    {/*NumBits*/16, /*Index*/259},	// EXT16
    {/*NumBits*/16, /*Index*/260},	// EXT32
    {/*NumBits*/32, /*Index*/261},	// FABS32fp_fp
    {/*NumBits*/32, /*Index*/262},	// FABS64fp_fp
    {/*NumBits*/32, /*Index*/263},	// FABS80fp_fp
    {/*NumBits*/32, /*Index*/264},	// FADD32fp_fp
    {/*NumBits*/32, /*Index*/265},	// FADD64fp_fp
    {/*NumBits*/32, /*Index*/266},	// FADD80fp_fp
    {/*NumBits*/32, /*Index*/267},	// FDABS32fp_fp
    {/*NumBits*/32, /*Index*/268},	// FDABS64fp_fp
    {/*NumBits*/32, /*Index*/269},	// FDABS80fp_fp
    {/*NumBits*/32, /*Index*/270},	// FDADD32fp_fp
    {/*NumBits*/32, /*Index*/271},	// FDADD64fp_fp
    {/*NumBits*/32, /*Index*/272},	// FDADD80fp_fp
    {/*NumBits*/32, /*Index*/273},	// FDDIV32fp_fp
    {/*NumBits*/32, /*Index*/274},	// FDDIV64fp_fp
    {/*NumBits*/32, /*Index*/275},	// FDDIV80fp_fp
    {/*NumBits*/32, /*Index*/276},	// FDIV32fp_fp
    {/*NumBits*/32, /*Index*/277},	// FDIV64fp_fp
    {/*NumBits*/32, /*Index*/278},	// FDIV80fp_fp
    {/*NumBits*/32, /*Index*/279},	// FDMOV32fp_fp
    {/*NumBits*/32, /*Index*/280},	// FDMOV64fp_fp
    {/*NumBits*/32, /*Index*/281},	// FDMOV80fp_fp
    {/*NumBits*/32, /*Index*/282},	// FDMUL32fp_fp
    {/*NumBits*/32, /*Index*/283},	// FDMUL64fp_fp
    {/*NumBits*/32, /*Index*/284},	// FDMUL80fp_fp
    {/*NumBits*/32, /*Index*/285},	// FDNEG32fp_fp
    {/*NumBits*/32, /*Index*/286},	// FDNEG64fp_fp
    {/*NumBits*/32, /*Index*/287},	// FDNEG80fp_fp
    {/*NumBits*/32, /*Index*/288},	// FDSUB32fp_fp
    {/*NumBits*/32, /*Index*/289},	// FDSUB64fp_fp
    {/*NumBits*/32, /*Index*/290},	// FDSUB80fp_fp
    {/*NumBits*/32, /*Index*/291},	// FMOV32fp_fp
    {/*NumBits*/32, /*Index*/292},	// FMOV64fp_fp
    {/*NumBits*/32, /*Index*/293},	// FMOV80fp_fp
    {/*NumBits*/32, /*Index*/294},	// FMOVE32a_fpi
    {/*NumBits*/32, /*Index*/295},	// FMOVE32d_fpcs
    {/*NumBits*/32, /*Index*/296},	// FMOVE32fpcs_d
    {/*NumBits*/32, /*Index*/297},	// FMOVE32fpi_a
    {/*NumBits*/32, /*Index*/298},	// FMUL32fp_fp
    {/*NumBits*/32, /*Index*/299},	// FMUL64fp_fp
    {/*NumBits*/32, /*Index*/300},	// FMUL80fp_fp
    {/*NumBits*/32, /*Index*/301},	// FNEG32fp_fp
    {/*NumBits*/32, /*Index*/302},	// FNEG64fp_fp
    {/*NumBits*/32, /*Index*/303},	// FNEG80fp_fp
    {/*NumBits*/32, /*Index*/304},	// FSABS32fp_fp
    {/*NumBits*/32, /*Index*/305},	// FSABS64fp_fp
    {/*NumBits*/32, /*Index*/306},	// FSABS80fp_fp
    {/*NumBits*/32, /*Index*/307},	// FSADD32fp_fp
    {/*NumBits*/32, /*Index*/308},	// FSADD64fp_fp
    {/*NumBits*/32, /*Index*/309},	// FSADD80fp_fp
    {/*NumBits*/32, /*Index*/310},	// FSDIV32fp_fp
    {/*NumBits*/32, /*Index*/311},	// FSDIV64fp_fp
    {/*NumBits*/32, /*Index*/312},	// FSDIV80fp_fp
    {/*NumBits*/32, /*Index*/313},	// FSMOV32fp_fp
    {/*NumBits*/32, /*Index*/314},	// FSMOV64fp_fp
    {/*NumBits*/32, /*Index*/315},	// FSMOV80fp_fp
    {/*NumBits*/32, /*Index*/316},	// FSMUL32fp_fp
    {/*NumBits*/32, /*Index*/317},	// FSMUL64fp_fp
    {/*NumBits*/32, /*Index*/318},	// FSMUL80fp_fp
    {/*NumBits*/32, /*Index*/319},	// FSNEG32fp_fp
    {/*NumBits*/32, /*Index*/320},	// FSNEG64fp_fp
    {/*NumBits*/32, /*Index*/321},	// FSNEG80fp_fp
    {/*NumBits*/32, /*Index*/322},	// FSSUB32fp_fp
    {/*NumBits*/32, /*Index*/323},	// FSSUB64fp_fp
    {/*NumBits*/32, /*Index*/324},	// FSSUB80fp_fp
    {/*NumBits*/32, /*Index*/325},	// FSUB32fp_fp
    {/*NumBits*/32, /*Index*/326},	// FSUB64fp_fp
    {/*NumBits*/32, /*Index*/327},	// FSUB80fp_fp
    {/*NumBits*/16, /*Index*/328},	// ILLEGAL
    {/*NumBits*/16, /*Index*/329},	// JMP32j
    {/*NumBits*/64, /*Index*/330},	// LEA32L
    {/*NumBits*/48, /*Index*/331},	// LEA32b
    {/*NumBits*/32, /*Index*/332},	// LEA32f
    {/*NumBits*/32, /*Index*/333},	// LEA32k
    {/*NumBits*/64, /*Index*/334},	// LEA32l
    {/*NumBits*/32, /*Index*/335},	// LEA32p
    {/*NumBits*/32, /*Index*/336},	// LEA32q
    {/*NumBits*/32, /*Index*/337},	// LINK16
    {/*NumBits*/48, /*Index*/338},	// LINK32
    {/*NumBits*/16, /*Index*/339},	// LSR16dd
    {/*NumBits*/16, /*Index*/340},	// LSR16di
    {/*NumBits*/16, /*Index*/341},	// LSR32dd
    {/*NumBits*/16, /*Index*/342},	// LSR32di
    {/*NumBits*/16, /*Index*/343},	// LSR8dd
    {/*NumBits*/16, /*Index*/344},	// LSR8di
    {/*NumBits*/16, /*Index*/345},	// MOV16aa
    {/*NumBits*/48, /*Index*/346},	// MOV16ab
    {/*NumBits*/48, /*Index*/347},	// MOV16ab_TC
    {/*NumBits*/16, /*Index*/348},	// MOV16ae
    {/*NumBits*/16, /*Index*/349},	// MOV16ae_TC
    {/*NumBits*/32, /*Index*/350},	// MOV16af
    {/*NumBits*/32, /*Index*/351},	// MOV16af_TC
    {/*NumBits*/32, /*Index*/352},	// MOV16ai
    {/*NumBits*/16, /*Index*/353},	// MOV16aj
    {/*NumBits*/16, /*Index*/354},	// MOV16aj_TC
    {/*NumBits*/32, /*Index*/355},	// MOV16ak
    {/*NumBits*/32, /*Index*/356},	// MOV16ak_TC
    {/*NumBits*/16, /*Index*/357},	// MOV16ao
    {/*NumBits*/16, /*Index*/358},	// MOV16ao_TC
    {/*NumBits*/32, /*Index*/359},	// MOV16ap
    {/*NumBits*/32, /*Index*/360},	// MOV16ap_TC
    {/*NumBits*/32, /*Index*/361},	// MOV16aq
    {/*NumBits*/32, /*Index*/362},	// MOV16aq_TC
    {/*NumBits*/16, /*Index*/363},	// MOV16ar
    {/*NumBits*/48, /*Index*/364},	// MOV16ba
    {/*NumBits*/80, /*Index*/365},	// MOV16bb
    {/*NumBits*/48, /*Index*/367},	// MOV16bc
    {/*NumBits*/48, /*Index*/368},	// MOV16bd
    {/*NumBits*/48, /*Index*/369},	// MOV16be
    {/*NumBits*/64, /*Index*/370},	// MOV16bf
    {/*NumBits*/64, /*Index*/371},	// MOV16bi
    {/*NumBits*/48, /*Index*/372},	// MOV16bj
    {/*NumBits*/64, /*Index*/373},	// MOV16bk
    {/*NumBits*/48, /*Index*/374},	// MOV16bo
    {/*NumBits*/64, /*Index*/375},	// MOV16bp
    {/*NumBits*/64, /*Index*/376},	// MOV16bq
    {/*NumBits*/48, /*Index*/377},	// MOV16br
    {/*NumBits*/48, /*Index*/378},	// MOV16bs
    {/*NumBits*/48, /*Index*/379},	// MOV16cb
    {/*NumBits*/16, /*Index*/380},	// MOV16cd
    {/*NumBits*/16, /*Index*/381},	// MOV16ce
    {/*NumBits*/32, /*Index*/382},	// MOV16cf
    {/*NumBits*/16, /*Index*/383},	// MOV16cj
    {/*NumBits*/32, /*Index*/384},	// MOV16ck
    {/*NumBits*/16, /*Index*/385},	// MOV16co
    {/*NumBits*/32, /*Index*/386},	// MOV16cp
    {/*NumBits*/32, /*Index*/387},	// MOV16cq
    {/*NumBits*/48, /*Index*/388},	// MOV16db
    {/*NumBits*/16, /*Index*/389},	// MOV16dc
    {/*NumBits*/16, /*Index*/390},	// MOV16dd
    {/*NumBits*/16, /*Index*/391},	// MOV16de
    {/*NumBits*/32, /*Index*/392},	// MOV16df
    {/*NumBits*/32, /*Index*/393},	// MOV16di
    {/*NumBits*/16, /*Index*/394},	// MOV16dj
    {/*NumBits*/32, /*Index*/395},	// MOV16dk
    {/*NumBits*/16, /*Index*/396},	// MOV16do
    {/*NumBits*/32, /*Index*/397},	// MOV16dp
    {/*NumBits*/32, /*Index*/398},	// MOV16dq
    {/*NumBits*/16, /*Index*/399},	// MOV16ds
    {/*NumBits*/16, /*Index*/400},	// MOV16ea
    {/*NumBits*/48, /*Index*/401},	// MOV16eb
    {/*NumBits*/16, /*Index*/402},	// MOV16ec
    {/*NumBits*/16, /*Index*/403},	// MOV16ed
    {/*NumBits*/16, /*Index*/404},	// MOV16ee
    {/*NumBits*/32, /*Index*/405},	// MOV16ef
    {/*NumBits*/32, /*Index*/406},	// MOV16ei
    {/*NumBits*/16, /*Index*/407},	// MOV16ej
    {/*NumBits*/32, /*Index*/408},	// MOV16ek
    {/*NumBits*/16, /*Index*/409},	// MOV16eo
    {/*NumBits*/32, /*Index*/410},	// MOV16ep
    {/*NumBits*/32, /*Index*/411},	// MOV16eq
    {/*NumBits*/16, /*Index*/412},	// MOV16er
    {/*NumBits*/16, /*Index*/413},	// MOV16es
    {/*NumBits*/32, /*Index*/414},	// MOV16fa
    {/*NumBits*/64, /*Index*/415},	// MOV16fb
    {/*NumBits*/32, /*Index*/416},	// MOV16fc
    {/*NumBits*/32, /*Index*/417},	// MOV16fd
    {/*NumBits*/32, /*Index*/418},	// MOV16fe
    {/*NumBits*/48, /*Index*/419},	// MOV16ff
    {/*NumBits*/48, /*Index*/420},	// MOV16fi
    {/*NumBits*/32, /*Index*/421},	// MOV16fj
    {/*NumBits*/48, /*Index*/422},	// MOV16fk
    {/*NumBits*/32, /*Index*/423},	// MOV16fo
    {/*NumBits*/48, /*Index*/424},	// MOV16fp
    {/*NumBits*/48, /*Index*/425},	// MOV16fq
    {/*NumBits*/32, /*Index*/426},	// MOV16fr
    {/*NumBits*/32, /*Index*/427},	// MOV16fs
    {/*NumBits*/16, /*Index*/428},	// MOV16ja
    {/*NumBits*/48, /*Index*/429},	// MOV16jb
    {/*NumBits*/16, /*Index*/430},	// MOV16jc
    {/*NumBits*/16, /*Index*/431},	// MOV16jd
    {/*NumBits*/16, /*Index*/432},	// MOV16je
    {/*NumBits*/32, /*Index*/433},	// MOV16jf
    {/*NumBits*/32, /*Index*/434},	// MOV16ji
    {/*NumBits*/16, /*Index*/435},	// MOV16jj
    {/*NumBits*/32, /*Index*/436},	// MOV16jk
    {/*NumBits*/16, /*Index*/437},	// MOV16jo
    {/*NumBits*/32, /*Index*/438},	// MOV16jp
    {/*NumBits*/32, /*Index*/439},	// MOV16jq
    {/*NumBits*/16, /*Index*/440},	// MOV16jr
    {/*NumBits*/16, /*Index*/441},	// MOV16js
    {/*NumBits*/16, /*Index*/442},	// MOV16oa
    {/*NumBits*/48, /*Index*/443},	// MOV16ob
    {/*NumBits*/16, /*Index*/444},	// MOV16oc
    {/*NumBits*/16, /*Index*/445},	// MOV16od
    {/*NumBits*/16, /*Index*/446},	// MOV16oe
    {/*NumBits*/32, /*Index*/447},	// MOV16of
    {/*NumBits*/32, /*Index*/448},	// MOV16oi
    {/*NumBits*/16, /*Index*/449},	// MOV16oj
    {/*NumBits*/32, /*Index*/450},	// MOV16ok
    {/*NumBits*/16, /*Index*/451},	// MOV16oo
    {/*NumBits*/32, /*Index*/452},	// MOV16op
    {/*NumBits*/32, /*Index*/453},	// MOV16oq
    {/*NumBits*/16, /*Index*/454},	// MOV16or
    {/*NumBits*/16, /*Index*/455},	// MOV16os
    {/*NumBits*/32, /*Index*/456},	// MOV16pa
    {/*NumBits*/64, /*Index*/457},	// MOV16pb
    {/*NumBits*/32, /*Index*/458},	// MOV16pc
    {/*NumBits*/32, /*Index*/459},	// MOV16pd
    {/*NumBits*/32, /*Index*/460},	// MOV16pe
    {/*NumBits*/48, /*Index*/461},	// MOV16pf
    {/*NumBits*/48, /*Index*/462},	// MOV16pi
    {/*NumBits*/32, /*Index*/463},	// MOV16pj
    {/*NumBits*/48, /*Index*/464},	// MOV16pk
    {/*NumBits*/32, /*Index*/465},	// MOV16po
    {/*NumBits*/48, /*Index*/466},	// MOV16pp
    {/*NumBits*/48, /*Index*/467},	// MOV16pq
    {/*NumBits*/32, /*Index*/468},	// MOV16pr
    {/*NumBits*/32, /*Index*/469},	// MOV16ps
    {/*NumBits*/16, /*Index*/470},	// MOV16ra
    {/*NumBits*/48, /*Index*/471},	// MOV16rb
    {/*NumBits*/48, /*Index*/472},	// MOV16rb_TC
    {/*NumBits*/16, /*Index*/473},	// MOV16re
    {/*NumBits*/16, /*Index*/474},	// MOV16re_TC
    {/*NumBits*/32, /*Index*/475},	// MOV16rf
    {/*NumBits*/32, /*Index*/476},	// MOV16rf_TC
    {/*NumBits*/32, /*Index*/477},	// MOV16ri
    {/*NumBits*/16, /*Index*/478},	// MOV16rj
    {/*NumBits*/16, /*Index*/479},	// MOV16rj_TC
    {/*NumBits*/32, /*Index*/480},	// MOV16rk
    {/*NumBits*/32, /*Index*/481},	// MOV16rk_TC
    {/*NumBits*/16, /*Index*/482},	// MOV16ro
    {/*NumBits*/16, /*Index*/483},	// MOV16ro_TC
    {/*NumBits*/32, /*Index*/484},	// MOV16rp
    {/*NumBits*/32, /*Index*/485},	// MOV16rp_TC
    {/*NumBits*/32, /*Index*/486},	// MOV16rq
    {/*NumBits*/32, /*Index*/487},	// MOV16rq_TC
    {/*NumBits*/16, /*Index*/488},	// MOV16rr
    {/*NumBits*/48, /*Index*/489},	// MOV16sb
    {/*NumBits*/16, /*Index*/490},	// MOV16sd
    {/*NumBits*/16, /*Index*/491},	// MOV16se
    {/*NumBits*/32, /*Index*/492},	// MOV16sf
    {/*NumBits*/16, /*Index*/493},	// MOV16sj
    {/*NumBits*/32, /*Index*/494},	// MOV16sk
    {/*NumBits*/16, /*Index*/495},	// MOV16so
    {/*NumBits*/32, /*Index*/496},	// MOV16sp
    {/*NumBits*/32, /*Index*/497},	// MOV16sq
    {/*NumBits*/16, /*Index*/498},	// MOV32aa
    {/*NumBits*/48, /*Index*/499},	// MOV32ab
    {/*NumBits*/48, /*Index*/500},	// MOV32ab_TC
    {/*NumBits*/16, /*Index*/501},	// MOV32ae
    {/*NumBits*/16, /*Index*/502},	// MOV32ae_TC
    {/*NumBits*/32, /*Index*/503},	// MOV32af
    {/*NumBits*/32, /*Index*/504},	// MOV32af_TC
    {/*NumBits*/48, /*Index*/505},	// MOV32ai
    {/*NumBits*/16, /*Index*/506},	// MOV32aj
    {/*NumBits*/16, /*Index*/507},	// MOV32aj_TC
    {/*NumBits*/32, /*Index*/508},	// MOV32ak
    {/*NumBits*/32, /*Index*/509},	// MOV32ak_TC
    {/*NumBits*/16, /*Index*/510},	// MOV32ao
    {/*NumBits*/16, /*Index*/511},	// MOV32ao_TC
    {/*NumBits*/32, /*Index*/512},	// MOV32ap
    {/*NumBits*/32, /*Index*/513},	// MOV32ap_TC
    {/*NumBits*/32, /*Index*/514},	// MOV32aq
    {/*NumBits*/32, /*Index*/515},	// MOV32aq_TC
    {/*NumBits*/16, /*Index*/516},	// MOV32ar
    {/*NumBits*/48, /*Index*/517},	// MOV32ba
    {/*NumBits*/80, /*Index*/518},	// MOV32bb
    {/*NumBits*/48, /*Index*/520},	// MOV32bd
    {/*NumBits*/48, /*Index*/521},	// MOV32be
    {/*NumBits*/64, /*Index*/522},	// MOV32bf
    {/*NumBits*/80, /*Index*/523},	// MOV32bi
    {/*NumBits*/48, /*Index*/525},	// MOV32bj
    {/*NumBits*/64, /*Index*/526},	// MOV32bk
    {/*NumBits*/48, /*Index*/527},	// MOV32bo
    {/*NumBits*/64, /*Index*/528},	// MOV32bp
    {/*NumBits*/64, /*Index*/529},	// MOV32bq
    {/*NumBits*/48, /*Index*/530},	// MOV32br
    {/*NumBits*/48, /*Index*/531},	// MOV32db
    {/*NumBits*/16, /*Index*/532},	// MOV32dd
    {/*NumBits*/16, /*Index*/533},	// MOV32de
    {/*NumBits*/32, /*Index*/534},	// MOV32df
    {/*NumBits*/48, /*Index*/535},	// MOV32di
    {/*NumBits*/16, /*Index*/536},	// MOV32dj
    {/*NumBits*/32, /*Index*/537},	// MOV32dk
    {/*NumBits*/16, /*Index*/538},	// MOV32do
    {/*NumBits*/32, /*Index*/539},	// MOV32dp
    {/*NumBits*/32, /*Index*/540},	// MOV32dq
    {/*NumBits*/16, /*Index*/541},	// MOV32ea
    {/*NumBits*/48, /*Index*/542},	// MOV32eb
    {/*NumBits*/16, /*Index*/543},	// MOV32ed
    {/*NumBits*/16, /*Index*/544},	// MOV32ee
    {/*NumBits*/32, /*Index*/545},	// MOV32ef
    {/*NumBits*/48, /*Index*/546},	// MOV32ei
    {/*NumBits*/16, /*Index*/547},	// MOV32ej
    {/*NumBits*/32, /*Index*/548},	// MOV32ek
    {/*NumBits*/16, /*Index*/549},	// MOV32eo
    {/*NumBits*/32, /*Index*/550},	// MOV32ep
    {/*NumBits*/32, /*Index*/551},	// MOV32eq
    {/*NumBits*/16, /*Index*/552},	// MOV32er
    {/*NumBits*/32, /*Index*/553},	// MOV32fa
    {/*NumBits*/64, /*Index*/554},	// MOV32fb
    {/*NumBits*/32, /*Index*/555},	// MOV32fd
    {/*NumBits*/32, /*Index*/556},	// MOV32fe
    {/*NumBits*/48, /*Index*/557},	// MOV32ff
    {/*NumBits*/64, /*Index*/558},	// MOV32fi
    {/*NumBits*/32, /*Index*/559},	// MOV32fj
    {/*NumBits*/48, /*Index*/560},	// MOV32fk
    {/*NumBits*/32, /*Index*/561},	// MOV32fo
    {/*NumBits*/48, /*Index*/562},	// MOV32fp
    {/*NumBits*/48, /*Index*/563},	// MOV32fq
    {/*NumBits*/32, /*Index*/564},	// MOV32fr
    {/*NumBits*/16, /*Index*/565},	// MOV32ja
    {/*NumBits*/48, /*Index*/566},	// MOV32jb
    {/*NumBits*/16, /*Index*/567},	// MOV32jd
    {/*NumBits*/16, /*Index*/568},	// MOV32je
    {/*NumBits*/32, /*Index*/569},	// MOV32jf
    {/*NumBits*/48, /*Index*/570},	// MOV32ji
    {/*NumBits*/16, /*Index*/571},	// MOV32jj
    {/*NumBits*/32, /*Index*/572},	// MOV32jk
    {/*NumBits*/16, /*Index*/573},	// MOV32jo
    {/*NumBits*/32, /*Index*/574},	// MOV32jp
    {/*NumBits*/32, /*Index*/575},	// MOV32jq
    {/*NumBits*/16, /*Index*/576},	// MOV32jr
    {/*NumBits*/16, /*Index*/577},	// MOV32oa
    {/*NumBits*/48, /*Index*/578},	// MOV32ob
    {/*NumBits*/16, /*Index*/579},	// MOV32od
    {/*NumBits*/16, /*Index*/580},	// MOV32oe
    {/*NumBits*/32, /*Index*/581},	// MOV32of
    {/*NumBits*/48, /*Index*/582},	// MOV32oi
    {/*NumBits*/16, /*Index*/583},	// MOV32oj
    {/*NumBits*/32, /*Index*/584},	// MOV32ok
    {/*NumBits*/16, /*Index*/585},	// MOV32oo
    {/*NumBits*/32, /*Index*/586},	// MOV32op
    {/*NumBits*/32, /*Index*/587},	// MOV32oq
    {/*NumBits*/16, /*Index*/588},	// MOV32or
    {/*NumBits*/32, /*Index*/589},	// MOV32pa
    {/*NumBits*/64, /*Index*/590},	// MOV32pb
    {/*NumBits*/32, /*Index*/591},	// MOV32pd
    {/*NumBits*/32, /*Index*/592},	// MOV32pe
    {/*NumBits*/48, /*Index*/593},	// MOV32pf
    {/*NumBits*/64, /*Index*/594},	// MOV32pi
    {/*NumBits*/32, /*Index*/595},	// MOV32pj
    {/*NumBits*/48, /*Index*/596},	// MOV32pk
    {/*NumBits*/32, /*Index*/597},	// MOV32po
    {/*NumBits*/48, /*Index*/598},	// MOV32pp
    {/*NumBits*/48, /*Index*/599},	// MOV32pq
    {/*NumBits*/32, /*Index*/600},	// MOV32pr
    {/*NumBits*/16, /*Index*/601},	// MOV32ra
    {/*NumBits*/48, /*Index*/602},	// MOV32rb
    {/*NumBits*/48, /*Index*/603},	// MOV32rb_TC
    {/*NumBits*/16, /*Index*/604},	// MOV32re
    {/*NumBits*/16, /*Index*/605},	// MOV32re_TC
    {/*NumBits*/32, /*Index*/606},	// MOV32rf
    {/*NumBits*/32, /*Index*/607},	// MOV32rf_TC
    {/*NumBits*/48, /*Index*/608},	// MOV32ri
    {/*NumBits*/16, /*Index*/609},	// MOV32rj
    {/*NumBits*/16, /*Index*/610},	// MOV32rj_TC
    {/*NumBits*/32, /*Index*/611},	// MOV32rk
    {/*NumBits*/32, /*Index*/612},	// MOV32rk_TC
    {/*NumBits*/16, /*Index*/613},	// MOV32ro
    {/*NumBits*/16, /*Index*/614},	// MOV32ro_TC
    {/*NumBits*/32, /*Index*/615},	// MOV32rp
    {/*NumBits*/32, /*Index*/616},	// MOV32rp_TC
    {/*NumBits*/32, /*Index*/617},	// MOV32rq
    {/*NumBits*/32, /*Index*/618},	// MOV32rq_TC
    {/*NumBits*/16, /*Index*/619},	// MOV32rr
    {/*NumBits*/80, /*Index*/620},	// MOV8bb
    {/*NumBits*/48, /*Index*/622},	// MOV8bd
    {/*NumBits*/48, /*Index*/623},	// MOV8be
    {/*NumBits*/64, /*Index*/624},	// MOV8bf
    {/*NumBits*/64, /*Index*/625},	// MOV8bi
    {/*NumBits*/48, /*Index*/626},	// MOV8bj
    {/*NumBits*/64, /*Index*/627},	// MOV8bk
    {/*NumBits*/48, /*Index*/628},	// MOV8bo
    {/*NumBits*/64, /*Index*/629},	// MOV8bp
    {/*NumBits*/64, /*Index*/630},	// MOV8bq
    {/*NumBits*/48, /*Index*/631},	// MOV8db
    {/*NumBits*/16, /*Index*/632},	// MOV8dd
    {/*NumBits*/16, /*Index*/633},	// MOV8de
    {/*NumBits*/32, /*Index*/634},	// MOV8df
    {/*NumBits*/32, /*Index*/635},	// MOV8di
    {/*NumBits*/16, /*Index*/636},	// MOV8dj
    {/*NumBits*/32, /*Index*/637},	// MOV8dk
    {/*NumBits*/16, /*Index*/638},	// MOV8do
    {/*NumBits*/32, /*Index*/639},	// MOV8dp
    {/*NumBits*/32, /*Index*/640},	// MOV8dq
    {/*NumBits*/48, /*Index*/641},	// MOV8eb
    {/*NumBits*/16, /*Index*/642},	// MOV8ed
    {/*NumBits*/16, /*Index*/643},	// MOV8ee
    {/*NumBits*/32, /*Index*/644},	// MOV8ef
    {/*NumBits*/32, /*Index*/645},	// MOV8ei
    {/*NumBits*/16, /*Index*/646},	// MOV8ej
    {/*NumBits*/32, /*Index*/647},	// MOV8ek
    {/*NumBits*/16, /*Index*/648},	// MOV8eo
    {/*NumBits*/32, /*Index*/649},	// MOV8ep
    {/*NumBits*/32, /*Index*/650},	// MOV8eq
    {/*NumBits*/64, /*Index*/651},	// MOV8fb
    {/*NumBits*/32, /*Index*/652},	// MOV8fd
    {/*NumBits*/32, /*Index*/653},	// MOV8fe
    {/*NumBits*/48, /*Index*/654},	// MOV8ff
    {/*NumBits*/48, /*Index*/655},	// MOV8fi
    {/*NumBits*/32, /*Index*/656},	// MOV8fj
    {/*NumBits*/48, /*Index*/657},	// MOV8fk
    {/*NumBits*/32, /*Index*/658},	// MOV8fo
    {/*NumBits*/48, /*Index*/659},	// MOV8fp
    {/*NumBits*/48, /*Index*/660},	// MOV8fq
    {/*NumBits*/48, /*Index*/661},	// MOV8jb
    {/*NumBits*/16, /*Index*/662},	// MOV8jd
    {/*NumBits*/16, /*Index*/663},	// MOV8je
    {/*NumBits*/32, /*Index*/664},	// MOV8jf
    {/*NumBits*/32, /*Index*/665},	// MOV8ji
    {/*NumBits*/16, /*Index*/666},	// MOV8jj
    {/*NumBits*/32, /*Index*/667},	// MOV8jk
    {/*NumBits*/16, /*Index*/668},	// MOV8jo
    {/*NumBits*/32, /*Index*/669},	// MOV8jp
    {/*NumBits*/32, /*Index*/670},	// MOV8jq
    {/*NumBits*/48, /*Index*/671},	// MOV8ob
    {/*NumBits*/16, /*Index*/672},	// MOV8od
    {/*NumBits*/16, /*Index*/673},	// MOV8oe
    {/*NumBits*/32, /*Index*/674},	// MOV8of
    {/*NumBits*/32, /*Index*/675},	// MOV8oi
    {/*NumBits*/16, /*Index*/676},	// MOV8oj
    {/*NumBits*/32, /*Index*/677},	// MOV8ok
    {/*NumBits*/16, /*Index*/678},	// MOV8oo
    {/*NumBits*/32, /*Index*/679},	// MOV8op
    {/*NumBits*/32, /*Index*/680},	// MOV8oq
    {/*NumBits*/64, /*Index*/681},	// MOV8pb
    {/*NumBits*/32, /*Index*/682},	// MOV8pd
    {/*NumBits*/32, /*Index*/683},	// MOV8pe
    {/*NumBits*/48, /*Index*/684},	// MOV8pf
    {/*NumBits*/48, /*Index*/685},	// MOV8pi
    {/*NumBits*/32, /*Index*/686},	// MOV8pj
    {/*NumBits*/48, /*Index*/687},	// MOV8pk
    {/*NumBits*/32, /*Index*/688},	// MOV8po
    {/*NumBits*/48, /*Index*/689},	// MOV8pp
    {/*NumBits*/48, /*Index*/690},	// MOV8pq
    {/*NumBits*/64, /*Index*/691},	// MOVM16bm
    {/*NumBits*/32, /*Index*/692},	// MOVM16em
    {/*NumBits*/48, /*Index*/693},	// MOVM16fm
    {/*NumBits*/32, /*Index*/694},	// MOVM16jm
    {/*NumBits*/64, /*Index*/695},	// MOVM16mb
    {/*NumBits*/32, /*Index*/696},	// MOVM16me
    {/*NumBits*/48, /*Index*/697},	// MOVM16mf
    {/*NumBits*/32, /*Index*/698},	// MOVM16mj
    {/*NumBits*/48, /*Index*/699},	// MOVM16mk
    {/*NumBits*/32, /*Index*/700},	// MOVM16mo
    {/*NumBits*/48, /*Index*/701},	// MOVM16mp
    {/*NumBits*/48, /*Index*/702},	// MOVM16mq
    {/*NumBits*/32, /*Index*/703},	// MOVM16om
    {/*NumBits*/48, /*Index*/704},	// MOVM16pm
    {/*NumBits*/64, /*Index*/705},	// MOVM32bm
    {/*NumBits*/32, /*Index*/706},	// MOVM32em
    {/*NumBits*/48, /*Index*/707},	// MOVM32fm
    {/*NumBits*/32, /*Index*/708},	// MOVM32jm
    {/*NumBits*/64, /*Index*/709},	// MOVM32mb
    {/*NumBits*/32, /*Index*/710},	// MOVM32me
    {/*NumBits*/48, /*Index*/711},	// MOVM32mf
    {/*NumBits*/32, /*Index*/712},	// MOVM32mj
    {/*NumBits*/48, /*Index*/713},	// MOVM32mk
    {/*NumBits*/32, /*Index*/714},	// MOVM32mo
    {/*NumBits*/48, /*Index*/715},	// MOVM32mp
    {/*NumBits*/48, /*Index*/716},	// MOVM32mq
    {/*NumBits*/32, /*Index*/717},	// MOVM32om
    {/*NumBits*/48, /*Index*/718},	// MOVM32pm
    {/*NumBits*/16, /*Index*/719},	// MOVQ
    {/*NumBits*/16, /*Index*/720},	// NEG16d
    {/*NumBits*/16, /*Index*/721},	// NEG32d
    {/*NumBits*/16, /*Index*/722},	// NEG8d
    {/*NumBits*/16, /*Index*/723},	// NEGX16d
    {/*NumBits*/16, /*Index*/724},	// NEGX32d
    {/*NumBits*/16, /*Index*/725},	// NEGX8d
    {/*NumBits*/16, /*Index*/726},	// NOP
    {/*NumBits*/16, /*Index*/727},	// NOT16d
    {/*NumBits*/16, /*Index*/728},	// NOT32d
    {/*NumBits*/16, /*Index*/729},	// NOT8d
    {/*NumBits*/16, /*Index*/730},	// OR16dd
    {/*NumBits*/32, /*Index*/731},	// OR16df
    {/*NumBits*/32, /*Index*/732},	// OR16di
    {/*NumBits*/16, /*Index*/733},	// OR16dj
    {/*NumBits*/32, /*Index*/734},	// OR16dk
    {/*NumBits*/32, /*Index*/735},	// OR16dp
    {/*NumBits*/32, /*Index*/736},	// OR16dq
    {/*NumBits*/16, /*Index*/737},	// OR16dr
    {/*NumBits*/32, /*Index*/738},	// OR16fd
    {/*NumBits*/48, /*Index*/739},	// OR16fi
    {/*NumBits*/16, /*Index*/740},	// OR16jd
    {/*NumBits*/32, /*Index*/741},	// OR16ji
    {/*NumBits*/32, /*Index*/742},	// OR16pd
    {/*NumBits*/48, /*Index*/743},	// OR16pi
    {/*NumBits*/16, /*Index*/744},	// OR32dd
    {/*NumBits*/32, /*Index*/745},	// OR32df
    {/*NumBits*/48, /*Index*/746},	// OR32di
    {/*NumBits*/16, /*Index*/747},	// OR32dj
    {/*NumBits*/32, /*Index*/748},	// OR32dk
    {/*NumBits*/32, /*Index*/749},	// OR32dp
    {/*NumBits*/32, /*Index*/750},	// OR32dq
    {/*NumBits*/16, /*Index*/751},	// OR32dr
    {/*NumBits*/32, /*Index*/752},	// OR32fd
    {/*NumBits*/64, /*Index*/753},	// OR32fi
    {/*NumBits*/16, /*Index*/754},	// OR32jd
    {/*NumBits*/48, /*Index*/755},	// OR32ji
    {/*NumBits*/32, /*Index*/756},	// OR32pd
    {/*NumBits*/64, /*Index*/757},	// OR32pi
    {/*NumBits*/16, /*Index*/758},	// OR8dd
    {/*NumBits*/32, /*Index*/759},	// OR8df
    {/*NumBits*/32, /*Index*/760},	// OR8di
    {/*NumBits*/16, /*Index*/761},	// OR8dj
    {/*NumBits*/32, /*Index*/762},	// OR8dk
    {/*NumBits*/32, /*Index*/763},	// OR8dp
    {/*NumBits*/32, /*Index*/764},	// OR8dq
    {/*NumBits*/32, /*Index*/765},	// OR8fd
    {/*NumBits*/48, /*Index*/766},	// OR8fi
    {/*NumBits*/16, /*Index*/767},	// OR8jd
    {/*NumBits*/32, /*Index*/768},	// OR8ji
    {/*NumBits*/32, /*Index*/769},	// OR8pd
    {/*NumBits*/48, /*Index*/770},	// OR8pi
    {/*NumBits*/16, /*Index*/771},	// ROL16dd
    {/*NumBits*/16, /*Index*/772},	// ROL16di
    {/*NumBits*/16, /*Index*/773},	// ROL32dd
    {/*NumBits*/16, /*Index*/774},	// ROL32di
    {/*NumBits*/16, /*Index*/775},	// ROL8dd
    {/*NumBits*/16, /*Index*/776},	// ROL8di
    {/*NumBits*/16, /*Index*/777},	// ROR16dd
    {/*NumBits*/16, /*Index*/778},	// ROR16di
    {/*NumBits*/16, /*Index*/779},	// ROR32dd
    {/*NumBits*/16, /*Index*/780},	// ROR32di
    {/*NumBits*/16, /*Index*/781},	// ROR8dd
    {/*NumBits*/16, /*Index*/782},	// ROR8di
    {/*NumBits*/16, /*Index*/783},	// RTE
    {/*NumBits*/16, /*Index*/784},	// RTS
    {/*NumBits*/16, /*Index*/785},	// SDIVd32d16
    {/*NumBits*/32, /*Index*/786},	// SDIVd32d32
    {/*NumBits*/32, /*Index*/787},	// SDIVd32i16
    {/*NumBits*/16, /*Index*/788},	// SETd8cc
    {/*NumBits*/16, /*Index*/789},	// SETd8cs
    {/*NumBits*/16, /*Index*/790},	// SETd8eq
    {/*NumBits*/16, /*Index*/791},	// SETd8f
    {/*NumBits*/16, /*Index*/792},	// SETd8ge
    {/*NumBits*/16, /*Index*/793},	// SETd8gt
    {/*NumBits*/16, /*Index*/794},	// SETd8hi
    {/*NumBits*/16, /*Index*/795},	// SETd8le
    {/*NumBits*/16, /*Index*/796},	// SETd8ls
    {/*NumBits*/16, /*Index*/797},	// SETd8lt
    {/*NumBits*/16, /*Index*/798},	// SETd8mi
    {/*NumBits*/16, /*Index*/799},	// SETd8ne
    {/*NumBits*/16, /*Index*/800},	// SETd8pl
    {/*NumBits*/16, /*Index*/801},	// SETd8t
    {/*NumBits*/16, /*Index*/802},	// SETd8vc
    {/*NumBits*/16, /*Index*/803},	// SETd8vs
    {/*NumBits*/16, /*Index*/804},	// SETj8cc
    {/*NumBits*/16, /*Index*/805},	// SETj8cs
    {/*NumBits*/16, /*Index*/806},	// SETj8eq
    {/*NumBits*/16, /*Index*/807},	// SETj8f
    {/*NumBits*/16, /*Index*/808},	// SETj8ge
    {/*NumBits*/16, /*Index*/809},	// SETj8gt
    {/*NumBits*/16, /*Index*/810},	// SETj8hi
    {/*NumBits*/16, /*Index*/811},	// SETj8le
    {/*NumBits*/16, /*Index*/812},	// SETj8ls
    {/*NumBits*/16, /*Index*/813},	// SETj8lt
    {/*NumBits*/16, /*Index*/814},	// SETj8mi
    {/*NumBits*/16, /*Index*/815},	// SETj8ne
    {/*NumBits*/16, /*Index*/816},	// SETj8pl
    {/*NumBits*/16, /*Index*/817},	// SETj8t
    {/*NumBits*/16, /*Index*/818},	// SETj8vc
    {/*NumBits*/16, /*Index*/819},	// SETj8vs
    {/*NumBits*/32, /*Index*/820},	// SETp8cc
    {/*NumBits*/32, /*Index*/821},	// SETp8cs
    {/*NumBits*/32, /*Index*/822},	// SETp8eq
    {/*NumBits*/32, /*Index*/823},	// SETp8f
    {/*NumBits*/32, /*Index*/824},	// SETp8ge
    {/*NumBits*/32, /*Index*/825},	// SETp8gt
    {/*NumBits*/32, /*Index*/826},	// SETp8hi
    {/*NumBits*/32, /*Index*/827},	// SETp8le
    {/*NumBits*/32, /*Index*/828},	// SETp8ls
    {/*NumBits*/32, /*Index*/829},	// SETp8lt
    {/*NumBits*/32, /*Index*/830},	// SETp8mi
    {/*NumBits*/32, /*Index*/831},	// SETp8ne
    {/*NumBits*/32, /*Index*/832},	// SETp8pl
    {/*NumBits*/32, /*Index*/833},	// SETp8t
    {/*NumBits*/32, /*Index*/834},	// SETp8vc
    {/*NumBits*/32, /*Index*/835},	// SETp8vs
    {/*NumBits*/16, /*Index*/836},	// SHL16dd
    {/*NumBits*/16, /*Index*/837},	// SHL16di
    {/*NumBits*/16, /*Index*/838},	// SHL32dd
    {/*NumBits*/16, /*Index*/839},	// SHL32di
    {/*NumBits*/16, /*Index*/840},	// SHL8dd
    {/*NumBits*/16, /*Index*/841},	// SHL8di
    {/*NumBits*/16, /*Index*/842},	// SMULd32d16
    {/*NumBits*/32, /*Index*/843},	// SMULd32d32
    {/*NumBits*/32, /*Index*/844},	// SMULd32i16
    {/*NumBits*/16, /*Index*/845},	// SUB16dd
    {/*NumBits*/32, /*Index*/846},	// SUB16df
    {/*NumBits*/32, /*Index*/847},	// SUB16di
    {/*NumBits*/16, /*Index*/848},	// SUB16dj
    {/*NumBits*/32, /*Index*/849},	// SUB16dk
    {/*NumBits*/32, /*Index*/850},	// SUB16dp
    {/*NumBits*/32, /*Index*/851},	// SUB16dq
    {/*NumBits*/16, /*Index*/852},	// SUB16dr
    {/*NumBits*/32, /*Index*/853},	// SUB16fd
    {/*NumBits*/48, /*Index*/854},	// SUB16fi
    {/*NumBits*/16, /*Index*/855},	// SUB16jd
    {/*NumBits*/32, /*Index*/856},	// SUB16ji
    {/*NumBits*/32, /*Index*/857},	// SUB16pd
    {/*NumBits*/48, /*Index*/858},	// SUB16pi
    {/*NumBits*/48, /*Index*/859},	// SUB32ab
    {/*NumBits*/32, /*Index*/860},	// SUB32af
    {/*NumBits*/48, /*Index*/861},	// SUB32ai
    {/*NumBits*/16, /*Index*/862},	// SUB32aj
    {/*NumBits*/32, /*Index*/863},	// SUB32ak
    {/*NumBits*/32, /*Index*/864},	// SUB32ap
    {/*NumBits*/32, /*Index*/865},	// SUB32aq
    {/*NumBits*/16, /*Index*/866},	// SUB32ar
    {/*NumBits*/16, /*Index*/867},	// SUB32dd
    {/*NumBits*/32, /*Index*/868},	// SUB32df
    {/*NumBits*/48, /*Index*/869},	// SUB32di
    {/*NumBits*/16, /*Index*/870},	// SUB32dj
    {/*NumBits*/32, /*Index*/871},	// SUB32dk
    {/*NumBits*/32, /*Index*/872},	// SUB32dp
    {/*NumBits*/32, /*Index*/873},	// SUB32dq
    {/*NumBits*/16, /*Index*/874},	// SUB32dr
    {/*NumBits*/32, /*Index*/875},	// SUB32fd
    {/*NumBits*/64, /*Index*/876},	// SUB32fi
    {/*NumBits*/16, /*Index*/877},	// SUB32jd
    {/*NumBits*/48, /*Index*/878},	// SUB32ji
    {/*NumBits*/32, /*Index*/879},	// SUB32pd
    {/*NumBits*/64, /*Index*/880},	// SUB32pi
    {/*NumBits*/16, /*Index*/881},	// SUB8dd
    {/*NumBits*/32, /*Index*/882},	// SUB8df
    {/*NumBits*/32, /*Index*/883},	// SUB8di
    {/*NumBits*/16, /*Index*/884},	// SUB8dj
    {/*NumBits*/32, /*Index*/885},	// SUB8dk
    {/*NumBits*/32, /*Index*/886},	// SUB8dp
    {/*NumBits*/32, /*Index*/887},	// SUB8dq
    {/*NumBits*/32, /*Index*/888},	// SUB8fd
    {/*NumBits*/48, /*Index*/889},	// SUB8fi
    {/*NumBits*/16, /*Index*/890},	// SUB8jd
    {/*NumBits*/32, /*Index*/891},	// SUB8ji
    {/*NumBits*/32, /*Index*/892},	// SUB8pd
    {/*NumBits*/48, /*Index*/893},	// SUB8pi
    {/*NumBits*/16, /*Index*/894},	// SUBX16dd
    {/*NumBits*/16, /*Index*/895},	// SUBX32dd
    {/*NumBits*/16, /*Index*/896},	// SUBX8dd
    {/*NumBits*/16, /*Index*/897},	// TRAP
    {/*NumBits*/16, /*Index*/898},	// TRAPV
    {/*NumBits*/16, /*Index*/899},	// UDIVd32d16
    {/*NumBits*/32, /*Index*/900},	// UDIVd32d32
    {/*NumBits*/32, /*Index*/901},	// UDIVd32i16
    {/*NumBits*/16, /*Index*/902},	// UMULd32d16
    {/*NumBits*/32, /*Index*/903},	// UMULd32d32
    {/*NumBits*/32, /*Index*/904},	// UMULd32i16
    {/*NumBits*/16, /*Index*/905},	// UNLK
    {/*NumBits*/16, /*Index*/906},	// XOR16dd
    {/*NumBits*/32, /*Index*/907},	// XOR16di
    {/*NumBits*/16, /*Index*/908},	// XOR32dd
    {/*NumBits*/48, /*Index*/909},	// XOR32di
    {/*NumBits*/16, /*Index*/910},	// XOR8dd
    {/*NumBits*/32, /*Index*/911},	// XOR8di
    {/*NumBits*/0, /*Index*/0}
  };
  static const uint64_t InstBits[] = {
    UINT64_C(53312),	// ADD16dd
    UINT64_C(134271088),	// ADD16df
    UINT64_C(53372),	// ADD16di
    UINT64_C(53328),	// ADD16dj
    UINT64_C(134271099),	// ADD16dk
    UINT64_C(53352),	// ADD16dp
    UINT64_C(53370),	// ADD16dq
    UINT64_C(53312),	// ADD16dr
    UINT64_C(134271344),	// ADD16fd
    UINT64_C(8796093023856),	// ADD16fi
    UINT64_C(53584),	// ADD16jd
    UINT64_C(1616),	// ADD16ji
    UINT64_C(53608),	// ADD16pd
    UINT64_C(1640),	// ADD16pi
    UINT64_C(53753),	// ADD32ab
    UINT64_C(134271472),	// ADD32af
    UINT64_C(53756),	// ADD32ai
    UINT64_C(53712),	// ADD32aj
    UINT64_C(134271483),	// ADD32ak
    UINT64_C(53736),	// ADD32ap
    UINT64_C(53754),	// ADD32aq
    UINT64_C(53696),	// ADD32ar
    UINT64_C(53376),	// ADD32dd
    UINT64_C(134271152),	// ADD32df
    UINT64_C(53436),	// ADD32di
    UINT64_C(53392),	// ADD32dj
    UINT64_C(134271163),	// ADD32dk
    UINT64_C(53416),	// ADD32dp
    UINT64_C(53434),	// ADD32dq
    UINT64_C(53376),	// ADD32dr
    UINT64_C(134271408),	// ADD32fd
    UINT64_C(576460752303425200),	// ADD32fi
    UINT64_C(53648),	// ADD32jd
    UINT64_C(1680),	// ADD32ji
    UINT64_C(53672),	// ADD32pd
    UINT64_C(1704),	// ADD32pi
    UINT64_C(53248),	// ADD8dd
    UINT64_C(134271024),	// ADD8df
    UINT64_C(53308),	// ADD8di
    UINT64_C(53264),	// ADD8dj
    UINT64_C(134271035),	// ADD8dk
    UINT64_C(53288),	// ADD8dp
    UINT64_C(53306),	// ADD8dq
    UINT64_C(134271280),	// ADD8fd
    UINT64_C(8796093023792),	// ADD8fi
    UINT64_C(53520),	// ADD8jd
    UINT64_C(1552),	// ADD8ji
    UINT64_C(53544),	// ADD8pd
    UINT64_C(1576),	// ADD8pi
    UINT64_C(53568),	// ADDX16dd
    UINT64_C(53632),	// ADDX32dd
    UINT64_C(53504),	// ADDX8dd
    UINT64_C(49216),	// AND16dd
    UINT64_C(134266992),	// AND16df
    UINT64_C(49276),	// AND16di
    UINT64_C(49232),	// AND16dj
    UINT64_C(134267003),	// AND16dk
    UINT64_C(49256),	// AND16dp
    UINT64_C(49274),	// AND16dq
    UINT64_C(49216),	// AND16dr
    UINT64_C(134267248),	// AND16fd
    UINT64_C(8796093022832),	// AND16fi
    UINT64_C(49488),	// AND16jd
    UINT64_C(592),	// AND16ji
    UINT64_C(49512),	// AND16pd
    UINT64_C(616),	// AND16pi
    UINT64_C(49280),	// AND32dd
    UINT64_C(134267056),	// AND32df
    UINT64_C(49340),	// AND32di
    UINT64_C(49296),	// AND32dj
    UINT64_C(134267067),	// AND32dk
    UINT64_C(49320),	// AND32dp
    UINT64_C(49338),	// AND32dq
    UINT64_C(49280),	// AND32dr
    UINT64_C(134267312),	// AND32fd
    UINT64_C(576460752303424176),	// AND32fi
    UINT64_C(49552),	// AND32jd
    UINT64_C(656),	// AND32ji
    UINT64_C(49576),	// AND32pd
    UINT64_C(680),	// AND32pi
    UINT64_C(49152),	// AND8dd
    UINT64_C(134266928),	// AND8df
    UINT64_C(49212),	// AND8di
    UINT64_C(49168),	// AND8dj
    UINT64_C(134266939),	// AND8dk
    UINT64_C(49192),	// AND8dp
    UINT64_C(49210),	// AND8dq
    UINT64_C(134267184),	// AND8fd
    UINT64_C(8796093022768),	// AND8fi
    UINT64_C(49424),	// AND8jd
    UINT64_C(528),	// AND8ji
    UINT64_C(49448),	// AND8pd
    UINT64_C(552),	// AND8pi
    UINT64_C(57440),	// ASR16dd
    UINT64_C(57408),	// ASR16di
    UINT64_C(57504),	// ASR32dd
    UINT64_C(57472),	// ASR32di
    UINT64_C(57376),	// ASR8dd
    UINT64_C(57344),	// ASR8di
    UINT64_C(320),	// BCHG32dd
    UINT64_C(2112),	// BCHG32di
    UINT64_C(352),	// BCHG8ed
    UINT64_C(2144),	// BCHG8ei
    UINT64_C(134218096),	// BCHG8fd
    UINT64_C(8796093024368),	// BCHG8fi
    UINT64_C(336),	// BCHG8jd
    UINT64_C(2128),	// BCHG8ji
    UINT64_C(344),	// BCHG8od
    UINT64_C(2136),	// BCHG8oi
    UINT64_C(360),	// BCHG8pd
    UINT64_C(2152),	// BCHG8pi
    UINT64_C(384),	// BCLR32dd
    UINT64_C(2176),	// BCLR32di
    UINT64_C(416),	// BCLR8ed
    UINT64_C(2208),	// BCLR8ei
    UINT64_C(134218160),	// BCLR8fd
    UINT64_C(8796093024432),	// BCLR8fi
    UINT64_C(400),	// BCLR8jd
    UINT64_C(2192),	// BCLR8ji
    UINT64_C(408),	// BCLR8od
    UINT64_C(2200),	// BCLR8oi
    UINT64_C(424),	// BCLR8pd
    UINT64_C(2216),	// BCLR8pi
    UINT64_C(18504),	// BKPT
    UINT64_C(24576),	// BRA16
    UINT64_C(24831),	// BRA32
    UINT64_C(24576),	// BRA8
    UINT64_C(448),	// BSET32dd
    UINT64_C(2240),	// BSET32di
    UINT64_C(480),	// BSET8ed
    UINT64_C(2272),	// BSET8ei
    UINT64_C(134218224),	// BSET8fd
    UINT64_C(8796093024496),	// BSET8fi
    UINT64_C(464),	// BSET8jd
    UINT64_C(2256),	// BSET8ji
    UINT64_C(472),	// BSET8od
    UINT64_C(2264),	// BSET8oi
    UINT64_C(488),	// BSET8pd
    UINT64_C(2280),	// BSET8pi
    UINT64_C(24832),	// BSR16
    UINT64_C(25087),	// BSR32
    UINT64_C(24832),	// BSR8
    UINT64_C(256),	// BTST32dd
    UINT64_C(2048),	// BTST32di
    UINT64_C(288),	// BTST8ed
    UINT64_C(2080),	// BTST8ei
    UINT64_C(134218032),	// BTST8fd
    UINT64_C(8796093024304),	// BTST8fi
    UINT64_C(272),	// BTST8jd
    UINT64_C(2064),	// BTST8ji
    UINT64_C(134218043),	// BTST8kd
    UINT64_C(8796093024315),	// BTST8ki
    UINT64_C(280),	// BTST8od
    UINT64_C(2072),	// BTST8oi
    UINT64_C(296),	// BTST8pd
    UINT64_C(2088),	// BTST8pi
    UINT64_C(314),	// BTST8qd
    UINT64_C(2106),	// BTST8qi
    UINT64_C(25600),	// Bcc16
    UINT64_C(25855),	// Bcc32
    UINT64_C(25600),	// Bcc8
    UINT64_C(25856),	// Bcs16
    UINT64_C(26111),	// Bcs32
    UINT64_C(25856),	// Bcs8
    UINT64_C(26368),	// Beq16
    UINT64_C(26623),	// Beq32
    UINT64_C(26368),	// Beq8
    UINT64_C(27648),	// Bge16
    UINT64_C(27903),	// Bge32
    UINT64_C(27648),	// Bge8
    UINT64_C(28160),	// Bgt16
    UINT64_C(28415),	// Bgt32
    UINT64_C(28160),	// Bgt8
    UINT64_C(25088),	// Bhi16
    UINT64_C(25343),	// Bhi32
    UINT64_C(25088),	// Bhi8
    UINT64_C(28416),	// Ble16
    UINT64_C(28671),	// Ble32
    UINT64_C(28416),	// Ble8
    UINT64_C(25344),	// Bls16
    UINT64_C(25599),	// Bls32
    UINT64_C(25344),	// Bls8
    UINT64_C(27904),	// Blt16
    UINT64_C(28159),	// Blt32
    UINT64_C(27904),	// Blt8
    UINT64_C(27392),	// Bmi16
    UINT64_C(27647),	// Bmi32
    UINT64_C(27392),	// Bmi8
    UINT64_C(26112),	// Bne16
    UINT64_C(26367),	// Bne32
    UINT64_C(26112),	// Bne8
    UINT64_C(27136),	// Bpl16
    UINT64_C(27391),	// Bpl32
    UINT64_C(27136),	// Bpl8
    UINT64_C(26624),	// Bvc16
    UINT64_C(26879),	// Bvc32
    UINT64_C(26624),	// Bvc8
    UINT64_C(26880),	// Bvs16
    UINT64_C(27135),	// Bvs32
    UINT64_C(26880),	// Bvs8
    UINT64_C(20153),	// CALLb
    UINT64_C(134237872),	// CALLf
    UINT64_C(20112),	// CALLj
    UINT64_C(134237883),	// CALLk
    UINT64_C(154160827),	// CALLl
    UINT64_C(20136),	// CALLp
    UINT64_C(20154),	// CALLq
    UINT64_C(3321),	// CASAL16
    UINT64_C(3833),	// CASAL32
    UINT64_C(2809),	// CASAL8
    UINT64_C(3280),	// CASARI16
    UINT64_C(3792),	// CASARI32
    UINT64_C(2768),	// CASARI8
    UINT64_C(3304),	// CASARID16
    UINT64_C(3816),	// CASARID32
    UINT64_C(2792),	// CASARID8
    UINT64_C(8796093025520),	// CASARII16
    UINT64_C(8796093026032),	// CASARII32
    UINT64_C(8796093025008),	// CASARII8
    UINT64_C(3193),	// CMP16bi
    UINT64_C(134262896),	// CMP16df
    UINT64_C(3136),	// CMP16di
    UINT64_C(45136),	// CMP16dj
    UINT64_C(134262907),	// CMP16dk
    UINT64_C(45160),	// CMP16dp
    UINT64_C(45178),	// CMP16dq
    UINT64_C(45120),	// CMP16dr
    UINT64_C(8796093025392),	// CMP16fi
    UINT64_C(3152),	// CMP16ji
    UINT64_C(8796093025403),	// CMP16ki
    UINT64_C(3176),	// CMP16pi
    UINT64_C(3194),	// CMP16qi
    UINT64_C(3257),UINT64_C(0),	// CMP32bi
    UINT64_C(134262960),	// CMP32df
    UINT64_C(3200),	// CMP32di
    UINT64_C(45200),	// CMP32dj
    UINT64_C(134262971),	// CMP32dk
    UINT64_C(45224),	// CMP32dp
    UINT64_C(45242),	// CMP32dq
    UINT64_C(45184),	// CMP32dr
    UINT64_C(576460752303426736),	// CMP32fi
    UINT64_C(3216),	// CMP32ji
    UINT64_C(576460752303426747),	// CMP32ki
    UINT64_C(3240),	// CMP32pi
    UINT64_C(3258),	// CMP32qi
    UINT64_C(3129),	// CMP8bi
    UINT64_C(45056),	// CMP8dd
    UINT64_C(134262832),	// CMP8df
    UINT64_C(3072),	// CMP8di
    UINT64_C(45072),	// CMP8dj
    UINT64_C(134262843),	// CMP8dk
    UINT64_C(45096),	// CMP8dp
    UINT64_C(45114),	// CMP8dq
    UINT64_C(8796093025328),	// CMP8fi
    UINT64_C(3088),	// CMP8ji
    UINT64_C(8796093025339),	// CMP8ki
    UINT64_C(3112),	// CMP8pi
    UINT64_C(3130),	// CMP8qi
    UINT64_C(18560),	// EXT16
    UINT64_C(18624),	// EXT32
    UINT64_C(1634816),	// FABS32fp_fp
    UINT64_C(1634816),	// FABS64fp_fp
    UINT64_C(1634816),	// FABS80fp_fp
    UINT64_C(2290176),	// FADD32fp_fp
    UINT64_C(2290176),	// FADD64fp_fp
    UINT64_C(2290176),	// FADD80fp_fp
    UINT64_C(6091264),	// FDABS32fp_fp
    UINT64_C(6091264),	// FDABS64fp_fp
    UINT64_C(6091264),	// FDABS80fp_fp
    UINT64_C(6746624),	// FDADD32fp_fp
    UINT64_C(6746624),	// FDADD64fp_fp
    UINT64_C(6746624),	// FDADD80fp_fp
    UINT64_C(6615552),	// FDDIV32fp_fp
    UINT64_C(6615552),	// FDDIV64fp_fp
    UINT64_C(6615552),	// FDDIV80fp_fp
    UINT64_C(2159104),	// FDIV32fp_fp
    UINT64_C(2159104),	// FDIV64fp_fp
    UINT64_C(2159104),	// FDIV80fp_fp
    UINT64_C(4518400),	// FDMOV32fp_fp
    UINT64_C(4518400),	// FDMOV64fp_fp
    UINT64_C(4518400),	// FDMOV80fp_fp
    UINT64_C(6812160),	// FDMUL32fp_fp
    UINT64_C(6812160),	// FDMUL64fp_fp
    UINT64_C(6812160),	// FDMUL80fp_fp
    UINT64_C(6222336),	// FDNEG32fp_fp
    UINT64_C(6222336),	// FDNEG64fp_fp
    UINT64_C(6222336),	// FDNEG80fp_fp
    UINT64_C(7139840),	// FDSUB32fp_fp
    UINT64_C(7139840),	// FDSUB64fp_fp
    UINT64_C(7139840),	// FDSUB80fp_fp
    UINT64_C(61952),	// FMOV32fp_fp
    UINT64_C(61952),	// FMOV64fp_fp
    UINT64_C(61952),	// FMOV80fp_fp
    UINT64_C(2684416520),	// FMOVE32a_fpi
    UINT64_C(2684416512),	// FMOVE32d_fpcs
    UINT64_C(2147545600),	// FMOVE32fpcs_d
    UINT64_C(2147545608),	// FMOVE32fpi_a
    UINT64_C(2355712),	// FMUL32fp_fp
    UINT64_C(2355712),	// FMUL64fp_fp
    UINT64_C(2355712),	// FMUL80fp_fp
    UINT64_C(1765888),	// FNEG32fp_fp
    UINT64_C(1765888),	// FNEG64fp_fp
    UINT64_C(1765888),	// FNEG80fp_fp
    UINT64_C(5829120),	// FSABS32fp_fp
    UINT64_C(5829120),	// FSABS64fp_fp
    UINT64_C(5829120),	// FSABS80fp_fp
    UINT64_C(6484480),	// FSADD32fp_fp
    UINT64_C(6484480),	// FSADD64fp_fp
    UINT64_C(6484480),	// FSADD80fp_fp
    UINT64_C(6353408),	// FSDIV32fp_fp
    UINT64_C(6353408),	// FSDIV64fp_fp
    UINT64_C(6353408),	// FSDIV80fp_fp
    UINT64_C(4256256),	// FSMOV32fp_fp
    UINT64_C(4256256),	// FSMOV64fp_fp
    UINT64_C(4256256),	// FSMOV80fp_fp
    UINT64_C(6550016),	// FSMUL32fp_fp
    UINT64_C(6550016),	// FSMUL64fp_fp
    UINT64_C(6550016),	// FSMUL80fp_fp
    UINT64_C(5960192),	// FSNEG32fp_fp
    UINT64_C(5960192),	// FSNEG64fp_fp
    UINT64_C(5960192),	// FSNEG80fp_fp
    UINT64_C(6877696),	// FSSUB32fp_fp
    UINT64_C(6877696),	// FSSUB64fp_fp
    UINT64_C(6877696),	// FSSUB80fp_fp
    UINT64_C(2683392),	// FSUB32fp_fp
    UINT64_C(2683392),	// FSUB64fp_fp
    UINT64_C(2683392),	// FSUB80fp_fp
    UINT64_C(19196),	// ILLEGAL
    UINT64_C(20176),	// JMP32j
    UINT64_C(19939835),	// LEA32L
    UINT64_C(16889),	// LEA32b
    UINT64_C(134234608),	// LEA32f
    UINT64_C(134234619),	// LEA32k
    UINT64_C(154157563),	// LEA32l
    UINT64_C(16872),	// LEA32p
    UINT64_C(16890),	// LEA32q
    UINT64_C(20048),	// LINK16
    UINT64_C(18440),	// LINK32
    UINT64_C(57448),	// LSR16dd
    UINT64_C(57416),	// LSR16di
    UINT64_C(57512),	// LSR32dd
    UINT64_C(57480),	// LSR32di
    UINT64_C(57384),	// LSR8dd
    UINT64_C(57352),	// LSR8di
    UINT64_C(12360),	// MOV16aa
    UINT64_C(12409),	// MOV16ab
    UINT64_C(12409),	// MOV16ab_TC
    UINT64_C(12384),	// MOV16ae
    UINT64_C(12384),	// MOV16ae_TC
    UINT64_C(134230128),	// MOV16af
    UINT64_C(134230128),	// MOV16af_TC
    UINT64_C(12412),	// MOV16ai
    UINT64_C(12368),	// MOV16aj
    UINT64_C(12368),	// MOV16aj_TC
    UINT64_C(134230139),	// MOV16ak
    UINT64_C(134230139),	// MOV16ak_TC
    UINT64_C(12376),	// MOV16ao
    UINT64_C(12376),	// MOV16ao_TC
    UINT64_C(12392),	// MOV16ap
    UINT64_C(12392),	// MOV16ap_TC
    UINT64_C(12410),	// MOV16aq
    UINT64_C(12410),	// MOV16aq_TC
    UINT64_C(12352),	// MOV16ar
    UINT64_C(13256),	// MOV16ba
    UINT64_C(13305),UINT64_C(0),	// MOV16bb
    UINT64_C(17145),	// MOV16bc
    UINT64_C(13248),	// MOV16bd
    UINT64_C(13280),	// MOV16be
    UINT64_C(134231024),	// MOV16bf
    UINT64_C(13308),	// MOV16bi
    UINT64_C(13264),	// MOV16bj
    UINT64_C(134231035),	// MOV16bk
    UINT64_C(13272),	// MOV16bo
    UINT64_C(13288),	// MOV16bp
    UINT64_C(13306),	// MOV16bq
    UINT64_C(13248),	// MOV16br
    UINT64_C(16633),	// MOV16bs
    UINT64_C(17657),	// MOV16cb
    UINT64_C(17600),	// MOV16cd
    UINT64_C(17632),	// MOV16ce
    UINT64_C(134235376),	// MOV16cf
    UINT64_C(17616),	// MOV16cj
    UINT64_C(134235387),	// MOV16ck
    UINT64_C(17624),	// MOV16co
    UINT64_C(17640),	// MOV16cp
    UINT64_C(17658),	// MOV16cq
    UINT64_C(12345),	// MOV16db
    UINT64_C(17088),	// MOV16dc
    UINT64_C(12288),	// MOV16dd
    UINT64_C(12320),	// MOV16de
    UINT64_C(134230064),	// MOV16df
    UINT64_C(12348),	// MOV16di
    UINT64_C(12304),	// MOV16dj
    UINT64_C(134230075),	// MOV16dk
    UINT64_C(12312),	// MOV16do
    UINT64_C(12328),	// MOV16dp
    UINT64_C(12346),	// MOV16dq
    UINT64_C(16576),	// MOV16ds
    UINT64_C(12552),	// MOV16ea
    UINT64_C(12601),	// MOV16eb
    UINT64_C(17120),	// MOV16ec
    UINT64_C(12544),	// MOV16ed
    UINT64_C(12576),	// MOV16ee
    UINT64_C(134230320),	// MOV16ef
    UINT64_C(12604),	// MOV16ei
    UINT64_C(12560),	// MOV16ej
    UINT64_C(134230331),	// MOV16ek
    UINT64_C(12568),	// MOV16eo
    UINT64_C(12584),	// MOV16ep
    UINT64_C(12602),	// MOV16eq
    UINT64_C(12544),	// MOV16er
    UINT64_C(16608),	// MOV16es
    UINT64_C(134230408),	// MOV16fa
    UINT64_C(576460752303436217),	// MOV16fb
    UINT64_C(134234864),	// MOV16fc
    UINT64_C(134230400),	// MOV16fd
    UINT64_C(134230432),	// MOV16fe
    UINT64_C(8796227252656),	// MOV16ff
    UINT64_C(8796093034940),	// MOV16fi
    UINT64_C(134230416),	// MOV16fj
    UINT64_C(8796227252667),	// MOV16fk
    UINT64_C(134230424),	// MOV16fo
    UINT64_C(8796093034920),	// MOV16fp
    UINT64_C(8796093034938),	// MOV16fq
    UINT64_C(134230400),	// MOV16fr
    UINT64_C(134234352),	// MOV16fs
    UINT64_C(12424),	// MOV16ja
    UINT64_C(12473),	// MOV16jb
    UINT64_C(17104),	// MOV16jc
    UINT64_C(12416),	// MOV16jd
    UINT64_C(12448),	// MOV16je
    UINT64_C(134230192),	// MOV16jf
    UINT64_C(12476),	// MOV16ji
    UINT64_C(12432),	// MOV16jj
    UINT64_C(134230203),	// MOV16jk
    UINT64_C(12440),	// MOV16jo
    UINT64_C(12456),	// MOV16jp
    UINT64_C(12474),	// MOV16jq
    UINT64_C(12416),	// MOV16jr
    UINT64_C(16592),	// MOV16js
    UINT64_C(12488),	// MOV16oa
    UINT64_C(12537),	// MOV16ob
    UINT64_C(17112),	// MOV16oc
    UINT64_C(12480),	// MOV16od
    UINT64_C(12512),	// MOV16oe
    UINT64_C(134230256),	// MOV16of
    UINT64_C(12540),	// MOV16oi
    UINT64_C(12496),	// MOV16oj
    UINT64_C(134230267),	// MOV16ok
    UINT64_C(12504),	// MOV16oo
    UINT64_C(12520),	// MOV16op
    UINT64_C(12538),	// MOV16oq
    UINT64_C(12480),	// MOV16or
    UINT64_C(16600),	// MOV16os
    UINT64_C(12616),	// MOV16pa
    UINT64_C(12665),	// MOV16pb
    UINT64_C(17128),	// MOV16pc
    UINT64_C(12608),	// MOV16pd
    UINT64_C(12640),	// MOV16pe
    UINT64_C(134230384),	// MOV16pf
    UINT64_C(12668),	// MOV16pi
    UINT64_C(12624),	// MOV16pj
    UINT64_C(134230395),	// MOV16pk
    UINT64_C(12632),	// MOV16po
    UINT64_C(12648),	// MOV16pp
    UINT64_C(12666),	// MOV16pq
    UINT64_C(12608),	// MOV16pr
    UINT64_C(16616),	// MOV16ps
    UINT64_C(12296),	// MOV16ra
    UINT64_C(12345),	// MOV16rb
    UINT64_C(12345),	// MOV16rb_TC
    UINT64_C(12320),	// MOV16re
    UINT64_C(12320),	// MOV16re_TC
    UINT64_C(134230064),	// MOV16rf
    UINT64_C(134230064),	// MOV16rf_TC
    UINT64_C(12348),	// MOV16ri
    UINT64_C(12304),	// MOV16rj
    UINT64_C(12304),	// MOV16rj_TC
    UINT64_C(134230075),	// MOV16rk
    UINT64_C(134230075),	// MOV16rk_TC
    UINT64_C(12312),	// MOV16ro
    UINT64_C(12312),	// MOV16ro_TC
    UINT64_C(12328),	// MOV16rp
    UINT64_C(12328),	// MOV16rp_TC
    UINT64_C(12346),	// MOV16rq
    UINT64_C(12346),	// MOV16rq_TC
    UINT64_C(12288),	// MOV16rr
    UINT64_C(18169),	// MOV16sb
    UINT64_C(18112),	// MOV16sd
    UINT64_C(18144),	// MOV16se
    UINT64_C(134235888),	// MOV16sf
    UINT64_C(18128),	// MOV16sj
    UINT64_C(134235899),	// MOV16sk
    UINT64_C(18136),	// MOV16so
    UINT64_C(18152),	// MOV16sp
    UINT64_C(18170),	// MOV16sq
    UINT64_C(8264),	// MOV32aa
    UINT64_C(8313),	// MOV32ab
    UINT64_C(8313),	// MOV32ab_TC
    UINT64_C(8288),	// MOV32ae
    UINT64_C(8288),	// MOV32ae_TC
    UINT64_C(134226032),	// MOV32af
    UINT64_C(134226032),	// MOV32af_TC
    UINT64_C(8316),	// MOV32ai
    UINT64_C(8272),	// MOV32aj
    UINT64_C(8272),	// MOV32aj_TC
    UINT64_C(134226043),	// MOV32ak
    UINT64_C(134226043),	// MOV32ak_TC
    UINT64_C(8280),	// MOV32ao
    UINT64_C(8280),	// MOV32ao_TC
    UINT64_C(8296),	// MOV32ap
    UINT64_C(8296),	// MOV32ap_TC
    UINT64_C(8314),	// MOV32aq
    UINT64_C(8314),	// MOV32aq_TC
    UINT64_C(8256),	// MOV32ar
    UINT64_C(9160),	// MOV32ba
    UINT64_C(9209),UINT64_C(0),	// MOV32bb
    UINT64_C(9152),	// MOV32bd
    UINT64_C(9184),	// MOV32be
    UINT64_C(134226928),	// MOV32bf
    UINT64_C(9212),UINT64_C(0),	// MOV32bi
    UINT64_C(9168),	// MOV32bj
    UINT64_C(134226939),	// MOV32bk
    UINT64_C(9176),	// MOV32bo
    UINT64_C(9192),	// MOV32bp
    UINT64_C(9210),	// MOV32bq
    UINT64_C(9152),	// MOV32br
    UINT64_C(8249),	// MOV32db
    UINT64_C(8192),	// MOV32dd
    UINT64_C(8224),	// MOV32de
    UINT64_C(134225968),	// MOV32df
    UINT64_C(8252),	// MOV32di
    UINT64_C(8208),	// MOV32dj
    UINT64_C(134225979),	// MOV32dk
    UINT64_C(8216),	// MOV32do
    UINT64_C(8232),	// MOV32dp
    UINT64_C(8250),	// MOV32dq
    UINT64_C(8456),	// MOV32ea
    UINT64_C(8505),	// MOV32eb
    UINT64_C(8448),	// MOV32ed
    UINT64_C(8480),	// MOV32ee
    UINT64_C(134226224),	// MOV32ef
    UINT64_C(8508),	// MOV32ei
    UINT64_C(8464),	// MOV32ej
    UINT64_C(134226235),	// MOV32ek
    UINT64_C(8472),	// MOV32eo
    UINT64_C(8488),	// MOV32ep
    UINT64_C(8506),	// MOV32eq
    UINT64_C(8448),	// MOV32er
    UINT64_C(134226312),	// MOV32fa
    UINT64_C(576460752303432121),	// MOV32fb
    UINT64_C(134226304),	// MOV32fd
    UINT64_C(134226336),	// MOV32fe
    UINT64_C(8796227248560),	// MOV32ff
    UINT64_C(576460752303432124),	// MOV32fi
    UINT64_C(134226320),	// MOV32fj
    UINT64_C(8796227248571),	// MOV32fk
    UINT64_C(134226328),	// MOV32fo
    UINT64_C(8796093030824),	// MOV32fp
    UINT64_C(8796093030842),	// MOV32fq
    UINT64_C(134226304),	// MOV32fr
    UINT64_C(8328),	// MOV32ja
    UINT64_C(8377),	// MOV32jb
    UINT64_C(8320),	// MOV32jd
    UINT64_C(8352),	// MOV32je
    UINT64_C(134226096),	// MOV32jf
    UINT64_C(8380),	// MOV32ji
    UINT64_C(8336),	// MOV32jj
    UINT64_C(134226107),	// MOV32jk
    UINT64_C(8344),	// MOV32jo
    UINT64_C(8360),	// MOV32jp
    UINT64_C(8378),	// MOV32jq
    UINT64_C(8320),	// MOV32jr
    UINT64_C(8392),	// MOV32oa
    UINT64_C(8441),	// MOV32ob
    UINT64_C(8384),	// MOV32od
    UINT64_C(8416),	// MOV32oe
    UINT64_C(134226160),	// MOV32of
    UINT64_C(8444),	// MOV32oi
    UINT64_C(8400),	// MOV32oj
    UINT64_C(134226171),	// MOV32ok
    UINT64_C(8408),	// MOV32oo
    UINT64_C(8424),	// MOV32op
    UINT64_C(8442),	// MOV32oq
    UINT64_C(8384),	// MOV32or
    UINT64_C(8520),	// MOV32pa
    UINT64_C(8569),	// MOV32pb
    UINT64_C(8512),	// MOV32pd
    UINT64_C(8544),	// MOV32pe
    UINT64_C(134226288),	// MOV32pf
    UINT64_C(8572),	// MOV32pi
    UINT64_C(8528),	// MOV32pj
    UINT64_C(134226299),	// MOV32pk
    UINT64_C(8536),	// MOV32po
    UINT64_C(8552),	// MOV32pp
    UINT64_C(8570),	// MOV32pq
    UINT64_C(8512),	// MOV32pr
    UINT64_C(8200),	// MOV32ra
    UINT64_C(8249),	// MOV32rb
    UINT64_C(8249),	// MOV32rb_TC
    UINT64_C(8224),	// MOV32re
    UINT64_C(8224),	// MOV32re_TC
    UINT64_C(134225968),	// MOV32rf
    UINT64_C(134225968),	// MOV32rf_TC
    UINT64_C(8252),	// MOV32ri
    UINT64_C(8208),	// MOV32rj
    UINT64_C(8208),	// MOV32rj_TC
    UINT64_C(134225979),	// MOV32rk
    UINT64_C(134225979),	// MOV32rk_TC
    UINT64_C(8216),	// MOV32ro
    UINT64_C(8216),	// MOV32ro_TC
    UINT64_C(8232),	// MOV32rp
    UINT64_C(8232),	// MOV32rp_TC
    UINT64_C(8250),	// MOV32rq
    UINT64_C(8250),	// MOV32rq_TC
    UINT64_C(8192),	// MOV32rr
    UINT64_C(5113),UINT64_C(0),	// MOV8bb
    UINT64_C(5056),	// MOV8bd
    UINT64_C(5088),	// MOV8be
    UINT64_C(134222832),	// MOV8bf
    UINT64_C(5116),	// MOV8bi
    UINT64_C(5072),	// MOV8bj
    UINT64_C(134222843),	// MOV8bk
    UINT64_C(5080),	// MOV8bo
    UINT64_C(5096),	// MOV8bp
    UINT64_C(5114),	// MOV8bq
    UINT64_C(4153),	// MOV8db
    UINT64_C(4096),	// MOV8dd
    UINT64_C(4128),	// MOV8de
    UINT64_C(134221872),	// MOV8df
    UINT64_C(4156),	// MOV8di
    UINT64_C(4112),	// MOV8dj
    UINT64_C(134221883),	// MOV8dk
    UINT64_C(4120),	// MOV8do
    UINT64_C(4136),	// MOV8dp
    UINT64_C(4154),	// MOV8dq
    UINT64_C(4409),	// MOV8eb
    UINT64_C(4352),	// MOV8ed
    UINT64_C(4384),	// MOV8ee
    UINT64_C(134222128),	// MOV8ef
    UINT64_C(4412),	// MOV8ei
    UINT64_C(4368),	// MOV8ej
    UINT64_C(134222139),	// MOV8ek
    UINT64_C(4376),	// MOV8eo
    UINT64_C(4392),	// MOV8ep
    UINT64_C(4410),	// MOV8eq
    UINT64_C(576460752303428025),	// MOV8fb
    UINT64_C(134222208),	// MOV8fd
    UINT64_C(134222240),	// MOV8fe
    UINT64_C(8796227244464),	// MOV8ff
    UINT64_C(8796093026748),	// MOV8fi
    UINT64_C(134222224),	// MOV8fj
    UINT64_C(8796227244475),	// MOV8fk
    UINT64_C(134222232),	// MOV8fo
    UINT64_C(8796093026728),	// MOV8fp
    UINT64_C(8796093026746),	// MOV8fq
    UINT64_C(4281),	// MOV8jb
    UINT64_C(4224),	// MOV8jd
    UINT64_C(4256),	// MOV8je
    UINT64_C(134222000),	// MOV8jf
    UINT64_C(4284),	// MOV8ji
    UINT64_C(4240),	// MOV8jj
    UINT64_C(134222011),	// MOV8jk
    UINT64_C(4248),	// MOV8jo
    UINT64_C(4264),	// MOV8jp
    UINT64_C(4282),	// MOV8jq
    UINT64_C(4345),	// MOV8ob
    UINT64_C(4288),	// MOV8od
    UINT64_C(4320),	// MOV8oe
    UINT64_C(134222064),	// MOV8of
    UINT64_C(4348),	// MOV8oi
    UINT64_C(4304),	// MOV8oj
    UINT64_C(134222075),	// MOV8ok
    UINT64_C(4312),	// MOV8oo
    UINT64_C(4328),	// MOV8op
    UINT64_C(4346),	// MOV8oq
    UINT64_C(4473),	// MOV8pb
    UINT64_C(4416),	// MOV8pd
    UINT64_C(4448),	// MOV8pe
    UINT64_C(134222192),	// MOV8pf
    UINT64_C(4476),	// MOV8pi
    UINT64_C(4432),	// MOV8pj
    UINT64_C(134222203),	// MOV8pk
    UINT64_C(4440),	// MOV8po
    UINT64_C(4456),	// MOV8pp
    UINT64_C(4474),	// MOV8pq
    UINT64_C(18617),	// MOVM16bm
    UINT64_C(18592),	// MOVM16em
    UINT64_C(8796093040816),	// MOVM16fm
    UINT64_C(18576),	// MOVM16jm
    UINT64_C(19641),	// MOVM16mb
    UINT64_C(19616),	// MOVM16me
    UINT64_C(8796093041840),	// MOVM16mf
    UINT64_C(19600),	// MOVM16mj
    UINT64_C(8796093041851),	// MOVM16mk
    UINT64_C(19608),	// MOVM16mo
    UINT64_C(19624),	// MOVM16mp
    UINT64_C(19642),	// MOVM16mq
    UINT64_C(18584),	// MOVM16om
    UINT64_C(18600),	// MOVM16pm
    UINT64_C(18681),	// MOVM32bm
    UINT64_C(18656),	// MOVM32em
    UINT64_C(8796093040880),	// MOVM32fm
    UINT64_C(18640),	// MOVM32jm
    UINT64_C(19705),	// MOVM32mb
    UINT64_C(19680),	// MOVM32me
    UINT64_C(8796093041904),	// MOVM32mf
    UINT64_C(19664),	// MOVM32mj
    UINT64_C(8796093041915),	// MOVM32mk
    UINT64_C(19672),	// MOVM32mo
    UINT64_C(19688),	// MOVM32mp
    UINT64_C(19706),	// MOVM32mq
    UINT64_C(18648),	// MOVM32om
    UINT64_C(18664),	// MOVM32pm
    UINT64_C(28672),	// MOVQ
    UINT64_C(17472),	// NEG16d
    UINT64_C(17536),	// NEG32d
    UINT64_C(17408),	// NEG8d
    UINT64_C(16448),	// NEGX16d
    UINT64_C(16512),	// NEGX32d
    UINT64_C(16384),	// NEGX8d
    UINT64_C(20081),	// NOP
    UINT64_C(17984),	// NOT16d
    UINT64_C(18048),	// NOT32d
    UINT64_C(17920),	// NOT8d
    UINT64_C(32832),	// OR16dd
    UINT64_C(134250608),	// OR16df
    UINT64_C(32892),	// OR16di
    UINT64_C(32848),	// OR16dj
    UINT64_C(134250619),	// OR16dk
    UINT64_C(32872),	// OR16dp
    UINT64_C(32890),	// OR16dq
    UINT64_C(32832),	// OR16dr
    UINT64_C(134250864),	// OR16fd
    UINT64_C(8796093022320),	// OR16fi
    UINT64_C(33104),	// OR16jd
    UINT64_C(80),	// OR16ji
    UINT64_C(33128),	// OR16pd
    UINT64_C(104),	// OR16pi
    UINT64_C(32896),	// OR32dd
    UINT64_C(134250672),	// OR32df
    UINT64_C(32956),	// OR32di
    UINT64_C(32912),	// OR32dj
    UINT64_C(134250683),	// OR32dk
    UINT64_C(32936),	// OR32dp
    UINT64_C(32954),	// OR32dq
    UINT64_C(32896),	// OR32dr
    UINT64_C(134250928),	// OR32fd
    UINT64_C(576460752303423664),	// OR32fi
    UINT64_C(33168),	// OR32jd
    UINT64_C(144),	// OR32ji
    UINT64_C(33192),	// OR32pd
    UINT64_C(168),	// OR32pi
    UINT64_C(32768),	// OR8dd
    UINT64_C(134250544),	// OR8df
    UINT64_C(32828),	// OR8di
    UINT64_C(32784),	// OR8dj
    UINT64_C(134250555),	// OR8dk
    UINT64_C(32808),	// OR8dp
    UINT64_C(32826),	// OR8dq
    UINT64_C(134250800),	// OR8fd
    UINT64_C(8796093022256),	// OR8fi
    UINT64_C(33040),	// OR8jd
    UINT64_C(16),	// OR8ji
    UINT64_C(33064),	// OR8pd
    UINT64_C(40),	// OR8pi
    UINT64_C(57720),	// ROL16dd
    UINT64_C(57688),	// ROL16di
    UINT64_C(57784),	// ROL32dd
    UINT64_C(57752),	// ROL32di
    UINT64_C(57656),	// ROL8dd
    UINT64_C(57624),	// ROL8di
    UINT64_C(57464),	// ROR16dd
    UINT64_C(57432),	// ROR16di
    UINT64_C(57528),	// ROR32dd
    UINT64_C(57496),	// ROR32di
    UINT64_C(57400),	// ROR8dd
    UINT64_C(57368),	// ROR8di
    UINT64_C(20083),	// RTE
    UINT64_C(20085),	// RTS
    UINT64_C(33216),	// SDIVd32d16
    UINT64_C(134237248),	// SDIVd32d32
    UINT64_C(33276),	// SDIVd32i16
    UINT64_C(21696),	// SETd8cc
    UINT64_C(21952),	// SETd8cs
    UINT64_C(22464),	// SETd8eq
    UINT64_C(20928),	// SETd8f
    UINT64_C(23744),	// SETd8ge
    UINT64_C(24256),	// SETd8gt
    UINT64_C(21184),	// SETd8hi
    UINT64_C(24512),	// SETd8le
    UINT64_C(21440),	// SETd8ls
    UINT64_C(24000),	// SETd8lt
    UINT64_C(23488),	// SETd8mi
    UINT64_C(22208),	// SETd8ne
    UINT64_C(23232),	// SETd8pl
    UINT64_C(20672),	// SETd8t
    UINT64_C(22720),	// SETd8vc
    UINT64_C(22976),	// SETd8vs
    UINT64_C(21712),	// SETj8cc
    UINT64_C(21968),	// SETj8cs
    UINT64_C(22480),	// SETj8eq
    UINT64_C(20944),	// SETj8f
    UINT64_C(23760),	// SETj8ge
    UINT64_C(24272),	// SETj8gt
    UINT64_C(21200),	// SETj8hi
    UINT64_C(24528),	// SETj8le
    UINT64_C(21456),	// SETj8ls
    UINT64_C(24016),	// SETj8lt
    UINT64_C(23504),	// SETj8mi
    UINT64_C(22224),	// SETj8ne
    UINT64_C(23248),	// SETj8pl
    UINT64_C(20688),	// SETj8t
    UINT64_C(22736),	// SETj8vc
    UINT64_C(22992),	// SETj8vs
    UINT64_C(21736),	// SETp8cc
    UINT64_C(21992),	// SETp8cs
    UINT64_C(22504),	// SETp8eq
    UINT64_C(20968),	// SETp8f
    UINT64_C(23784),	// SETp8ge
    UINT64_C(24296),	// SETp8gt
    UINT64_C(21224),	// SETp8hi
    UINT64_C(24552),	// SETp8le
    UINT64_C(21480),	// SETp8ls
    UINT64_C(24040),	// SETp8lt
    UINT64_C(23528),	// SETp8mi
    UINT64_C(22248),	// SETp8ne
    UINT64_C(23272),	// SETp8pl
    UINT64_C(20712),	// SETp8t
    UINT64_C(22760),	// SETp8vc
    UINT64_C(23016),	// SETp8vs
    UINT64_C(57704),	// SHL16dd
    UINT64_C(57672),	// SHL16di
    UINT64_C(57768),	// SHL32dd
    UINT64_C(57736),	// SHL32di
    UINT64_C(57640),	// SHL8dd
    UINT64_C(57608),	// SHL8di
    UINT64_C(49600),	// SMULd32d16
    UINT64_C(134237184),	// SMULd32d32
    UINT64_C(49660),	// SMULd32i16
    UINT64_C(36928),	// SUB16dd
    UINT64_C(134254704),	// SUB16df
    UINT64_C(36988),	// SUB16di
    UINT64_C(36944),	// SUB16dj
    UINT64_C(134254715),	// SUB16dk
    UINT64_C(36968),	// SUB16dp
    UINT64_C(36986),	// SUB16dq
    UINT64_C(36928),	// SUB16dr
    UINT64_C(134254960),	// SUB16fd
    UINT64_C(8796093023344),	// SUB16fi
    UINT64_C(37200),	// SUB16jd
    UINT64_C(1104),	// SUB16ji
    UINT64_C(37224),	// SUB16pd
    UINT64_C(1128),	// SUB16pi
    UINT64_C(37369),	// SUB32ab
    UINT64_C(134255088),	// SUB32af
    UINT64_C(37372),	// SUB32ai
    UINT64_C(37328),	// SUB32aj
    UINT64_C(134255099),	// SUB32ak
    UINT64_C(37352),	// SUB32ap
    UINT64_C(37370),	// SUB32aq
    UINT64_C(37312),	// SUB32ar
    UINT64_C(36992),	// SUB32dd
    UINT64_C(134254768),	// SUB32df
    UINT64_C(37052),	// SUB32di
    UINT64_C(37008),	// SUB32dj
    UINT64_C(134254779),	// SUB32dk
    UINT64_C(37032),	// SUB32dp
    UINT64_C(37050),	// SUB32dq
    UINT64_C(36992),	// SUB32dr
    UINT64_C(134255024),	// SUB32fd
    UINT64_C(576460752303424688),	// SUB32fi
    UINT64_C(37264),	// SUB32jd
    UINT64_C(1168),	// SUB32ji
    UINT64_C(37288),	// SUB32pd
    UINT64_C(1192),	// SUB32pi
    UINT64_C(36864),	// SUB8dd
    UINT64_C(134254640),	// SUB8df
    UINT64_C(36924),	// SUB8di
    UINT64_C(36880),	// SUB8dj
    UINT64_C(134254651),	// SUB8dk
    UINT64_C(36904),	// SUB8dp
    UINT64_C(36922),	// SUB8dq
    UINT64_C(134254896),	// SUB8fd
    UINT64_C(8796093023280),	// SUB8fi
    UINT64_C(37136),	// SUB8jd
    UINT64_C(1040),	// SUB8ji
    UINT64_C(37160),	// SUB8pd
    UINT64_C(1064),	// SUB8pi
    UINT64_C(37184),	// SUBX16dd
    UINT64_C(37248),	// SUBX32dd
    UINT64_C(37120),	// SUBX8dd
    UINT64_C(20032),	// TRAP
    UINT64_C(20086),	// TRAPV
    UINT64_C(32960),	// UDIVd32d16
    UINT64_C(19520),	// UDIVd32d32
    UINT64_C(33020),	// UDIVd32i16
    UINT64_C(49344),	// UMULd32d16
    UINT64_C(19456),	// UMULd32d32
    UINT64_C(49404),	// UMULd32i16
    UINT64_C(20056),	// UNLK
    UINT64_C(45376),	// XOR16dd
    UINT64_C(2624),	// XOR16di
    UINT64_C(45440),	// XOR32dd
    UINT64_C(2688),	// XOR32di
    UINT64_C(45312),	// XOR8dd
    UINT64_C(2560),	// XOR8di
    UINT64_C(0)
  };
  auto getInstBits = [&](unsigned Opcode) -> APInt {
    unsigned NumBits = Index[Opcode][0];
    if (!NumBits)
      return APInt::getZeroWidth();
    unsigned Idx = Index[Opcode][1];
    ArrayRef<uint64_t> Data(&InstBits[Idx], APInt::getNumWords(NumBits));
    return APInt(NumBits, Data);
  };
  const unsigned opcode = MI.getOpcode();
  switch (opcode) {
    case M68k::ILLEGAL:
    case M68k::NOP:
    case M68k::RTE:
    case M68k::RTS:
    case M68k::TRAPV: {
      Inst = getInstBits(opcode);
      break;
    }
    case M68k::BTST8qi: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: bitno
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 16);
      Scratch.clearAllBits();
      // op: dst
      encodePCRelImm<16>(MI, /*OpIdx=*/0, /*Pos=*/32, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 32);
      break;
    }
    case M68k::BTST8qd: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: bitno
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      Scratch.clearAllBits();
      // op: dst
      encodePCRelImm<16>(MI, /*OpIdx=*/0, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      break;
    }
    case M68k::BRA16:
    case M68k::BSR16:
    case M68k::Bcc16:
    case M68k::Bcs16:
    case M68k::Beq16:
    case M68k::Bge16:
    case M68k::Bgt16:
    case M68k::Bhi16:
    case M68k::Ble16:
    case M68k::Bls16:
    case M68k::Blt16:
    case M68k::Bmi16:
    case M68k::Bne16:
    case M68k::Bpl16:
    case M68k::Bvc16:
    case M68k::Bvs16:
    case M68k::CALLq: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst
      encodePCRelImm<16>(MI, /*OpIdx=*/0, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      break;
    }
    case M68k::MOVM16em:
    case M68k::MOVM32em: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: mask
      encodeInverseMoveMask(MI, /*OpIdx=*/1, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      break;
    }
    case M68k::MOVM16jm:
    case M68k::MOVM16om:
    case M68k::MOVM32jm:
    case M68k::MOVM32om: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: mask
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      break;
    }
    case M68k::ADD16ji:
    case M68k::AND16ji:
    case M68k::OR16ji:
    case M68k::SUB16ji: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: opd
      encodeRelocImm<16>(MI, /*OpIdx=*/1, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      break;
    }
    case M68k::XOR16di: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: opd
      encodeRelocImm<16>(MI, /*OpIdx=*/2, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      break;
    }
    case M68k::MOV16rq:
    case M68k::MOV16rq_TC:
    case M68k::MOV32rq:
    case M68k::MOV32rq_TC: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/6, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(1, 3), 6);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      Scratch.clearAllBits();
      // op: src
      encodePCRelImm<16>(MI, /*OpIdx=*/1, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      break;
    }
    case M68k::MOV16ri: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/6, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(1, 3), 6);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      Scratch.clearAllBits();
      // op: src
      encodeRelocImm<16>(MI, /*OpIdx=*/1, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      break;
    }
    case M68k::ADD8dq:
    case M68k::ADD16dq:
    case M68k::ADD32aq:
    case M68k::ADD32dq:
    case M68k::AND8dq:
    case M68k::AND16dq:
    case M68k::AND32dq:
    case M68k::OR8dq:
    case M68k::OR16dq:
    case M68k::OR32dq:
    case M68k::SUB8dq:
    case M68k::SUB16dq:
    case M68k::SUB32aq:
    case M68k::SUB32dq: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      Scratch.clearAllBits();
      // op: opd
      encodePCRelImm<16>(MI, /*OpIdx=*/2, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      break;
    }
    case M68k::ADD16di:
    case M68k::AND16di:
    case M68k::OR16di:
    case M68k::SDIVd32i16:
    case M68k::SMULd32i16:
    case M68k::SUB16di:
    case M68k::UDIVd32i16:
    case M68k::UMULd32i16: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      Scratch.clearAllBits();
      // op: opd
      encodeRelocImm<16>(MI, /*OpIdx=*/2, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      break;
    }
    case M68k::LEA32q:
    case M68k::MOV8dq:
    case M68k::MOV8eq:
    case M68k::MOV8jq:
    case M68k::MOV8oq:
    case M68k::MOV16aq:
    case M68k::MOV16aq_TC:
    case M68k::MOV16dq:
    case M68k::MOV16eq:
    case M68k::MOV16jq:
    case M68k::MOV16oq:
    case M68k::MOV32aq:
    case M68k::MOV32aq_TC:
    case M68k::MOV32dq:
    case M68k::MOV32eq:
    case M68k::MOV32jq:
    case M68k::MOV32oq: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      Scratch.clearAllBits();
      // op: src
      encodePCRelImm<16>(MI, /*OpIdx=*/1, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      break;
    }
    case M68k::MOV16ai:
    case M68k::MOV16di:
    case M68k::MOV16ei:
    case M68k::MOV16ji:
    case M68k::MOV16oi: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      Scratch.clearAllBits();
      // op: src
      encodeRelocImm<16>(MI, /*OpIdx=*/1, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      break;
    }
    case M68k::BCHG8pi:
    case M68k::BCLR8pi:
    case M68k::BSET8pi:
    case M68k::BTST8pi: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst.reg
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: bitno
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 16);
      Scratch.clearAllBits();
      // op: dst.disp
      encodeRelocImm<16>(MI, /*OpIdx=*/0, /*Pos=*/32, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 32);
      break;
    }
    case M68k::BCHG8pd:
    case M68k::BCLR8pd:
    case M68k::BSET8pd:
    case M68k::BTST8pd: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst.reg
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: bitno
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      Scratch.clearAllBits();
      // op: dst.disp
      encodeRelocImm<16>(MI, /*OpIdx=*/0, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      break;
    }
    case M68k::CALLp:
    case M68k::MOV16pc:
    case M68k::MOV16ps:
    case M68k::SETp8cc:
    case M68k::SETp8cs:
    case M68k::SETp8eq:
    case M68k::SETp8f:
    case M68k::SETp8ge:
    case M68k::SETp8gt:
    case M68k::SETp8hi:
    case M68k::SETp8le:
    case M68k::SETp8ls:
    case M68k::SETp8lt:
    case M68k::SETp8mi:
    case M68k::SETp8ne:
    case M68k::SETp8pl:
    case M68k::SETp8t:
    case M68k::SETp8vc:
    case M68k::SETp8vs: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst.reg
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: dst.disp
      encodeRelocImm<16>(MI, /*OpIdx=*/0, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      break;
    }
    case M68k::MOVM16pm:
    case M68k::MOVM32pm: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst.reg
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: mask
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      Scratch.clearAllBits();
      // op: dst.disp
      encodeRelocImm<16>(MI, /*OpIdx=*/0, /*Pos=*/32, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 32);
      break;
    }
    case M68k::MOVM16fm:
    case M68k::MOVM32fm: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst.reg
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: mask
      getMachineOpValue(MI, MI.getOperand(3), /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      Scratch.clearAllBits();
      // op: dst.disp
      encodeRelocImm<8>(MI, /*OpIdx=*/0, /*Pos=*/32, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 32);
      Scratch.clearAllBits();
      // op: dst.index
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/44, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 44);
      break;
    }
    case M68k::ADD16pi:
    case M68k::AND16pi:
    case M68k::OR16pi:
    case M68k::SUB16pi: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst.reg
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: opd
      encodeRelocImm<16>(MI, /*OpIdx=*/2, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      Scratch.clearAllBits();
      // op: dst.disp
      encodeRelocImm<16>(MI, /*OpIdx=*/0, /*Pos=*/32, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 32);
      break;
    }
    case M68k::ADD16fi:
    case M68k::AND16fi:
    case M68k::OR16fi:
    case M68k::SUB16fi: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst.reg
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: opd
      encodeRelocImm<16>(MI, /*OpIdx=*/3, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      Scratch.clearAllBits();
      // op: dst.disp
      encodeRelocImm<8>(MI, /*OpIdx=*/0, /*Pos=*/32, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 32);
      Scratch.clearAllBits();
      // op: dst.index
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/44, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 44);
      break;
    }
    case M68k::ADD8pi:
    case M68k::AND8pi:
    case M68k::OR8pi:
    case M68k::SUB8pi: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst.reg
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: opd
      encodeRelocImm<8>(MI, /*OpIdx=*/2, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 16);
      Scratch.clearAllBits();
      // op: dst.disp
      encodeRelocImm<16>(MI, /*OpIdx=*/0, /*Pos=*/32, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 32);
      break;
    }
    case M68k::ADD8pd:
    case M68k::ADD16pd:
    case M68k::ADD32pd:
    case M68k::AND8pd:
    case M68k::AND16pd:
    case M68k::AND32pd:
    case M68k::OR8pd:
    case M68k::OR16pd:
    case M68k::OR32pd:
    case M68k::SUB8pd:
    case M68k::SUB16pd:
    case M68k::SUB32pd: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst.reg
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: opd
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      Scratch.clearAllBits();
      // op: dst.disp
      encodeRelocImm<16>(MI, /*OpIdx=*/0, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      break;
    }
    case M68k::MOV8pq:
    case M68k::MOV16pq:
    case M68k::MOV32pq: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst.reg
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      Scratch.clearAllBits();
      // op: src
      encodePCRelImm<16>(MI, /*OpIdx=*/2, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      Scratch.clearAllBits();
      // op: dst.disp
      encodeRelocImm<16>(MI, /*OpIdx=*/0, /*Pos=*/32, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 32);
      break;
    }
    case M68k::MOV8fq:
    case M68k::MOV16fq:
    case M68k::MOV32fq: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst.reg
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      Scratch.clearAllBits();
      // op: src
      encodePCRelImm<16>(MI, /*OpIdx=*/3, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      Scratch.clearAllBits();
      // op: dst.disp
      encodeRelocImm<8>(MI, /*OpIdx=*/0, /*Pos=*/32, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 32);
      Scratch.clearAllBits();
      // op: dst.index
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/44, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 44);
      break;
    }
    case M68k::MOV16pi: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst.reg
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      Scratch.clearAllBits();
      // op: src
      encodeRelocImm<16>(MI, /*OpIdx=*/2, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      Scratch.clearAllBits();
      // op: dst.disp
      encodeRelocImm<16>(MI, /*OpIdx=*/0, /*Pos=*/32, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 32);
      break;
    }
    case M68k::MOV16fi: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst.reg
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      Scratch.clearAllBits();
      // op: src
      encodeRelocImm<16>(MI, /*OpIdx=*/3, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      Scratch.clearAllBits();
      // op: dst.disp
      encodeRelocImm<8>(MI, /*OpIdx=*/0, /*Pos=*/32, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 32);
      Scratch.clearAllBits();
      // op: dst.index
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/44, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 44);
      break;
    }
    case M68k::MOV8pi: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst.reg
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      Scratch.clearAllBits();
      // op: src
      encodeRelocImm<8>(MI, /*OpIdx=*/2, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 16);
      Scratch.clearAllBits();
      // op: dst.disp
      encodeRelocImm<16>(MI, /*OpIdx=*/0, /*Pos=*/32, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 32);
      break;
    }
    case M68k::MOV8pk:
    case M68k::MOV16pk:
    case M68k::MOV32pk: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst.reg
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      Scratch.clearAllBits();
      // op: src.disp
      encodePCRelImm<8>(MI, /*OpIdx=*/2, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 16);
      Scratch.clearAllBits();
      // op: src.index
      getMachineOpValue(MI, MI.getOperand(3), /*Pos=*/28, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 28);
      Scratch.clearAllBits();
      // op: dst.disp
      encodeRelocImm<16>(MI, /*OpIdx=*/0, /*Pos=*/32, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 32);
      break;
    }
    case M68k::CMP16qi: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: imm
      encodeRelocImm<16>(MI, /*OpIdx=*/0, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      Scratch.clearAllBits();
      // op: mem
      encodePCRelImm<16>(MI, /*OpIdx=*/1, /*Pos=*/32, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 32);
      break;
    }
    case M68k::CMP16ki: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: imm
      encodeRelocImm<16>(MI, /*OpIdx=*/0, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      Scratch.clearAllBits();
      // op: mem.disp
      encodePCRelImm<8>(MI, /*OpIdx=*/1, /*Pos=*/32, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 32);
      Scratch.clearAllBits();
      // op: mem.index
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/44, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 44);
      break;
    }
    case M68k::CMP8qi: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: imm
      encodeRelocImm<8>(MI, /*OpIdx=*/0, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 16);
      Scratch.clearAllBits();
      // op: mem
      encodePCRelImm<16>(MI, /*OpIdx=*/1, /*Pos=*/32, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 32);
      break;
    }
    case M68k::MOVM16mq:
    case M68k::MOVM32mq: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: mask
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      Scratch.clearAllBits();
      // op: src
      encodePCRelImm<16>(MI, /*OpIdx=*/1, /*Pos=*/32, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 32);
      break;
    }
    case M68k::MOVM16mk:
    case M68k::MOVM32mk: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: mask
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      Scratch.clearAllBits();
      // op: src.disp
      encodePCRelImm<8>(MI, /*OpIdx=*/1, /*Pos=*/32, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 32);
      Scratch.clearAllBits();
      // op: src.index
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/44, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 44);
      break;
    }
    case M68k::CMP16ji: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: mem
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: imm
      encodeRelocImm<16>(MI, /*OpIdx=*/0, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      break;
    }
    case M68k::CMP16pi: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: mem.reg
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: imm
      encodeRelocImm<16>(MI, /*OpIdx=*/0, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      Scratch.clearAllBits();
      // op: mem.disp
      encodeRelocImm<16>(MI, /*OpIdx=*/1, /*Pos=*/32, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 32);
      break;
    }
    case M68k::CMP16fi: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: mem.reg
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: imm
      encodeRelocImm<16>(MI, /*OpIdx=*/0, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      Scratch.clearAllBits();
      // op: mem.disp
      encodeRelocImm<8>(MI, /*OpIdx=*/1, /*Pos=*/32, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 32);
      Scratch.clearAllBits();
      // op: mem.index
      getMachineOpValue(MI, MI.getOperand(3), /*Pos=*/44, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 44);
      break;
    }
    case M68k::CMP8pi: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: mem.reg
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: imm
      encodeRelocImm<8>(MI, /*OpIdx=*/0, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 16);
      Scratch.clearAllBits();
      // op: mem.disp
      encodeRelocImm<16>(MI, /*OpIdx=*/1, /*Pos=*/32, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 32);
      break;
    }
    case M68k::CMP8dp:
    case M68k::CMP16dp:
    case M68k::CMP32dp: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: mem.reg
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: reg
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      Scratch.clearAllBits();
      // op: mem.disp
      encodeRelocImm<16>(MI, /*OpIdx=*/1, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      break;
    }
    case M68k::CASARID8:
    case M68k::CASARID16:
    case M68k::CASARID32: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: mem.reg
      getMachineOpValue(MI, MI.getOperand(4), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: dc
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 16);
      Scratch.clearAllBits();
      // op: du
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/22, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 22);
      Scratch.clearAllBits();
      // op: mem.disp
      encodeRelocImm<16>(MI, /*OpIdx=*/3, /*Pos=*/32, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 32);
      break;
    }
    case M68k::ADD8dp:
    case M68k::ADD16dp:
    case M68k::ADD32ap:
    case M68k::ADD32dp:
    case M68k::AND8dp:
    case M68k::AND16dp:
    case M68k::AND32dp:
    case M68k::OR8dp:
    case M68k::OR16dp:
    case M68k::OR32dp:
    case M68k::SUB8dp:
    case M68k::SUB16dp:
    case M68k::SUB32ap:
    case M68k::SUB32dp: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: opd.reg
      getMachineOpValue(MI, MI.getOperand(3), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      Scratch.clearAllBits();
      // op: opd.disp
      encodeRelocImm<16>(MI, /*OpIdx=*/2, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      break;
    }
    case M68k::CMP8dq:
    case M68k::CMP16dq:
    case M68k::CMP32dq: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: reg
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      Scratch.clearAllBits();
      // op: mem
      encodePCRelImm<16>(MI, /*OpIdx=*/1, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      break;
    }
    case M68k::CMP16di: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: reg
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: imm
      encodeRelocImm<16>(MI, /*OpIdx=*/0, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      break;
    }
    case M68k::MOV16cq:
    case M68k::MOV16sq: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: src
      encodePCRelImm<16>(MI, /*OpIdx=*/1, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      break;
    }
    case M68k::LINK16: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: src
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: disp
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      break;
    }
    case M68k::MOVM16me:
    case M68k::MOVM32me: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: src
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: mask
      encodeInverseMoveMask(MI, /*OpIdx=*/0, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      break;
    }
    case M68k::MOVM16mj:
    case M68k::MOVM16mo:
    case M68k::MOVM32mj:
    case M68k::MOVM32mo: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: src
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: mask
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      break;
    }
    case M68k::MOV8pd:
    case M68k::MOV8pe:
    case M68k::MOV8pj:
    case M68k::MOV8po:
    case M68k::MOV16pa:
    case M68k::MOV16pd:
    case M68k::MOV16pe:
    case M68k::MOV16pj:
    case M68k::MOV16po:
    case M68k::MOV32pa:
    case M68k::MOV32pd:
    case M68k::MOV32pe:
    case M68k::MOV32pj:
    case M68k::MOV32po: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: src
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: dst.reg
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      Scratch.clearAllBits();
      // op: dst.disp
      encodeRelocImm<16>(MI, /*OpIdx=*/0, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      break;
    }
    case M68k::MOV16pr:
    case M68k::MOV32pr: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: src
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: src
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/3, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(1, 3), 3);
      Scratch.clearAllBits();
      // op: dst.reg
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      Scratch.clearAllBits();
      // op: dst.disp
      encodeRelocImm<16>(MI, /*OpIdx=*/0, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      break;
    }
    case M68k::MOV16rp:
    case M68k::MOV16rp_TC:
    case M68k::MOV32rp:
    case M68k::MOV32rp_TC: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: src.reg
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/6, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(1, 3), 6);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      Scratch.clearAllBits();
      // op: src.disp
      encodeRelocImm<16>(MI, /*OpIdx=*/1, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      break;
    }
    case M68k::LEA32p:
    case M68k::MOV8dp:
    case M68k::MOV8ep:
    case M68k::MOV8jp:
    case M68k::MOV8op:
    case M68k::MOV16ap:
    case M68k::MOV16ap_TC:
    case M68k::MOV16dp:
    case M68k::MOV16ep:
    case M68k::MOV16jp:
    case M68k::MOV16op:
    case M68k::MOV32ap:
    case M68k::MOV32ap_TC:
    case M68k::MOV32dp:
    case M68k::MOV32ep:
    case M68k::MOV32jp:
    case M68k::MOV32op: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: src.reg
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      Scratch.clearAllBits();
      // op: src.disp
      encodeRelocImm<16>(MI, /*OpIdx=*/1, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      break;
    }
    case M68k::MOVM16mp:
    case M68k::MOVM32mp: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: src.reg
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: mask
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      Scratch.clearAllBits();
      // op: src.disp
      encodeRelocImm<16>(MI, /*OpIdx=*/1, /*Pos=*/32, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 32);
      break;
    }
    case M68k::MOVM16mf:
    case M68k::MOVM32mf: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: src.reg
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: mask
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      Scratch.clearAllBits();
      // op: src.disp
      encodeRelocImm<8>(MI, /*OpIdx=*/1, /*Pos=*/32, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 32);
      Scratch.clearAllBits();
      // op: src.index
      getMachineOpValue(MI, MI.getOperand(3), /*Pos=*/44, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 44);
      break;
    }
    case M68k::MOV16cp:
    case M68k::MOV16sp: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: src.reg
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: src.disp
      encodeRelocImm<16>(MI, /*OpIdx=*/1, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      break;
    }
    case M68k::MOV8pp:
    case M68k::MOV16pp:
    case M68k::MOV32pp: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: src.reg
      getMachineOpValue(MI, MI.getOperand(3), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: dst.reg
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      Scratch.clearAllBits();
      // op: src.disp
      encodeRelocImm<16>(MI, /*OpIdx=*/2, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      Scratch.clearAllBits();
      // op: dst.disp
      encodeRelocImm<16>(MI, /*OpIdx=*/0, /*Pos=*/32, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 32);
      break;
    }
    case M68k::MOV8pf:
    case M68k::MOV16pf:
    case M68k::MOV32pf: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: src.reg
      getMachineOpValue(MI, MI.getOperand(3), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: dst.reg
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      Scratch.clearAllBits();
      // op: src.disp
      encodeRelocImm<8>(MI, /*OpIdx=*/2, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 16);
      Scratch.clearAllBits();
      // op: src.index
      getMachineOpValue(MI, MI.getOperand(4), /*Pos=*/28, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 28);
      Scratch.clearAllBits();
      // op: dst.disp
      encodeRelocImm<16>(MI, /*OpIdx=*/0, /*Pos=*/32, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 32);
      break;
    }
    case M68k::MOV8fp:
    case M68k::MOV16fp:
    case M68k::MOV32fp: {
      if (Scratch.getBitWidth() < 16) { Scratch = Scratch.zext(16); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: src.reg
      getMachineOpValue(MI, MI.getOperand(4), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: dst.reg
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      Scratch.clearAllBits();
      // op: src.disp
      encodeRelocImm<16>(MI, /*OpIdx=*/3, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      Scratch.clearAllBits();
      // op: dst.disp
      encodeRelocImm<8>(MI, /*OpIdx=*/0, /*Pos=*/32, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 32);
      Scratch.clearAllBits();
      // op: dst.index
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/44, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 44);
      break;
    }
    case M68k::CALLj:
    case M68k::JMP32j:
    case M68k::MOV16dc:
    case M68k::MOV16ds:
    case M68k::MOV16ec:
    case M68k::MOV16es:
    case M68k::MOV16jc:
    case M68k::MOV16js:
    case M68k::MOV16oc:
    case M68k::MOV16os:
    case M68k::SETj8cc:
    case M68k::SETj8cs:
    case M68k::SETj8eq:
    case M68k::SETj8f:
    case M68k::SETj8ge:
    case M68k::SETj8gt:
    case M68k::SETj8hi:
    case M68k::SETj8le:
    case M68k::SETj8ls:
    case M68k::SETj8lt:
    case M68k::SETj8mi:
    case M68k::SETj8ne:
    case M68k::SETj8pl:
    case M68k::SETj8t:
    case M68k::SETj8vc:
    case M68k::SETj8vs: {
      if (Scratch.getBitWidth() < 3) { Scratch = Scratch.zext(3); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      break;
    }
    case M68k::BCHG8ed:
    case M68k::BCHG8jd:
    case M68k::BCHG8od:
    case M68k::BCLR8ed:
    case M68k::BCLR8jd:
    case M68k::BCLR8od:
    case M68k::BSET8ed:
    case M68k::BSET8jd:
    case M68k::BSET8od:
    case M68k::BTST8ed:
    case M68k::BTST8jd:
    case M68k::BTST8od: {
      if (Scratch.getBitWidth() < 3) { Scratch = Scratch.zext(3); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: bitno
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      break;
    }
    case M68k::ADD8jd:
    case M68k::ADD16jd:
    case M68k::ADD32jd:
    case M68k::AND8jd:
    case M68k::AND16jd:
    case M68k::AND32jd:
    case M68k::OR8jd:
    case M68k::OR16jd:
    case M68k::OR32jd:
    case M68k::SUB8jd:
    case M68k::SUB16jd:
    case M68k::SUB32jd: {
      if (Scratch.getBitWidth() < 3) { Scratch = Scratch.zext(3); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: opd
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      break;
    }
    case M68k::ASR8dd:
    case M68k::ASR8di:
    case M68k::ASR16dd:
    case M68k::ASR16di:
    case M68k::ASR32dd:
    case M68k::ASR32di:
    case M68k::LSR8dd:
    case M68k::LSR8di:
    case M68k::LSR16dd:
    case M68k::LSR16di:
    case M68k::LSR32dd:
    case M68k::LSR32di:
    case M68k::ROL8dd:
    case M68k::ROL8di:
    case M68k::ROL16dd:
    case M68k::ROL16di:
    case M68k::ROL32dd:
    case M68k::ROL32di:
    case M68k::ROR8dd:
    case M68k::ROR8di:
    case M68k::ROR16dd:
    case M68k::ROR16di:
    case M68k::ROR32dd:
    case M68k::ROR32di:
    case M68k::SHL8dd:
    case M68k::SHL8di:
    case M68k::SHL16dd:
    case M68k::SHL16di:
    case M68k::SHL32dd:
    case M68k::SHL32di:
    case M68k::XOR8dd:
    case M68k::XOR16dd:
    case M68k::XOR32dd: {
      if (Scratch.getBitWidth() < 3) { Scratch = Scratch.zext(3); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: opd
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      break;
    }
    case M68k::FMOVE32a_fpi:
    case M68k::FMOVE32d_fpcs: {
      if (Scratch.getBitWidth() < 3) { Scratch = Scratch.zext(3); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: src
      encodeFPSYSSelect(MI, /*OpIdx=*/1, /*Pos=*/26, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 26);
      break;
    }
    case M68k::FADD32fp_fp:
    case M68k::FADD64fp_fp:
    case M68k::FADD80fp_fp:
    case M68k::FDADD32fp_fp:
    case M68k::FDADD64fp_fp:
    case M68k::FDADD80fp_fp:
    case M68k::FDDIV32fp_fp:
    case M68k::FDDIV64fp_fp:
    case M68k::FDDIV80fp_fp:
    case M68k::FDIV32fp_fp:
    case M68k::FDIV64fp_fp:
    case M68k::FDIV80fp_fp:
    case M68k::FDMUL32fp_fp:
    case M68k::FDMUL64fp_fp:
    case M68k::FDMUL80fp_fp:
    case M68k::FDSUB32fp_fp:
    case M68k::FDSUB64fp_fp:
    case M68k::FDSUB80fp_fp:
    case M68k::FMUL32fp_fp:
    case M68k::FMUL64fp_fp:
    case M68k::FMUL80fp_fp:
    case M68k::FSADD32fp_fp:
    case M68k::FSADD64fp_fp:
    case M68k::FSADD80fp_fp:
    case M68k::FSDIV32fp_fp:
    case M68k::FSDIV64fp_fp:
    case M68k::FSDIV80fp_fp:
    case M68k::FSMUL32fp_fp:
    case M68k::FSMUL64fp_fp:
    case M68k::FSMUL80fp_fp:
    case M68k::FSSUB32fp_fp:
    case M68k::FSSUB64fp_fp:
    case M68k::FSSUB80fp_fp:
    case M68k::FSUB32fp_fp:
    case M68k::FSUB64fp_fp:
    case M68k::FSUB80fp_fp: {
      if (Scratch.getBitWidth() < 3) { Scratch = Scratch.zext(3); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/23, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 23);
      Scratch.clearAllBits();
      // op: opd
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/26, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 26);
      break;
    }
    case M68k::FABS32fp_fp:
    case M68k::FABS64fp_fp:
    case M68k::FABS80fp_fp:
    case M68k::FDABS32fp_fp:
    case M68k::FDABS64fp_fp:
    case M68k::FDABS80fp_fp:
    case M68k::FDMOV32fp_fp:
    case M68k::FDMOV64fp_fp:
    case M68k::FDMOV80fp_fp:
    case M68k::FDNEG32fp_fp:
    case M68k::FDNEG64fp_fp:
    case M68k::FDNEG80fp_fp:
    case M68k::FMOV32fp_fp:
    case M68k::FMOV64fp_fp:
    case M68k::FMOV80fp_fp:
    case M68k::FNEG32fp_fp:
    case M68k::FNEG64fp_fp:
    case M68k::FNEG80fp_fp:
    case M68k::FSABS32fp_fp:
    case M68k::FSABS64fp_fp:
    case M68k::FSABS80fp_fp:
    case M68k::FSMOV32fp_fp:
    case M68k::FSMOV64fp_fp:
    case M68k::FSMOV80fp_fp:
    case M68k::FSNEG32fp_fp:
    case M68k::FSNEG64fp_fp:
    case M68k::FSNEG80fp_fp: {
      if (Scratch.getBitWidth() < 3) { Scratch = Scratch.zext(3); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/23, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 23);
      Scratch.clearAllBits();
      // op: src
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/26, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 26);
      break;
    }
    case M68k::CMP8dj:
    case M68k::CMP16dj:
    case M68k::CMP32dj: {
      if (Scratch.getBitWidth() < 3) { Scratch = Scratch.zext(3); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: mem
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: reg
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      break;
    }
    case M68k::CASARI8:
    case M68k::CASARI16:
    case M68k::CASARI32: {
      if (Scratch.getBitWidth() < 3) { Scratch = Scratch.zext(3); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: mem
      getMachineOpValue(MI, MI.getOperand(3), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: dc
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 16);
      Scratch.clearAllBits();
      // op: du
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/22, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 22);
      break;
    }
    case M68k::SDIVd32d32:
    case M68k::SMULd32d32:
    case M68k::UDIVd32d32:
    case M68k::UMULd32d32: {
      if (Scratch.getBitWidth() < 3) { Scratch = Scratch.zext(3); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: opd
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/28, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 28);
      break;
    }
    case M68k::ADD8dd:
    case M68k::ADD8dj:
    case M68k::ADD16dd:
    case M68k::ADD16dj:
    case M68k::ADD32aj:
    case M68k::ADD32dd:
    case M68k::ADD32dj:
    case M68k::ADDX8dd:
    case M68k::ADDX16dd:
    case M68k::ADDX32dd:
    case M68k::AND8dd:
    case M68k::AND8dj:
    case M68k::AND16dd:
    case M68k::AND16dj:
    case M68k::AND32dd:
    case M68k::AND32dj:
    case M68k::OR8dd:
    case M68k::OR8dj:
    case M68k::OR16dd:
    case M68k::OR16dj:
    case M68k::OR32dd:
    case M68k::OR32dj:
    case M68k::SDIVd32d16:
    case M68k::SMULd32d16:
    case M68k::SUB8dd:
    case M68k::SUB8dj:
    case M68k::SUB16dd:
    case M68k::SUB16dj:
    case M68k::SUB32aj:
    case M68k::SUB32dd:
    case M68k::SUB32dj:
    case M68k::SUBX8dd:
    case M68k::SUBX16dd:
    case M68k::SUBX32dd:
    case M68k::UDIVd32d16:
    case M68k::UMULd32d16: {
      if (Scratch.getBitWidth() < 3) { Scratch = Scratch.zext(3); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: opd
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      break;
    }
    case M68k::UNLK: {
      if (Scratch.getBitWidth() < 3) { Scratch = Scratch.zext(3); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: src
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      break;
    }
    case M68k::EXT16:
    case M68k::EXT32:
    case M68k::MOV16cd:
    case M68k::MOV16ce:
    case M68k::MOV16cj:
    case M68k::MOV16co:
    case M68k::MOV16sd:
    case M68k::MOV16se:
    case M68k::MOV16sj:
    case M68k::MOV16so: {
      if (Scratch.getBitWidth() < 3) { Scratch = Scratch.zext(3); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: src
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      break;
    }
    case M68k::FMOVE32fpcs_d:
    case M68k::FMOVE32fpi_a: {
      if (Scratch.getBitWidth() < 3) { Scratch = Scratch.zext(3); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: src
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: dst
      encodeFPSYSSelect(MI, /*OpIdx=*/0, /*Pos=*/26, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 26);
      break;
    }
    case M68k::MOV8dd:
    case M68k::MOV8de:
    case M68k::MOV8dj:
    case M68k::MOV8do:
    case M68k::MOV8ed:
    case M68k::MOV8ee:
    case M68k::MOV8ej:
    case M68k::MOV8eo:
    case M68k::MOV8jd:
    case M68k::MOV8je:
    case M68k::MOV8jj:
    case M68k::MOV8jo:
    case M68k::MOV8od:
    case M68k::MOV8oe:
    case M68k::MOV8oj:
    case M68k::MOV8oo:
    case M68k::MOV16aa:
    case M68k::MOV16ae:
    case M68k::MOV16ae_TC:
    case M68k::MOV16aj:
    case M68k::MOV16aj_TC:
    case M68k::MOV16ao:
    case M68k::MOV16ao_TC:
    case M68k::MOV16dd:
    case M68k::MOV16de:
    case M68k::MOV16dj:
    case M68k::MOV16do:
    case M68k::MOV16ea:
    case M68k::MOV16ed:
    case M68k::MOV16ee:
    case M68k::MOV16ej:
    case M68k::MOV16eo:
    case M68k::MOV16ja:
    case M68k::MOV16jd:
    case M68k::MOV16je:
    case M68k::MOV16jj:
    case M68k::MOV16jo:
    case M68k::MOV16oa:
    case M68k::MOV16od:
    case M68k::MOV16oe:
    case M68k::MOV16oj:
    case M68k::MOV16oo:
    case M68k::MOV32aa:
    case M68k::MOV32ae:
    case M68k::MOV32ae_TC:
    case M68k::MOV32aj:
    case M68k::MOV32aj_TC:
    case M68k::MOV32ao:
    case M68k::MOV32ao_TC:
    case M68k::MOV32dd:
    case M68k::MOV32de:
    case M68k::MOV32dj:
    case M68k::MOV32do:
    case M68k::MOV32ea:
    case M68k::MOV32ed:
    case M68k::MOV32ee:
    case M68k::MOV32ej:
    case M68k::MOV32eo:
    case M68k::MOV32ja:
    case M68k::MOV32jd:
    case M68k::MOV32je:
    case M68k::MOV32jj:
    case M68k::MOV32jo:
    case M68k::MOV32oa:
    case M68k::MOV32od:
    case M68k::MOV32oe:
    case M68k::MOV32oj:
    case M68k::MOV32oo: {
      if (Scratch.getBitWidth() < 3) { Scratch = Scratch.zext(3); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: src
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      break;
    }
    case M68k::BKPT: {
      if (Scratch.getBitWidth() < 3) { Scratch = Scratch.zext(3); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: vect
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      break;
    }
    case M68k::CASAL8:
    case M68k::CASAL16:
    case M68k::CASAL32: {
      if (Scratch.getBitWidth() < 32) { Scratch = Scratch.zext(32); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dc
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 16);
      Scratch.clearAllBits();
      // op: du
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/22, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 22);
      Scratch.clearAllBits();
      // op: mem
      encodeRelocImm<32>(MI, /*OpIdx=*/3, /*Pos=*/32, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(32, 0), 32);
      break;
    }
    case M68k::BRA32:
    case M68k::BSR32:
    case M68k::Bcc32:
    case M68k::Bcs32:
    case M68k::Beq32:
    case M68k::Bge32:
    case M68k::Bgt32:
    case M68k::Bhi32:
    case M68k::Ble32:
    case M68k::Bls32:
    case M68k::Blt32:
    case M68k::Bmi32:
    case M68k::Bne32:
    case M68k::Bpl32:
    case M68k::Bvc32:
    case M68k::Bvs32: {
      if (Scratch.getBitWidth() < 32) { Scratch = Scratch.zext(32); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst
      encodePCRelImm<32>(MI, /*OpIdx=*/0, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(32, 0), 16);
      break;
    }
    case M68k::CALLb:
    case M68k::MOV16bc:
    case M68k::MOV16bs: {
      if (Scratch.getBitWidth() < 32) { Scratch = Scratch.zext(32); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst
      encodeRelocImm<32>(MI, /*OpIdx=*/0, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(32, 0), 16);
      break;
    }
    case M68k::ADD32ji:
    case M68k::AND32ji:
    case M68k::OR32ji:
    case M68k::SUB32ji: {
      if (Scratch.getBitWidth() < 32) { Scratch = Scratch.zext(32); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: opd
      encodeRelocImm<32>(MI, /*OpIdx=*/1, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(32, 0), 16);
      break;
    }
    case M68k::XOR32di: {
      if (Scratch.getBitWidth() < 32) { Scratch = Scratch.zext(32); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: opd
      encodeRelocImm<32>(MI, /*OpIdx=*/2, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(32, 0), 16);
      break;
    }
    case M68k::MOV16rb:
    case M68k::MOV16rb_TC:
    case M68k::MOV32rb:
    case M68k::MOV32rb_TC:
    case M68k::MOV32ri: {
      if (Scratch.getBitWidth() < 32) { Scratch = Scratch.zext(32); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/6, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(1, 3), 6);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      Scratch.clearAllBits();
      // op: src
      encodeRelocImm<32>(MI, /*OpIdx=*/1, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(32, 0), 16);
      break;
    }
    case M68k::ADD32ab:
    case M68k::ADD32ai:
    case M68k::ADD32di:
    case M68k::AND32di:
    case M68k::OR32di:
    case M68k::SUB32ab:
    case M68k::SUB32ai:
    case M68k::SUB32di: {
      if (Scratch.getBitWidth() < 32) { Scratch = Scratch.zext(32); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      Scratch.clearAllBits();
      // op: opd
      encodeRelocImm<32>(MI, /*OpIdx=*/2, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(32, 0), 16);
      break;
    }
    case M68k::LEA32b:
    case M68k::MOV8db:
    case M68k::MOV8eb:
    case M68k::MOV8jb:
    case M68k::MOV8ob:
    case M68k::MOV16ab:
    case M68k::MOV16ab_TC:
    case M68k::MOV16db:
    case M68k::MOV16eb:
    case M68k::MOV16jb:
    case M68k::MOV16ob:
    case M68k::MOV32ab:
    case M68k::MOV32ab_TC:
    case M68k::MOV32ai:
    case M68k::MOV32db:
    case M68k::MOV32di:
    case M68k::MOV32eb:
    case M68k::MOV32ei:
    case M68k::MOV32jb:
    case M68k::MOV32ji:
    case M68k::MOV32ob:
    case M68k::MOV32oi: {
      if (Scratch.getBitWidth() < 32) { Scratch = Scratch.zext(32); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      Scratch.clearAllBits();
      // op: src
      encodeRelocImm<32>(MI, /*OpIdx=*/1, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(32, 0), 16);
      break;
    }
    case M68k::LEA32L:
    case M68k::LEA32l: {
      if (Scratch.getBitWidth() < 32) { Scratch = Scratch.zext(32); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      Scratch.clearAllBits();
      // op: src.index
      encodeIndexSuppress(MI, /*OpIdx=*/2, /*Pos=*/22, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(1, 4), 22);
      Scratch.clearAllBits();
      // op: src.scale
      encodeScale(MI, /*OpIdx=*/3, /*Pos=*/25, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(2, 0), 25);
      Scratch.clearAllBits();
      // op: src.index
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/28, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 28);
      Scratch.clearAllBits();
      // op: src.disp
      encodePCRelImm<32>(MI, /*OpIdx=*/1, /*Pos=*/32, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(32, 0), 32);
      break;
    }
    case M68k::CALLl: {
      if (Scratch.getBitWidth() < 32) { Scratch = Scratch.zext(32); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst.index
      encodeIndexSuppress(MI, /*OpIdx=*/1, /*Pos=*/22, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(1, 4), 22);
      Scratch.clearAllBits();
      // op: dst.scale
      encodeScale(MI, /*OpIdx=*/2, /*Pos=*/25, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(2, 0), 25);
      Scratch.clearAllBits();
      // op: dst.index
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/28, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 28);
      Scratch.clearAllBits();
      // op: dst.disp
      encodePCRelImm<32>(MI, /*OpIdx=*/0, /*Pos=*/32, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(32, 0), 32);
      break;
    }
    case M68k::ADD32pi:
    case M68k::AND32pi:
    case M68k::OR32pi:
    case M68k::SUB32pi: {
      if (Scratch.getBitWidth() < 32) { Scratch = Scratch.zext(32); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst.reg
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: opd
      encodeRelocImm<32>(MI, /*OpIdx=*/2, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(32, 0), 16);
      Scratch.clearAllBits();
      // op: dst.disp
      encodeRelocImm<16>(MI, /*OpIdx=*/0, /*Pos=*/48, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 48);
      break;
    }
    case M68k::ADD32fi:
    case M68k::AND32fi:
    case M68k::OR32fi:
    case M68k::SUB32fi: {
      if (Scratch.getBitWidth() < 32) { Scratch = Scratch.zext(32); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst.reg
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: opd
      encodeRelocImm<32>(MI, /*OpIdx=*/3, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(32, 0), 16);
      Scratch.clearAllBits();
      // op: dst.disp
      encodeRelocImm<8>(MI, /*OpIdx=*/0, /*Pos=*/48, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 48);
      Scratch.clearAllBits();
      // op: dst.index
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/60, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 60);
      break;
    }
    case M68k::MOV8pb:
    case M68k::MOV16pb:
    case M68k::MOV32pb:
    case M68k::MOV32pi: {
      if (Scratch.getBitWidth() < 32) { Scratch = Scratch.zext(32); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst.reg
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      Scratch.clearAllBits();
      // op: src
      encodeRelocImm<32>(MI, /*OpIdx=*/2, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(32, 0), 16);
      Scratch.clearAllBits();
      // op: dst.disp
      encodeRelocImm<16>(MI, /*OpIdx=*/0, /*Pos=*/48, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 48);
      break;
    }
    case M68k::MOV8fb:
    case M68k::MOV16fb:
    case M68k::MOV32fb:
    case M68k::MOV32fi: {
      if (Scratch.getBitWidth() < 32) { Scratch = Scratch.zext(32); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst.reg
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      Scratch.clearAllBits();
      // op: src
      encodeRelocImm<32>(MI, /*OpIdx=*/3, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(32, 0), 16);
      Scratch.clearAllBits();
      // op: dst.disp
      encodeRelocImm<8>(MI, /*OpIdx=*/0, /*Pos=*/48, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 48);
      Scratch.clearAllBits();
      // op: dst.index
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/60, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 60);
      break;
    }
    case M68k::CMP16bi: {
      if (Scratch.getBitWidth() < 32) { Scratch = Scratch.zext(32); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: imm
      encodeRelocImm<16>(MI, /*OpIdx=*/0, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      Scratch.clearAllBits();
      // op: abs
      encodeRelocImm<32>(MI, /*OpIdx=*/1, /*Pos=*/32, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(32, 0), 32);
      break;
    }
    case M68k::CMP32bi: {
      if (Scratch.getBitWidth() < 32) { Scratch = Scratch.zext(32); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: imm
      encodeRelocImm<32>(MI, /*OpIdx=*/0, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(32, 0), 16);
      Scratch.clearAllBits();
      // op: abs
      encodeRelocImm<32>(MI, /*OpIdx=*/1, /*Pos=*/48, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(32, 0), 48);
      break;
    }
    case M68k::CMP32qi: {
      if (Scratch.getBitWidth() < 32) { Scratch = Scratch.zext(32); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: imm
      encodeRelocImm<32>(MI, /*OpIdx=*/0, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(32, 0), 16);
      Scratch.clearAllBits();
      // op: mem
      encodePCRelImm<16>(MI, /*OpIdx=*/1, /*Pos=*/48, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 48);
      break;
    }
    case M68k::CMP32ki: {
      if (Scratch.getBitWidth() < 32) { Scratch = Scratch.zext(32); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: imm
      encodeRelocImm<32>(MI, /*OpIdx=*/0, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(32, 0), 16);
      Scratch.clearAllBits();
      // op: mem.disp
      encodePCRelImm<8>(MI, /*OpIdx=*/1, /*Pos=*/48, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 48);
      Scratch.clearAllBits();
      // op: mem.index
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/60, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 60);
      break;
    }
    case M68k::CMP8bi: {
      if (Scratch.getBitWidth() < 32) { Scratch = Scratch.zext(32); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: imm
      encodeRelocImm<8>(MI, /*OpIdx=*/0, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 16);
      Scratch.clearAllBits();
      // op: abs
      encodeRelocImm<32>(MI, /*OpIdx=*/1, /*Pos=*/32, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(32, 0), 32);
      break;
    }
    case M68k::MOVM16mb:
    case M68k::MOVM32mb: {
      if (Scratch.getBitWidth() < 32) { Scratch = Scratch.zext(32); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: mask
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      Scratch.clearAllBits();
      // op: src
      encodeRelocImm<32>(MI, /*OpIdx=*/1, /*Pos=*/32, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(32, 0), 32);
      break;
    }
    case M68k::MOVM16bm:
    case M68k::MOVM32bm: {
      if (Scratch.getBitWidth() < 32) { Scratch = Scratch.zext(32); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: mask
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      Scratch.clearAllBits();
      // op: dst
      encodeRelocImm<32>(MI, /*OpIdx=*/0, /*Pos=*/32, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(32, 0), 32);
      break;
    }
    case M68k::CMP32ji: {
      if (Scratch.getBitWidth() < 32) { Scratch = Scratch.zext(32); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: mem
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: imm
      encodeRelocImm<32>(MI, /*OpIdx=*/0, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(32, 0), 16);
      break;
    }
    case M68k::CMP32pi: {
      if (Scratch.getBitWidth() < 32) { Scratch = Scratch.zext(32); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: mem.reg
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: imm
      encodeRelocImm<32>(MI, /*OpIdx=*/0, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(32, 0), 16);
      Scratch.clearAllBits();
      // op: mem.disp
      encodeRelocImm<16>(MI, /*OpIdx=*/1, /*Pos=*/48, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 48);
      break;
    }
    case M68k::CMP32fi: {
      if (Scratch.getBitWidth() < 32) { Scratch = Scratch.zext(32); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: mem.reg
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: imm
      encodeRelocImm<32>(MI, /*OpIdx=*/0, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(32, 0), 16);
      Scratch.clearAllBits();
      // op: mem.disp
      encodeRelocImm<8>(MI, /*OpIdx=*/1, /*Pos=*/48, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 48);
      Scratch.clearAllBits();
      // op: mem.index
      getMachineOpValue(MI, MI.getOperand(3), /*Pos=*/60, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 60);
      break;
    }
    case M68k::CMP32di: {
      if (Scratch.getBitWidth() < 32) { Scratch = Scratch.zext(32); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: reg
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: imm
      encodeRelocImm<32>(MI, /*OpIdx=*/0, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(32, 0), 16);
      break;
    }
    case M68k::MOV8bq:
    case M68k::MOV16bq:
    case M68k::MOV32bq: {
      if (Scratch.getBitWidth() < 32) { Scratch = Scratch.zext(32); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: src
      encodePCRelImm<16>(MI, /*OpIdx=*/1, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      Scratch.clearAllBits();
      // op: dst
      encodeRelocImm<32>(MI, /*OpIdx=*/0, /*Pos=*/32, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(32, 0), 32);
      break;
    }
    case M68k::MOV16bi: {
      if (Scratch.getBitWidth() < 32) { Scratch = Scratch.zext(32); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: src
      encodeRelocImm<16>(MI, /*OpIdx=*/1, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      Scratch.clearAllBits();
      // op: dst
      encodeRelocImm<32>(MI, /*OpIdx=*/0, /*Pos=*/32, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(32, 0), 32);
      break;
    }
    case M68k::MOV16cb:
    case M68k::MOV16sb: {
      if (Scratch.getBitWidth() < 32) { Scratch = Scratch.zext(32); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: src
      encodeRelocImm<32>(MI, /*OpIdx=*/1, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(32, 0), 16);
      break;
    }
    case M68k::MOV8bb:
    case M68k::MOV16bb:
    case M68k::MOV32bb:
    case M68k::MOV32bi: {
      if (Scratch.getBitWidth() < 32) { Scratch = Scratch.zext(32); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: src
      encodeRelocImm<32>(MI, /*OpIdx=*/1, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(32, 0), 16);
      Scratch.clearAllBits();
      // op: dst
      encodeRelocImm<32>(MI, /*OpIdx=*/0, /*Pos=*/48, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(32, 0), 48);
      break;
    }
    case M68k::MOV8bi: {
      if (Scratch.getBitWidth() < 32) { Scratch = Scratch.zext(32); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: src
      encodeRelocImm<8>(MI, /*OpIdx=*/1, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 16);
      Scratch.clearAllBits();
      // op: dst
      encodeRelocImm<32>(MI, /*OpIdx=*/0, /*Pos=*/32, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(32, 0), 32);
      break;
    }
    case M68k::LINK32: {
      if (Scratch.getBitWidth() < 32) { Scratch = Scratch.zext(32); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: src
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: disp
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 16), 16);
      Scratch.clearAllBits();
      // op: disp
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/32, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 32);
      break;
    }
    case M68k::MOV8bd:
    case M68k::MOV8be:
    case M68k::MOV8bj:
    case M68k::MOV8bo:
    case M68k::MOV16ba:
    case M68k::MOV16bd:
    case M68k::MOV16be:
    case M68k::MOV16bj:
    case M68k::MOV16bo:
    case M68k::MOV32ba:
    case M68k::MOV32bd:
    case M68k::MOV32be:
    case M68k::MOV32bj:
    case M68k::MOV32bo: {
      if (Scratch.getBitWidth() < 32) { Scratch = Scratch.zext(32); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: src
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: dst
      encodeRelocImm<32>(MI, /*OpIdx=*/0, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(32, 0), 16);
      break;
    }
    case M68k::MOV16br:
    case M68k::MOV32br: {
      if (Scratch.getBitWidth() < 32) { Scratch = Scratch.zext(32); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: src
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: src
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/3, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(1, 3), 3);
      Scratch.clearAllBits();
      // op: dst
      encodeRelocImm<32>(MI, /*OpIdx=*/0, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(32, 0), 16);
      break;
    }
    case M68k::MOV8bk:
    case M68k::MOV16bk:
    case M68k::MOV32bk: {
      if (Scratch.getBitWidth() < 32) { Scratch = Scratch.zext(32); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: src.disp
      encodePCRelImm<8>(MI, /*OpIdx=*/1, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 16);
      Scratch.clearAllBits();
      // op: src.index
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/28, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 28);
      Scratch.clearAllBits();
      // op: dst
      encodeRelocImm<32>(MI, /*OpIdx=*/0, /*Pos=*/32, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(32, 0), 32);
      break;
    }
    case M68k::MOV8bp:
    case M68k::MOV16bp:
    case M68k::MOV32bp: {
      if (Scratch.getBitWidth() < 32) { Scratch = Scratch.zext(32); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: src.reg
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: src.disp
      encodeRelocImm<16>(MI, /*OpIdx=*/1, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(16, 0), 16);
      Scratch.clearAllBits();
      // op: dst
      encodeRelocImm<32>(MI, /*OpIdx=*/0, /*Pos=*/32, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(32, 0), 32);
      break;
    }
    case M68k::MOV8bf:
    case M68k::MOV16bf:
    case M68k::MOV32bf: {
      if (Scratch.getBitWidth() < 32) { Scratch = Scratch.zext(32); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: src.reg
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: src.disp
      encodeRelocImm<8>(MI, /*OpIdx=*/1, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 16);
      Scratch.clearAllBits();
      // op: src.index
      getMachineOpValue(MI, MI.getOperand(3), /*Pos=*/28, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 28);
      Scratch.clearAllBits();
      // op: dst
      encodeRelocImm<32>(MI, /*OpIdx=*/0, /*Pos=*/32, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(32, 0), 32);
      break;
    }
    case M68k::NEG8d:
    case M68k::NEG16d:
    case M68k::NEG32d:
    case M68k::NEGX8d:
    case M68k::NEGX16d:
    case M68k::NEGX32d:
    case M68k::NOT8d:
    case M68k::NOT16d:
    case M68k::NOT32d:
    case M68k::SETd8cc:
    case M68k::SETd8cs:
    case M68k::SETd8eq:
    case M68k::SETd8f:
    case M68k::SETd8ge:
    case M68k::SETd8gt:
    case M68k::SETd8hi:
    case M68k::SETd8le:
    case M68k::SETd8ls:
    case M68k::SETd8lt:
    case M68k::SETd8mi:
    case M68k::SETd8ne:
    case M68k::SETd8pl:
    case M68k::SETd8t:
    case M68k::SETd8vc:
    case M68k::SETd8vs: {
      if (Scratch.getBitWidth() < 4) { Scratch = Scratch.zext(4); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 0);
      break;
    }
    case M68k::BCHG32dd:
    case M68k::BCLR32dd:
    case M68k::BSET32dd:
    case M68k::BTST32dd: {
      if (Scratch.getBitWidth() < 4) { Scratch = Scratch.zext(4); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 0);
      Scratch.clearAllBits();
      // op: bitno
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      break;
    }
    case M68k::CMP8dd:
    case M68k::CMP16dr:
    case M68k::CMP32dr: {
      if (Scratch.getBitWidth() < 4) { Scratch = Scratch.zext(4); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: lhs
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 0);
      Scratch.clearAllBits();
      // op: rhs
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      break;
    }
    case M68k::ADD16dr:
    case M68k::ADD32ar:
    case M68k::ADD32dr:
    case M68k::AND16dr:
    case M68k::AND32dr:
    case M68k::OR16dr:
    case M68k::OR32dr:
    case M68k::SUB16dr:
    case M68k::SUB32ar:
    case M68k::SUB32dr: {
      if (Scratch.getBitWidth() < 4) { Scratch = Scratch.zext(4); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: opd
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 0);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      break;
    }
    case M68k::MOV16ra:
    case M68k::MOV16re:
    case M68k::MOV16re_TC:
    case M68k::MOV16rj:
    case M68k::MOV16rj_TC:
    case M68k::MOV16ro:
    case M68k::MOV16ro_TC:
    case M68k::MOV32ra:
    case M68k::MOV32re:
    case M68k::MOV32re_TC:
    case M68k::MOV32rj:
    case M68k::MOV32rj_TC:
    case M68k::MOV32ro:
    case M68k::MOV32ro_TC: {
      if (Scratch.getBitWidth() < 4) { Scratch = Scratch.zext(4); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: src
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/6, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(1, 3), 6);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      break;
    }
    case M68k::MOV16rr:
    case M68k::MOV32rr: {
      if (Scratch.getBitWidth() < 4) { Scratch = Scratch.zext(4); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: src
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: src
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/3, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(1, 3), 3);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/6, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(1, 3), 6);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      break;
    }
    case M68k::MOV16ar:
    case M68k::MOV16er:
    case M68k::MOV16jr:
    case M68k::MOV16or:
    case M68k::MOV32ar:
    case M68k::MOV32er:
    case M68k::MOV32jr:
    case M68k::MOV32or: {
      if (Scratch.getBitWidth() < 4) { Scratch = Scratch.zext(4); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: src
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: src
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/3, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(1, 3), 3);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      break;
    }
    case M68k::TRAP: {
      if (Scratch.getBitWidth() < 4) { Scratch = Scratch.zext(4); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: vect
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 0);
      break;
    }
    case M68k::BTST8ki: {
      if (Scratch.getBitWidth() < 8) { Scratch = Scratch.zext(8); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: bitno
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 16);
      Scratch.clearAllBits();
      // op: dst.disp
      encodePCRelImm<8>(MI, /*OpIdx=*/0, /*Pos=*/32, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 32);
      Scratch.clearAllBits();
      // op: dst.index
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/44, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 44);
      break;
    }
    case M68k::BTST8kd: {
      if (Scratch.getBitWidth() < 8) { Scratch = Scratch.zext(8); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: bitno
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      Scratch.clearAllBits();
      // op: dst.disp
      encodePCRelImm<8>(MI, /*OpIdx=*/0, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 16);
      Scratch.clearAllBits();
      // op: dst.index
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/28, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 28);
      break;
    }
    case M68k::BRA8:
    case M68k::BSR8:
    case M68k::Bcc8:
    case M68k::Bcs8:
    case M68k::Beq8:
    case M68k::Bge8:
    case M68k::Bgt8:
    case M68k::Bhi8:
    case M68k::Ble8:
    case M68k::Bls8:
    case M68k::Blt8:
    case M68k::Bmi8:
    case M68k::Bne8:
    case M68k::Bpl8:
    case M68k::Bvc8:
    case M68k::Bvs8: {
      if (Scratch.getBitWidth() < 8) { Scratch = Scratch.zext(8); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst
      encodePCRelImm<8>(MI, /*OpIdx=*/0, /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 0);
      break;
    }
    case M68k::BCHG8ei:
    case M68k::BCHG8ji:
    case M68k::BCHG8oi:
    case M68k::BCLR8ei:
    case M68k::BCLR8ji:
    case M68k::BCLR8oi:
    case M68k::BSET8ei:
    case M68k::BSET8ji:
    case M68k::BSET8oi:
    case M68k::BTST8ei:
    case M68k::BTST8ji:
    case M68k::BTST8oi: {
      if (Scratch.getBitWidth() < 8) { Scratch = Scratch.zext(8); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: bitno
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 16);
      break;
    }
    case M68k::ADD8ji:
    case M68k::AND8ji:
    case M68k::OR8ji:
    case M68k::SUB8ji: {
      if (Scratch.getBitWidth() < 8) { Scratch = Scratch.zext(8); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: opd
      encodeRelocImm<8>(MI, /*OpIdx=*/1, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 16);
      break;
    }
    case M68k::XOR8di: {
      if (Scratch.getBitWidth() < 8) { Scratch = Scratch.zext(8); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: opd
      encodeRelocImm<8>(MI, /*OpIdx=*/2, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 16);
      break;
    }
    case M68k::BCHG32di:
    case M68k::BCLR32di:
    case M68k::BSET32di:
    case M68k::BTST32di: {
      if (Scratch.getBitWidth() < 8) { Scratch = Scratch.zext(8); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 0);
      Scratch.clearAllBits();
      // op: bitno
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 16);
      break;
    }
    case M68k::MOV16rk:
    case M68k::MOV16rk_TC:
    case M68k::MOV32rk:
    case M68k::MOV32rk_TC: {
      if (Scratch.getBitWidth() < 8) { Scratch = Scratch.zext(8); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/6, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(1, 3), 6);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      Scratch.clearAllBits();
      // op: src.disp
      encodePCRelImm<8>(MI, /*OpIdx=*/1, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 16);
      Scratch.clearAllBits();
      // op: src.index
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/28, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 28);
      break;
    }
    case M68k::ADD8di:
    case M68k::AND8di:
    case M68k::OR8di:
    case M68k::SUB8di: {
      if (Scratch.getBitWidth() < 8) { Scratch = Scratch.zext(8); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      Scratch.clearAllBits();
      // op: opd
      encodeRelocImm<8>(MI, /*OpIdx=*/2, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 16);
      break;
    }
    case M68k::ADD8dk:
    case M68k::ADD16dk:
    case M68k::ADD32ak:
    case M68k::ADD32dk:
    case M68k::AND8dk:
    case M68k::AND16dk:
    case M68k::AND32dk:
    case M68k::OR8dk:
    case M68k::OR16dk:
    case M68k::OR32dk:
    case M68k::SUB8dk:
    case M68k::SUB16dk:
    case M68k::SUB32ak:
    case M68k::SUB32dk: {
      if (Scratch.getBitWidth() < 8) { Scratch = Scratch.zext(8); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      Scratch.clearAllBits();
      // op: opd.disp
      encodePCRelImm<8>(MI, /*OpIdx=*/2, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 16);
      Scratch.clearAllBits();
      // op: opd.index
      getMachineOpValue(MI, MI.getOperand(3), /*Pos=*/28, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 28);
      break;
    }
    case M68k::MOV8di:
    case M68k::MOV8ei:
    case M68k::MOV8ji:
    case M68k::MOV8oi: {
      if (Scratch.getBitWidth() < 8) { Scratch = Scratch.zext(8); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      Scratch.clearAllBits();
      // op: src
      encodeRelocImm<8>(MI, /*OpIdx=*/1, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 16);
      break;
    }
    case M68k::LEA32k:
    case M68k::MOV8dk:
    case M68k::MOV8ek:
    case M68k::MOV8jk:
    case M68k::MOV8ok:
    case M68k::MOV16ak:
    case M68k::MOV16ak_TC:
    case M68k::MOV16dk:
    case M68k::MOV16ek:
    case M68k::MOV16jk:
    case M68k::MOV16ok:
    case M68k::MOV32ak:
    case M68k::MOV32ak_TC:
    case M68k::MOV32dk:
    case M68k::MOV32ek:
    case M68k::MOV32jk:
    case M68k::MOV32ok: {
      if (Scratch.getBitWidth() < 8) { Scratch = Scratch.zext(8); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      Scratch.clearAllBits();
      // op: src.disp
      encodePCRelImm<8>(MI, /*OpIdx=*/1, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 16);
      Scratch.clearAllBits();
      // op: src.index
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/28, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 28);
      break;
    }
    case M68k::CALLk: {
      if (Scratch.getBitWidth() < 8) { Scratch = Scratch.zext(8); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst.disp
      encodePCRelImm<8>(MI, /*OpIdx=*/0, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 16);
      Scratch.clearAllBits();
      // op: dst.index
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/28, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 28);
      break;
    }
    case M68k::BCHG8fi:
    case M68k::BCLR8fi:
    case M68k::BSET8fi:
    case M68k::BTST8fi: {
      if (Scratch.getBitWidth() < 8) { Scratch = Scratch.zext(8); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst.reg
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: bitno
      getMachineOpValue(MI, MI.getOperand(3), /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 16);
      Scratch.clearAllBits();
      // op: dst.disp
      encodeRelocImm<8>(MI, /*OpIdx=*/0, /*Pos=*/32, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 32);
      Scratch.clearAllBits();
      // op: dst.index
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/44, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 44);
      break;
    }
    case M68k::BCHG8fd:
    case M68k::BCLR8fd:
    case M68k::BSET8fd:
    case M68k::BTST8fd: {
      if (Scratch.getBitWidth() < 8) { Scratch = Scratch.zext(8); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst.reg
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: bitno
      getMachineOpValue(MI, MI.getOperand(3), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      Scratch.clearAllBits();
      // op: dst.disp
      encodeRelocImm<8>(MI, /*OpIdx=*/0, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 16);
      Scratch.clearAllBits();
      // op: dst.index
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/28, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 28);
      break;
    }
    case M68k::CALLf:
    case M68k::MOV16fc:
    case M68k::MOV16fs: {
      if (Scratch.getBitWidth() < 8) { Scratch = Scratch.zext(8); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst.reg
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: dst.disp
      encodeRelocImm<8>(MI, /*OpIdx=*/0, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 16);
      Scratch.clearAllBits();
      // op: dst.index
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/28, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 28);
      break;
    }
    case M68k::ADD8fi:
    case M68k::AND8fi:
    case M68k::OR8fi:
    case M68k::SUB8fi: {
      if (Scratch.getBitWidth() < 8) { Scratch = Scratch.zext(8); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst.reg
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: opd
      encodeRelocImm<8>(MI, /*OpIdx=*/3, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 16);
      Scratch.clearAllBits();
      // op: dst.disp
      encodeRelocImm<8>(MI, /*OpIdx=*/0, /*Pos=*/32, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 32);
      Scratch.clearAllBits();
      // op: dst.index
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/44, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 44);
      break;
    }
    case M68k::ADD8fd:
    case M68k::ADD16fd:
    case M68k::ADD32fd:
    case M68k::AND8fd:
    case M68k::AND16fd:
    case M68k::AND32fd:
    case M68k::OR8fd:
    case M68k::OR16fd:
    case M68k::OR32fd:
    case M68k::SUB8fd:
    case M68k::SUB16fd:
    case M68k::SUB32fd: {
      if (Scratch.getBitWidth() < 8) { Scratch = Scratch.zext(8); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst.reg
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: opd
      getMachineOpValue(MI, MI.getOperand(3), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      Scratch.clearAllBits();
      // op: dst.disp
      encodeRelocImm<8>(MI, /*OpIdx=*/0, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 16);
      Scratch.clearAllBits();
      // op: dst.index
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/28, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 28);
      break;
    }
    case M68k::MOV8fi: {
      if (Scratch.getBitWidth() < 8) { Scratch = Scratch.zext(8); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst.reg
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      Scratch.clearAllBits();
      // op: src
      encodeRelocImm<8>(MI, /*OpIdx=*/3, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 16);
      Scratch.clearAllBits();
      // op: dst.disp
      encodeRelocImm<8>(MI, /*OpIdx=*/0, /*Pos=*/32, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 32);
      Scratch.clearAllBits();
      // op: dst.index
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/44, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 44);
      break;
    }
    case M68k::MOV8fk:
    case M68k::MOV16fk:
    case M68k::MOV32fk: {
      if (Scratch.getBitWidth() < 8) { Scratch = Scratch.zext(8); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: dst.reg
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      Scratch.clearAllBits();
      // op: src.disp
      encodePCRelImm<8>(MI, /*OpIdx=*/3, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 16);
      Scratch.clearAllBits();
      // op: src.index
      getMachineOpValue(MI, MI.getOperand(4), /*Pos=*/28, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 28);
      Scratch.clearAllBits();
      // op: dst.disp
      encodeRelocImm<8>(MI, /*OpIdx=*/0, /*Pos=*/32, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 32);
      Scratch.clearAllBits();
      // op: dst.index
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/44, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 44);
      break;
    }
    case M68k::CMP8ki: {
      if (Scratch.getBitWidth() < 8) { Scratch = Scratch.zext(8); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: imm
      encodeRelocImm<8>(MI, /*OpIdx=*/0, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 16);
      Scratch.clearAllBits();
      // op: mem.disp
      encodePCRelImm<8>(MI, /*OpIdx=*/1, /*Pos=*/32, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 32);
      Scratch.clearAllBits();
      // op: mem.index
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/44, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 44);
      break;
    }
    case M68k::MOVQ: {
      if (Scratch.getBitWidth() < 8) { Scratch = Scratch.zext(8); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: imm
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 0);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      break;
    }
    case M68k::CMP8ji: {
      if (Scratch.getBitWidth() < 8) { Scratch = Scratch.zext(8); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: mem
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: imm
      encodeRelocImm<8>(MI, /*OpIdx=*/0, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 16);
      break;
    }
    case M68k::CMP8fi: {
      if (Scratch.getBitWidth() < 8) { Scratch = Scratch.zext(8); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: mem.reg
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: imm
      encodeRelocImm<8>(MI, /*OpIdx=*/0, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 16);
      Scratch.clearAllBits();
      // op: mem.disp
      encodeRelocImm<8>(MI, /*OpIdx=*/1, /*Pos=*/32, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 32);
      Scratch.clearAllBits();
      // op: mem.index
      getMachineOpValue(MI, MI.getOperand(3), /*Pos=*/44, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 44);
      break;
    }
    case M68k::CMP8df:
    case M68k::CMP16df:
    case M68k::CMP32df: {
      if (Scratch.getBitWidth() < 8) { Scratch = Scratch.zext(8); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: mem.reg
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: reg
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      Scratch.clearAllBits();
      // op: mem.disp
      encodeRelocImm<8>(MI, /*OpIdx=*/1, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 16);
      Scratch.clearAllBits();
      // op: mem.index
      getMachineOpValue(MI, MI.getOperand(3), /*Pos=*/28, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 28);
      break;
    }
    case M68k::CASARII8:
    case M68k::CASARII16:
    case M68k::CASARII32: {
      if (Scratch.getBitWidth() < 8) { Scratch = Scratch.zext(8); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: mem.reg
      getMachineOpValue(MI, MI.getOperand(4), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: dc
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 16);
      Scratch.clearAllBits();
      // op: du
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/22, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 22);
      Scratch.clearAllBits();
      // op: mem.disp
      encodeRelocImm<8>(MI, /*OpIdx=*/3, /*Pos=*/32, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 32);
      Scratch.clearAllBits();
      // op: mem.index
      getMachineOpValue(MI, MI.getOperand(5), /*Pos=*/44, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 44);
      break;
    }
    case M68k::ADD8df:
    case M68k::ADD16df:
    case M68k::ADD32af:
    case M68k::ADD32df:
    case M68k::AND8df:
    case M68k::AND16df:
    case M68k::AND32df:
    case M68k::OR8df:
    case M68k::OR16df:
    case M68k::OR32df:
    case M68k::SUB8df:
    case M68k::SUB16df:
    case M68k::SUB32af:
    case M68k::SUB32df: {
      if (Scratch.getBitWidth() < 8) { Scratch = Scratch.zext(8); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: opd.reg
      getMachineOpValue(MI, MI.getOperand(3), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      Scratch.clearAllBits();
      // op: opd.disp
      encodeRelocImm<8>(MI, /*OpIdx=*/2, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 16);
      Scratch.clearAllBits();
      // op: opd.index
      getMachineOpValue(MI, MI.getOperand(4), /*Pos=*/28, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 28);
      break;
    }
    case M68k::CMP8dk:
    case M68k::CMP16dk:
    case M68k::CMP32dk: {
      if (Scratch.getBitWidth() < 8) { Scratch = Scratch.zext(8); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: reg
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      Scratch.clearAllBits();
      // op: mem.disp
      encodePCRelImm<8>(MI, /*OpIdx=*/1, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 16);
      Scratch.clearAllBits();
      // op: mem.index
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/28, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 28);
      break;
    }
    case M68k::CMP8di: {
      if (Scratch.getBitWidth() < 8) { Scratch = Scratch.zext(8); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: reg
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: imm
      encodeRelocImm<8>(MI, /*OpIdx=*/0, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 16);
      break;
    }
    case M68k::MOV8fd:
    case M68k::MOV8fe:
    case M68k::MOV8fj:
    case M68k::MOV8fo:
    case M68k::MOV16fa:
    case M68k::MOV16fd:
    case M68k::MOV16fe:
    case M68k::MOV16fj:
    case M68k::MOV16fo:
    case M68k::MOV32fa:
    case M68k::MOV32fd:
    case M68k::MOV32fe:
    case M68k::MOV32fj:
    case M68k::MOV32fo: {
      if (Scratch.getBitWidth() < 8) { Scratch = Scratch.zext(8); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: src
      getMachineOpValue(MI, MI.getOperand(3), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: dst.reg
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      Scratch.clearAllBits();
      // op: dst.disp
      encodeRelocImm<8>(MI, /*OpIdx=*/0, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 16);
      Scratch.clearAllBits();
      // op: dst.index
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/28, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 28);
      break;
    }
    case M68k::MOV16fr:
    case M68k::MOV32fr: {
      if (Scratch.getBitWidth() < 8) { Scratch = Scratch.zext(8); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: src
      getMachineOpValue(MI, MI.getOperand(3), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: src
      getMachineOpValue(MI, MI.getOperand(3), /*Pos=*/3, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(1, 3), 3);
      Scratch.clearAllBits();
      // op: dst.reg
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      Scratch.clearAllBits();
      // op: dst.disp
      encodeRelocImm<8>(MI, /*OpIdx=*/0, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 16);
      Scratch.clearAllBits();
      // op: dst.index
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/28, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 28);
      break;
    }
    case M68k::MOV16ck:
    case M68k::MOV16sk: {
      if (Scratch.getBitWidth() < 8) { Scratch = Scratch.zext(8); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: src.disp
      encodePCRelImm<8>(MI, /*OpIdx=*/1, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 16);
      Scratch.clearAllBits();
      // op: src.index
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/28, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 28);
      break;
    }
    case M68k::MOV16rf:
    case M68k::MOV16rf_TC:
    case M68k::MOV32rf:
    case M68k::MOV32rf_TC: {
      if (Scratch.getBitWidth() < 8) { Scratch = Scratch.zext(8); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: src.reg
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/6, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(1, 3), 6);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      Scratch.clearAllBits();
      // op: src.disp
      encodeRelocImm<8>(MI, /*OpIdx=*/1, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 16);
      Scratch.clearAllBits();
      // op: src.index
      getMachineOpValue(MI, MI.getOperand(3), /*Pos=*/28, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 28);
      break;
    }
    case M68k::LEA32f:
    case M68k::MOV8df:
    case M68k::MOV8ef:
    case M68k::MOV8jf:
    case M68k::MOV8of:
    case M68k::MOV16af:
    case M68k::MOV16af_TC:
    case M68k::MOV16df:
    case M68k::MOV16ef:
    case M68k::MOV16jf:
    case M68k::MOV16of:
    case M68k::MOV32af:
    case M68k::MOV32af_TC:
    case M68k::MOV32df:
    case M68k::MOV32ef:
    case M68k::MOV32jf:
    case M68k::MOV32of: {
      if (Scratch.getBitWidth() < 8) { Scratch = Scratch.zext(8); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: src.reg
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: dst
      getMachineOpValue(MI, MI.getOperand(0), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      Scratch.clearAllBits();
      // op: src.disp
      encodeRelocImm<8>(MI, /*OpIdx=*/1, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 16);
      Scratch.clearAllBits();
      // op: src.index
      getMachineOpValue(MI, MI.getOperand(3), /*Pos=*/28, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 28);
      break;
    }
    case M68k::MOV16cf:
    case M68k::MOV16sf: {
      if (Scratch.getBitWidth() < 8) { Scratch = Scratch.zext(8); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: src.reg
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: src.disp
      encodeRelocImm<8>(MI, /*OpIdx=*/1, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 16);
      Scratch.clearAllBits();
      // op: src.index
      getMachineOpValue(MI, MI.getOperand(3), /*Pos=*/28, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 28);
      break;
    }
    case M68k::MOV8ff:
    case M68k::MOV16ff:
    case M68k::MOV32ff: {
      if (Scratch.getBitWidth() < 8) { Scratch = Scratch.zext(8); }
      Inst = getInstBits(opcode);
      Scratch.clearAllBits();
      // op: src.reg
      getMachineOpValue(MI, MI.getOperand(4), /*Pos=*/0, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 0);
      Scratch.clearAllBits();
      // op: dst.reg
      getMachineOpValue(MI, MI.getOperand(1), /*Pos=*/9, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(3, 0), 9);
      Scratch.clearAllBits();
      // op: src.disp
      encodeRelocImm<8>(MI, /*OpIdx=*/3, /*Pos=*/16, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 16);
      Scratch.clearAllBits();
      // op: src.index
      getMachineOpValue(MI, MI.getOperand(5), /*Pos=*/28, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 28);
      Scratch.clearAllBits();
      // op: dst.disp
      encodeRelocImm<8>(MI, /*OpIdx=*/0, /*Pos=*/32, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(8, 0), 32);
      Scratch.clearAllBits();
      // op: dst.index
      getMachineOpValue(MI, MI.getOperand(2), /*Pos=*/44, Scratch, Fixups, STI);
      Inst.insertBits(Scratch.extractBits(4, 0), 44);
      break;
    }
  default:
    reportUnsupportedInst(MI);
  }
}

