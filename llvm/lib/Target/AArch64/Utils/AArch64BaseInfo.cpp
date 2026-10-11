//===-- AArch64BaseInfo.cpp - AArch64 Base encoding information------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file provides basic encoding and assembly information for AArch64.
//
//===----------------------------------------------------------------------===//
#include "AArch64BaseInfo.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringExtras.h"
// #include "llvm/Support/Regex.h"

using namespace llvm_ks;

namespace llvm_ks {
  namespace AArch64AT {
#define GET_ATsList_IMPL
#include "AArch64GenSystemOperands.inc"
  }
}


namespace llvm_ks {
  namespace AArch64DBnXS {
#define GET_DBnXSsList_IMPL
#include "AArch64GenSystemOperands.inc"
  }
}

namespace llvm_ks {
  namespace AArch64DB {
#define GET_DBsList_IMPL
#include "AArch64GenSystemOperands.inc"
  }
}

namespace llvm_ks {
  namespace AArch64DC {
#define GET_DCsList_IMPL
#include "AArch64GenSystemOperands.inc"
  }
}

namespace llvm_ks {
  namespace AArch64IC {
#define GET_ICsList_IMPL
#include "AArch64GenSystemOperands.inc"
  }
}

namespace llvm_ks {
  namespace AArch64ISB {
#define GET_ISBsList_IMPL
#include "AArch64GenSystemOperands.inc"
  }
}

namespace llvm_ks {
  namespace AArch64PRFM {
#define GET_PRFMsList_IMPL
#include "AArch64GenSystemOperands.inc"
  }
}

namespace llvm_ks {
  namespace AArch64SVEPRFM {
#define GET_SVEPRFMsList_IMPL
#include "AArch64GenSystemOperands.inc"
  }
}

namespace llvm_ks {
  namespace AArch64RPRFM {
#define GET_RPRFMsList_IMPL
#include "AArch64GenSystemOperands.inc"
  } // namespace AArch64RPRFM
} // namespace llvm_ks

namespace llvm_ks {
  namespace AArch64SVEPredPattern {
#define GET_SVEPREDPATsList_IMPL
#include "AArch64GenSystemOperands.inc"
  }
}

namespace llvm_ks {
namespace AArch64SVEVecLenSpecifier {
#define GET_SVEVECLENSPECIFIERsList_IMPL
#include "AArch64GenSystemOperands.inc"
} // namespace AArch64SVEVecLenSpecifier
} // namespace llvm_ks

namespace llvm_ks {
  namespace AArch64ExactFPImm {
#define GET_ExactFPImmsList_IMPL
#include "AArch64GenSystemOperands.inc"
  }
}

namespace llvm_ks {
  namespace AArch64PState {
#define GET_PStateImm0_15sList_IMPL
#include "AArch64GenSystemOperands.inc"
#define GET_PStateImm0_1sList_IMPL
#include "AArch64GenSystemOperands.inc"
  }
}

namespace llvm_ks {
namespace AArch64TIndexHint {
#define GET_TINDEX_IMPL
#include "AArch64GenSystemOperands.inc"
} // namespace AArch64TIndexHint
} // namespace llvm_ks

namespace llvm_ks {
  namespace AArch64SysReg {
#define GET_SysRegsList_IMPL
#include "AArch64GenSystemOperands.inc"
  }
}

// Keystone(amaanq): I rewrote this function to get rid of the regex dependency
// - the regex was ^S([0-3])_([0-7])_C([0-9]|1[0-5])_C([0-9]|1[0-5])_([0-7])$
uint32_t AArch64SysReg::parseGenericRegister(StringRef Name) {
  // Try to parse an S<op0>_<op1>_<Cn>_<Cm>_<op2> register name
  std::string UpperName = Name.upper();
  StringRef S = UpperName;

  if (!S.consume_front("S"))
    return -1;

  SmallVector<StringRef, 5> Parts;
  S.split(Parts, '_');

  if (Parts.size() != 5)
    return -1;

  // Check format: should be digit, digit, C+digits, C+digits, digit
  if (Parts[0].size() != 1 || !isdigit(Parts[0][0]))
    return -1;
  if (Parts[1].size() != 1 || !isdigit(Parts[1][0]))
    return -1;
  if (!Parts[2].consume_front("C") || Parts[2].empty())
    return -1;
  if (!Parts[3].consume_front("C") || Parts[3].empty())
    return -1;
  if (Parts[4].size() != 1 || !isdigit(Parts[4][0]))
    return -1;

  uint32_t Op0, Op1, CRn, CRm, Op2;
  if (Parts[0].getAsInteger(10, Op0) || Op0 > 3)
    return -1;
  if (Parts[1].getAsInteger(10, Op1) || Op1 > 7)
    return -1;
  if (Parts[2].getAsInteger(10, CRn) || CRn > 15)
    return -1;
  if (Parts[3].getAsInteger(10, CRm) || CRm > 15)
    return -1;
  if (Parts[4].getAsInteger(10, Op2) || Op2 > 7)
    return -1;

  uint32_t Bits = (Op0 << 14) | (Op1 << 11) | (CRn << 7) | (CRm << 3) | Op2;
  return Bits;
}

std::string AArch64SysReg::genericRegisterString(uint32_t Bits) {
  assert(Bits < 0x10000);
  uint32_t Op0 = (Bits >> 14) & 0x3;
  uint32_t Op1 = (Bits >> 11) & 0x7;
  uint32_t CRn = (Bits >> 7) & 0xf;
  uint32_t CRm = (Bits >> 3) & 0xf;
  uint32_t Op2 = Bits & 0x7;

  return "S" + utostr(Op0) + "_" + utostr(Op1) + "_C" + utostr(CRn) + "_C" +
         utostr(CRm) + "_" + utostr(Op2);
}

namespace llvm_ks {
namespace AArch64TLBI {
#define GET_TLBITable_IMPL
#include "AArch64GenSystemOperands.inc"
} // namespace AArch64TLBI
} // namespace llvm_ks

namespace llvm_ks {
namespace AArch64PLBI {
#define GET_PLBITable_IMPL
#include "AArch64GenSystemOperands.inc"
} // namespace AArch64PLBI
} // namespace llvm_ks

namespace llvm_ks {
namespace AArch64TLBIP {
#define GET_TLBIPTable_IMPL
#include "AArch64GenSystemOperands.inc"
} // namespace AArch64TLBIP
} // namespace llvm_ks

namespace llvm_ks {
namespace AArch64GIC {
#define GET_GICTable_IMPL
#include "AArch64GenSystemOperands.inc"
} // namespace AArch64GIC
} // namespace llvm_ks

namespace llvm_ks {
namespace AArch64GICR {
#define GET_GICRTable_IMPL
#include "AArch64GenSystemOperands.inc"
} // namespace AArch64GICR
} // namespace llvm_ks

namespace llvm_ks {
namespace AArch64GSB {
#define GET_GSBTable_IMPL
#include "AArch64GenSystemOperands.inc"
} // namespace AArch64GSB
} // namespace llvm_ks

namespace llvm_ks {
  namespace AArch64SVCR {
#define GET_SVCRsList_IMPL
#include "AArch64GenSystemOperands.inc"
  }
}
