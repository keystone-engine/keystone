#ifdef GET_REGINFO_ENUM
#undef GET_REGINFO_ENUM

#include "RISCVGenRegisterInfoEnums.inc"

#endif // GET_REGINFO_ENUM

#ifdef GET_REGINFO_MC_DESC
#undef GET_REGINFO_MC_DESC

#include "RISCVGenRegisterInfoMCDesc.inc"

#endif // GET_REGINFO_MC_DESC

#ifdef GET_REGINFO_HEADER
#undef GET_REGINFO_HEADER

#include "RISCVGenRegisterInfoHeader.inc"

#endif // GET_REGINFO_HEADER

#ifdef GET_REGINFO_TARGET_DESC
#undef GET_REGINFO_TARGET_DESC

#include "RISCVGenRegisterInfoTargetDesc.inc"

#endif // GET_REGINFO_TARGET_DESC

