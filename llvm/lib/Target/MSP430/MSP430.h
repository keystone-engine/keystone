//==-- MSP430.h - Top-level interface for MSP430 representation --*- C++ -*-==//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains the entry points for global functions defined in
// the LLVM MSP430 backend.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIB_TARGET_MSP430_MSP430_H
#define LLVM_LIB_TARGET_MSP430_MSP430_H

#include "MCTargetDesc/MSP430MCTargetDesc.h"
#include "llvm/Support/TargetRegistry.h"

namespace MSP430CC {
    // MSP430 specific condition code.
    enum CondCodes {
        COND_E  = 0,  // aka COND_Z
        COND_NE = 1,  // aka COND_NZ
        COND_HS = 2,  // aka COND_C
        COND_LO = 3,  // aka COND_NC
        COND_GE = 4,
        COND_L  = 5,
        COND_N  = 6,  // jump if negative
        COND_NONE, // unconditional

        COND_INVALID = -1
    };
}

enum class DiagnosticPredicateTy {
    Match,
    NearMatch,
    NoMatch,
};

// When an operand is parsed, the assembler will try to iterate through a set of
// possible operand classes that the operand might match and call the
// corresponding PredicateMethod to determine that.
//
// If there are two AsmOperands that would give a specific diagnostic if there
// is no match, there is currently no mechanism to distinguish which operand is
// a closer match. The DiagnosticPredicate distinguishes between 'completely
// no match' and 'near match', so the assembler can decide whether to give a
// specific diagnostic, or use 'InvalidOperand' and continue to find a
// 'better matching' diagnostic.
//
// For example:
//    opcode opnd0, onpd1, opnd2
//
// where:
//    opnd2 could be an 'immediate of range [-8, 7]'
//    opnd2 could be a  'register + shift/extend'.
//
// If opnd2 is a valid register, but with a wrong shift/extend suffix, it makes
// little sense to give a diagnostic that the operand should be an immediate
// in range [-8, 7].
//
// This is a light-weight alternative to the 'NearMissInfo' approach
// below which collects *all* possible diagnostics. This alternative
// is optional and fully backward compatible with existing
// PredicateMethods that return a 'bool' (match or no match).
struct DiagnosticPredicate {
    DiagnosticPredicateTy Type;

    explicit DiagnosticPredicate(bool Match)
            : Type(Match ? DiagnosticPredicateTy::Match
                         : DiagnosticPredicateTy::NearMatch) {}
    DiagnosticPredicate(DiagnosticPredicateTy T) : Type(T) {}
    DiagnosticPredicate(const DiagnosticPredicate &) = default;

    operator bool() const { return Type == DiagnosticPredicateTy::Match; }
    bool isMatch() const { return Type == DiagnosticPredicateTy::Match; }
    bool isNearMatch() const { return Type == DiagnosticPredicateTy::NearMatch; }
    bool isNoMatch() const { return Type == DiagnosticPredicateTy::NoMatch; }
};

#endif
