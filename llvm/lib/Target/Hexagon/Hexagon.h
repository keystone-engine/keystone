//=-- Hexagon.h - Top-level interface for Hexagon representation --*- C++ -*-=//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains the entry points for global functions defined in the LLVM
// Hexagon back-end.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIB_TARGET_HEXAGON_HEXAGON_H
#define LLVM_LIB_TARGET_HEXAGON_HEXAGON_H

// Normal instruction size (in bytes).
#define HEXAGON_INSTR_SIZE 4

// Maximum number of words and instructions in a packet.
#define HEXAGON_PACKET_SIZE 4
#define HEXAGON_MAX_PACKET_SIZE (HEXAGON_PACKET_SIZE * HEXAGON_INSTR_SIZE)
// Minimum number of instructions in an end-loop packet.
#define HEXAGON_PACKET_INNER_SIZE 2
#define HEXAGON_PACKET_OUTER_SIZE 3
// Maximum number of instructions in a packet before shuffling,
// including a compound one or a duplex or an extender.
#define HEXAGON_PRESHUFFLE_PACKET_SIZE (HEXAGON_PACKET_SIZE + 3)

#include "MCTargetDesc/HexagonMCTargetDesc.h"

#endif
