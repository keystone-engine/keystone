//===- StringTableBuilder.h - String table building utility -----*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_MC_STRINGTABLEBUILDER_H
#define LLVM_MC_STRINGTABLEBUILDER_H

#include "llvm/ADT/CachedHashString.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/Alignment.h"
#include "llvm/Support/Compiler.h"
#include <cstddef>
#include <cstdint>

namespace llvm_ks {

class raw_ostream;

/// Utility for building string tables with deduplicated suffixes.
class StringTableBuilder {
public:
  enum Kind {
    ELF,
    WinCOFF,
    MachO,
    MachO64,
    MachOLinked,
    MachO64Linked,
    RAW,
    DWARF,
    XCOFF,
    DXContainer
  };

private:
  // Only non-zero priority will be recorded.
  DenseMap<CachedHashStringRef, uint8_t> StringPriorityMap;
  DenseMap<CachedHashStringRef, size_t> StringIndexMap;
  size_t Size = 0;
  Kind K;
  Align Alignment;
  bool Finalized = false;

  void finalizeStringTable(bool Optimize);
  void initSize();

public:
  // Keystone: stub implementations (object emission not used)
  StringTableBuilder(Kind K_, Align A = Align(1)) : K(K_), Alignment(A) {}
  ~StringTableBuilder() = default;

  size_t add(CachedHashStringRef S, uint8_t Priority = 0) {
    auto P = StringIndexMap.try_emplace(S, Size);
    if (P.second)
      Size += S.val().size() + 1;
    return P.first->second;
  }
  size_t add(StringRef S, uint8_t Priority = 0) {
    return add(CachedHashStringRef(S), Priority);
  }

  void finalize() { Finalized = true; }
  void finalizeInOrder() { Finalized = true; }

  size_t getOffset(CachedHashStringRef S) const {
    auto I = StringIndexMap.find(S);
    return I == StringIndexMap.end() ? 0 : I->second;
  }
  size_t getOffset(StringRef S) const {
    return getOffset(CachedHashStringRef(S));
  }

  /// Check if a string is contained in the string table. Since this class
  /// doesn't store the string values, this function can be used to check if
  /// storage needs to be done prior to adding the string.
  bool contains(StringRef S) const { return contains(CachedHashStringRef(S)); }
  bool contains(CachedHashStringRef S) const { return StringIndexMap.count(S); }

  bool empty() const { return StringIndexMap.empty(); }
  size_t getSize() const { return Size; }
  void clear() { StringIndexMap.clear(); StringPriorityMap.clear(); Size = 0; Finalized = false; }

  void write(raw_ostream &OS) const {}
  void write(uint8_t *Buf) const {}

  bool isFinalized() const { return Finalized; }
};

} // end namespace llvm_ks

#endif // LLVM_MC_STRINGTABLEBUILDER_H
