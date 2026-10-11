//===- FormatVariadicDetails.h - Helpers for FormatVariadic.h ----*- C++-*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_FORMATVARIADICDETAILS_H
#define LLVM_SUPPORT_FORMATVARIADICDETAILS_H

#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/STLForwardCompat.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/Compiler.h"
#include "llvm/Support/raw_ostream.h"

#include <type_traits>

namespace llvm_ks {
template <typename T, typename Enable = void> struct format_provider {};
class Error;

namespace support {
namespace detail {

using FormatFunctorRef = function_ref<void(llvm_ks::raw_ostream &, StringRef)>;

template <typename T> class FormatFunctor {
  // If the caller passed an Error by value, then we would be responsible for
  // consuming it. Make the caller opt into this by calling fmt_consume().
  static_assert(
      !std::is_same_v<llvm_ks::Error, std::remove_cv_t<T>>,
      "llvm_ks::Error-by-value must be wrapped in fmt_consume() for formatv");

  T Item;

  using DecayedT = std::decay_t<T>;
  using Signature_format = void (*)(const DecayedT &, llvm_ks::raw_ostream &,
                                    StringRef);

  template <typename U>
  using MemberFormatCheck = decltype(std::declval<U>().format(
      std::declval<llvm_ks::raw_ostream &>(), std::declval<llvm_ks::StringRef>()));
  template <typename U>
  using StaticFormatCheck = SameType<Signature_format, &U::format>;
  template <typename U>
  using StreamCheck = std::is_same<decltype(std::declval<llvm_ks::raw_ostream &>()
                                            << std::declval<U>()),
                                   llvm_ks::raw_ostream &>;

public:
  static constexpr bool HasMemberProvider =
      llvm_ks::is_detected<MemberFormatCheck, DecayedT>::value;
  static constexpr bool HasFormatProvider =
      llvm_ks::is_detected<StaticFormatCheck,
                        llvm_ks::format_provider<DecayedT>>::value;
  static constexpr bool HasStreamProvider =
      llvm_ks::is_detected<StreamCheck, DecayedT>::value;

  static_assert(HasMemberProvider || HasFormatProvider || HasStreamProvider,
                "type has no format provider");

  explicit FormatFunctor(T &&Item) : Item(std::forward<T>(Item)) {}

  void operator()(llvm_ks::raw_ostream &S, StringRef Options) {
    if constexpr (HasMemberProvider)
      Item.format(S, Options);
    else if constexpr (HasFormatProvider)
      format_provider<DecayedT>::format(Item, S, Options);
    else if constexpr (HasStreamProvider)
      S << Item;
  }
};

template <typename T> FormatFunctor(T &&) -> FormatFunctor<T>;

} // namespace detail
} // namespace support
} // namespace llvm_ks

#endif
