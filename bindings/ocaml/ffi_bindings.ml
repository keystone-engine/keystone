open Ctypes

module Bindings (F: Cstubs.FOREIGN)  =
  struct

    open F

    module T = Ffi_types.Types(Ffi_generated_types)

    let temp = Ffi_generated_types.constant "KS_MODE_BIG_ENDIAN" int64_t

    let ks_arch_supported_ = foreign "ks_arch_supported" (T.ks_arch @-> returning bool)

    let ks_version_ = foreign "ks_version" (ptr uint @-> ptr uint @-> returning uint)

    let ks_open_ = foreign "ks_open" (T.ks_arch @-> int64_t @-> (ptr (ptr T.ks_engine)) @-> returning T.ks_err)

    let ks_close_ = foreign "ks_close" (ptr T.ks_engine @-> returning int64_t)

    let ks_err_ = foreign "ks_errno" (ptr T.ks_engine @-> returning T.ks_err)

    let ks_option_ = foreign "ks_option" (ptr T.ks_engine @-> T.ks_opt_type @-> T.ks_opt_value @-> returning T.ks_err)

    let ks_strerror_ = foreign "ks_strerror" (T.ks_err @-> returning string)

    let ks_free_ = foreign "ks_free" (ptr void @-> returning void)

    let ks_asm_ = foreign "ks_asm" (ptr T.ks_engine @-> string @-> int64_t @-> ptr (ptr uchar) @-> ptr size_t @-> ptr size_t @-> returning int)

 end
