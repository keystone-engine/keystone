open Ctypes
open Foreign

module B = Ffi_bindings.Bindings(Ffi_generated)
module Types = B.T

type encoded_result =
  {
    encoding: int array;
    encoding_size : int;
    stat_count : int;
  }

let ks_arch_supported arch =
  B.ks_arch_supported_ arch

let ks_version major minor =
  let major = Unsigned.UInt.of_int major in
  let minor = Unsigned.UInt.of_int minor in
  let u = B.ks_version_ (allocate uint major) (allocate uint minor) in
  Unsigned.UInt.to_int u

(* TODO: better handling of error value *)
let ks_option engine opttype optvalue =
  match opttype with
  | Types.KS_OPT_SYNTAX -> B.ks_option_ engine Types.KS_OPT_SYNTAX optvalue

let ks_strerror err =
  B.ks_strerror_ err

let ks_open arch ?(endian=Types.KS_MODE_LITTLE_ENDIAN) mode =
  let check_endian =
    match endian with
    | Types.KS_MODE_BIG_ENDIAN ->
       begin
         let m = Ffi_generated_types.constant (Types.string_of_ks_mode Types.KS_MODE_BIG_ENDIAN) int64_t in
         let m' = Ffi_generated_types.constant (Types.string_of_ks_mode mode) int64_t in
         Result.Ok(Int64.add m m')

       end
    | Types.KS_MODE_LITTLE_ENDIAN -> Result.Ok(Ffi_generated_types.constant (Types.string_of_ks_mode mode) int64_t)
    | _ -> Result.Error("Non-endian mode passed to endian arg of ks_open: use KS_MODE_BIG_ENDIAN or KS_MODE_LITTLE_ENDIAN")
  in
  let mode =
    match check_endian with
    | Result.Ok a -> a
    | Result.Error e -> failwith e
  in
  let engine = allocate_n ~count:1 ((ptr Types.ks_engine)) in

  match (B.ks_open_ arch mode engine) with
  | Types.KS_ERR_OK -> Result.Ok(!@ engine)
  | _ as err -> Result.Error(ks_strerror err)


let ks_close engine = B.ks_close_ engine

let ks_errno engine = B.ks_err_ engine


let ks_asm engine str addr =
  let addr' = Int64.of_int addr in
  let encoding = allocate_n ~count:1 (ptr uchar) in
  let encoding_size = allocate size_t (Unsigned.Size_t.of_int 0) in
  let stat_count = allocate size_t (Unsigned.Size_t.of_int 0) in
  match (B.ks_asm_ engine str addr' encoding encoding_size stat_count) with
  | 0 -> begin
      let iencoding_size = Unsigned.Size_t.to_int (!@ encoding_size) in
      let istat_count = Unsigned.Size_t.to_int (!@ stat_count) in
      let encodedasm =
        CArray.from_ptr (!@ encoding) (Unsigned.Size_t.to_int (!@ encoding_size))
        |> CArray.to_list |> Array.of_list  (* No map in CArray *)
        |> Array.map (fun c -> Unsigned.UChar.to_int c)
      in
      B.ks_free_ (to_voidp (!@ encoding));
      Result.Ok({encoding = encodedasm; encoding_size =  iencoding_size; stat_count = istat_count})
    end
  | _ -> let err = ks_errno engine |> ks_strerror  in
         Result.Error err

let asm_array_to_string a =
  Array.fold_left (fun str c -> let t = Printf.sprintf "%02x " c in str^t) "" a
