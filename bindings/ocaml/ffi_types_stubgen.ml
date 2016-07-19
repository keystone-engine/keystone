let () =
	print_endline ("#include " ^  Config.keystone_header_loc);
        Cstubs.Types.write_c Format.std_formatter (module Ffi_types.Types)
