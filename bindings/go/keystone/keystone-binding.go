/* Keystone Assembler Engine (www.keystone-engine.org) */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2016 */
/* Golang bindings by Remco Verhoef <remco@dutchcoders.io>, 2016 */

// +build darwin,linux,cgo
package keystone

// #cgo LDFLAGS: -lkeystone -lstdc++ -lm
// #include <keystone/keystone.h>
import "C"
import "unsafe"

func ks_version() (uint, uint) {
	major := C.uint(0)
	minor := C.uint(0)
	C.ks_version(&major, &minor)
	return uint(major), uint(minor)
}

func ks_arch_supported(a Architecture) bool {
	return bool(C.ks_arch_supported((C.ks_arch)(a)))
}

func ks_open(a Architecture, m Mode, engine **C.ks_engine) error {
	if err := C.ks_open((C.ks_arch)(a), (C.int)(m), (**C.ks_engine)(unsafe.Pointer(engine))); err != 0 {
		return Error(err)
	}

	return nil
}

func ks_option(engine *C.ks_engine, type_ OptionType, value OptionValue) error {
	if err := C.ks_option(engine, C.ks_opt_type(type_), C.size_t(value)); err != 0 {
		return Error(err)
	}
	return nil
}

func ks_errno(engine *C.ks_engine) error {
	if err := C.ks_errno(engine); err != 0 {
		return Error(err)
	}
	return nil
}

func ks_asm(engine *C.ks_engine, str string, address uint64, encoding *[]byte, stat_count *uint64) bool {
	cstr := C.CString(str)
	defer C.free(unsafe.Pointer(cstr))

	var p_insn unsafe.Pointer
	defer C.free(unsafe.Pointer(p_insn))

	var count, l_insn C.size_t
	err := C.ks_asm(engine, cstr, C.uint64_t(address), (**C.uchar)(unsafe.Pointer(&p_insn)), &l_insn, &count)
	*encoding = C.GoBytes(p_insn, C.int(l_insn))
	*stat_count = uint64(count)
	return err == 0
}

func ks_close(engine *C.ks_engine) error {
	if err := C.ks_close(engine); err != 0 {
		return Error(err)
	}
	return nil
}
