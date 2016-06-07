/* Keystone Assembler Engine (www.keystone-engine.org) */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2016 */
/* Golang bindings by Remco Verhoef <remco@dutchcoders.io>, 2016 */

package keystone

// #include <keystone/keystone.h>
import "C"

type Architecture uint

type Mode uint

type OptionType uint

type OptionValue uint

type Error uint32

func (e Error) Error() string {
	s := C.ks_strerror((C.ks_err)(e))
	return C.GoString(s)
}

func (a Architecture) Supported() bool {
	return ks_arch_supported(a)
}

func Version() (uint, uint) {
	return ks_version()
}

type Keystone struct {
	engine *C.ks_engine
}

func New(a Architecture, m Mode) (*Keystone, error) {
	ks := &Keystone{}
	if err := ks_open(a, m, &ks.engine); err != nil {
		return nil, err
	} else {
		return ks, nil
	}
}

func (ks *Keystone) LastError() error {
	return ks_errno(ks.engine)
}

func (ks *Keystone) Option(type_ OptionType, value OptionValue) error {
	if err := ks_option(ks.engine, type_, value); err != nil {
		return err
	}

	return nil
}

func (ks *Keystone) Assemble(str string, address uint64) ([]byte, uint64, bool) {
	encoding := []byte{}
	stat_count := uint64(0)
	ok := ks_asm(ks.engine, str, address, &encoding, &stat_count)
	return encoding, stat_count, ok
}

func (ks *Keystone) Close() error {
	return ks_close(ks.engine)
}
