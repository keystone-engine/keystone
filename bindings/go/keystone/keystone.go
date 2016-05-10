/* Keystone Assembler Engine (www.keystone-engine.org) */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2016 */
/* Golang bindings by Remco Verhoef <remco@dutchcoders.io>, 2016 */

package keystone

// #include "keystone.h"
import "C"

type Architecture uint

const (
	ArchitectureARM     Architecture = KS_ARCH_ARM     // ARM architecture (including Thumb, Thumb-2)
	ArchitectureARM64   Architecture = KS_ARCH_ARM64   // ARM-64, also called AArch64
	ArchitectureMIPS    Architecture = KS_ARCH_MIPS    // Mips architecture
	ArchitectureX86     Architecture = KS_ARCH_X86     // X86 architecture (including x86 & x86-64)
	ArchitecturePPC     Architecture = KS_ARCH_PPC     // PowerPC architecture (currently unsupported)
	ArchitectureSPARC   Architecture = KS_ARCH_SPARC   // Sparc architecture
	ArchitectureSYSTEMZ Architecture = KS_ARCH_SYSTEMZ // SystemZ architecture (S390X)
	ArchitectureHEXAGON Architecture = KS_ARCH_HEXAGON // Hexagon architecture
)

type Mode uint

const (
	ModeLittleEndian Mode = KS_MODE_LITTLE_ENDIAN
	ModeBigEndian    Mode = KS_MODE_BIG_ENDIAN
	ModeARM          Mode = KS_MODE_ARM
	ModeThumb        Mode = KS_MODE_THUMB
	ModeV8           Mode = KS_MODE_V8
	ModeMicro        Mode = KS_MODE_MICRO
	ModeMIPS3        Mode = KS_MODE_MIPS3
	ModeMIPS32R6     Mode = KS_MODE_MIPS32R6
	ModeMIPS32       Mode = KS_MODE_MIPS32
	ModeMIPS64       Mode = KS_MODE_MIPS64
	Mode16           Mode = KS_MODE_16
	Mode32           Mode = KS_MODE_32
	Mode64           Mode = KS_MODE_64
	ModePPC32        Mode = KS_MODE_PPC32
	ModePPC64        Mode = KS_MODE_PPC64
	ModeQPX          Mode = KS_MODE_QPX
	ModeSparc32      Mode = KS_MODE_SPARC32
	ModeSparc64      Mode = KS_MODE_SPARC64
	ModeV9           Mode = KS_MODE_V9
)

type OptionType uint

const (
	OptionSyntax OptionType = KS_OPT_SYNTAX
)

type OptionValue uint

const (
	OptionSyntaxIntel OptionValue = KS_OPT_SYNTAX_INTEL
	OptionSyntaxATT   OptionValue = KS_OPT_SYNTAX_ATT
	OptionSyntaxNASM  OptionValue = KS_OPT_SYNTAX_NASM
	OptionSyntaxMASM  OptionValue = KS_OPT_SYNTAX_MASM
	OptionSyntaxGAS   OptionValue = KS_OPT_SYNTAX_GAS
)

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
