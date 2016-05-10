/* Keystone Assembler Engine (www.keystone-engine.org) */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2016 */
/* Golang bindings by Remco Verhoef <remco@dutchcoders.io>, 2016 */

package keystone

import (
	"fmt"
	"reflect"
	"testing"
)

func TestVersion(t *testing.T) {
	major, minor := Version()
	if major == KS_API_MAJOR && minor == KS_API_MINOR {
	} else {
		t.Error(fmt.Errorf("Unexpected version: got %d.%d expected %d.%d", major, minor, 1, 0))
	}
}

func TestArchitectureSupported(t *testing.T) {
	if !ArchitectureARM.Supported() {
		t.Error(fmt.Errorf("ARM not supported"))
	}
}

type Test struct {
	Architecture   Architecture
	Mode           Mode
	Address        uint64
	Assembly       string
	ExpectedResult []byte
}

type Syntax struct {
	Syntax OptionValue
	Tests  []Test
}

var tests = []Syntax{
	Syntax{
		OptionSyntaxIntel, []Test{
			Test{ArchitectureX86, Mode32, 0, "mov ah, al", []byte{0x88, 0xc4}},
		},
	},
}

func TestRun(t *testing.T) {
	for _, st := range tests {
		for _, tr := range st.Tests {
			if ks, err := New(tr.Architecture, tr.Mode); err != nil {
				t.Error(err)
			} else {
				defer ks.Close()

				if err := ks.Option(OptionSyntax, st.Syntax); err != nil {
					t.Error(fmt.Errorf("Could not set syntax option to intel"))
				} else if insn, _, ok := ks.Assemble(tr.Assembly, tr.Address); !ok {
					t.Error(fmt.Errorf("Could not assemble instruction"))
				} else if !reflect.DeepEqual(insn, tr.ExpectedResult) {
					t.Error(fmt.Errorf("Not expected result: expected %#v got %#v", tr.ExpectedResult, insn))
				}
			}
		}
	}
}
