/* Keystone Assembler Engine (www.keystone-engine.org) */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2016 */
/* Golang bindings by Remco Verhoef <remco@dutchcoders.io>, 2016 */

package main

import (
	"fmt"
	"os"

	"github.com/keystone-engine/keystone/bindings/go/keystone"
)

func main() {
	assembly := os.Args[1]

	ks, err := keystone.New(keystone.ARCH_X86, keystone.MODE_32)
	if err != nil {
		panic(err)
	}
	defer ks.Close()

	if err := ks.Option(keystone.OPT_SYNTAX, keystone.OPT_SYNTAX_INTEL); err != nil {
		panic(fmt.Errorf("Could not set syntax option to intel"))
	}

	if insn, _, ok := ks.Assemble(assembly, 0); !ok {
		panic(fmt.Errorf("Could not assemble instruction"))
	} else {
		fmt.Printf("%s: [%x]", assembly, insn)
	}
}
