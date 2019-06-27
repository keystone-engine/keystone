# keystone
Go bindings for the [keystone](http://www.keystone-engine.org/) engine.

## Sample
```go
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
```

## Testing

```
go test
```

## Contributors
- Remco Verhoef (@remco_verhoef)
