# keystone 
Go bindings for the [keystone](http://www.keystone-engine.org/) engine.

```go
package main

import (
        "fmt"
        "os"

        keystone "github.com/keystone-engine/beta/bindings/go/keystone"
)

func main() {
        assembly := os.Args[1]

        if ks, err := keystone.New(keystone.ArchitectureX86, keystone.Mode32); err != nil {
                panic(err)
        } else {
                defer ks.Close()

                if err := ks.Option(keystone.OptionSyntax, keystone.OptionSyntaxIntel); err != nil {
                        panic(fmt.Errorf("Could not set syntax option to intel"))
                }

                if insn, _, ok := ks.Assemble(assembly, 0); !ok {
                        panic(fmt.Errorf("Could not assemble instruction"))
                } else {
                        fmt.Printf("%s: [%x]", assembly, insn)
                }
        }
}
```

## Installation

## Notes

## Contributing

Contributors:
- Remco Verhoef (@remco_verhoef)

Special thanks to:
- Sébastien Duquette (@ekse) for his [unicorn-rs](https://github.com/ekse/unicorn-rs) binding
