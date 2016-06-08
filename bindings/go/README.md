# keystone 
Go bindings for the [keystone](http://www.keystone-engine.org/) engine.

## Sample
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

## Testing

```
go test
```

## Contributors
- Remco Verhoef (@remco_verhoef)
