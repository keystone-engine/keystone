# Keystone.Net
.NET Standard bindings for Keystone.

## Usage
```csharp
using Keystone;

using (Engine keystone = new Engine(Architecture.X86, Mode.X32) { ThrowOnError = true })
{
    ulong address = 0;

    keystone.ResolveSymbol += (string s, ref ulong w) =>
    {
        if (s == "_j1")
        {
            w = 0x1234abcd;
            return true;
        }

        return false;
    };
    
    EncodedData enc = keystone.Assemble("xor eax, eax; jmp _j1", address);

    enc.Buffer.ShouldBe(new byte[] { 0x00 });
    enc.Address.ShouldBe(address);
    enc.StatementCount.ShouldBe(3);
}
```

For those who already used the bindings before their last update, many things have changed.
You can migrate your existing code easily using the [migration guide](./MIGRATON.md).
