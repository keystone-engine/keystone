# Changes

### Names
- The `KeystoneNET` namespace was renamed to `Keystone`.
- The `Keystone` and `KeystoneEncoded` classes were respectively renamed to `Engine` and `EncodedData`.
- The `KeystoneArchitecture`, `KeystoneMode`, `KeystoneOptionType` and `KeystoneOptionValue` enums had their names changed, dropping the `Keystone` prefix (ie: `Architecture`, `Mode`, ...). Furthermore, their members were renamed, dropping the `KS_MODE_`, `KS_ARCH_`, and `KS_OPT_` prefixes.

### The `Engine` class
- The `Engine` constructor no longer takes `bool throwOnError`. Instead, the public `ThrowOnError` property now has both a getter and a setter, making it possible to alter the error behavior after initialization.
- Errors are no longer reported as `InvalidOperationException`, but instead as `KeystoneException`, a custom class which stores the returned error code.
- An error encountered in the constructor or when setting `ResolveSymbol` will throw an exception, regardless of the value of `ThrowOnError`.
- `AppendAssemble` was renamed to `Assemble`, and no longer accepts `ICollection<byte>`. Instead it accepts a `byte[]` buffer and an `int` index, and writes much more efficiently into it. A new overload accepting a `Stream` has also been added.
- The `out uint statements` parameter has been replaced by an `out int statementCount` parameter. It will always be positive, but better integrates into the C# language.

# Examples

### Namespace
```csharp
using KeystoneNET;
```
becomes
```csharp
using Keystone;
```

### Initialization
```csharp
using (var ks = new Keystone(KeystoneArchitecture.KS_ARCH_X86,
                             KeystoneMode.KS_MODE_32,
                             throwOnError: false))
{
}
```
becomes
```csharp
using (var ks = new Engine(Architecture.X86, Mode.X32)
                          { ThrowOnError = true })
{
}
```

### Catching errors
```csharp
try
{
    ks.SymbolResolver += Callback;
}
catch (InvalidOperationException e)
{
    Console.WriteLine(e);
}
```
becomes
```csharp
try
{
    ks.SymbolResolver += Callback;
}
catch (KeystoneException e)
{
    Console.WriteLine(e);
}
```

### Assembling data
```csharp
var data = new List<byte>();

ks.AppendAssemble("add eax, eax", data);
```
becomes
```csharp
var data = new byte[1024];

ks.Assemble("add eax, eax", data);
```
or
```csharp
using (var ms = new MemoryStream())
{
    ks.Assemble("add eax, eax", ms);
}
```
