# Keystone.Net
.NET bindings for Keystone (.NET Standard 2.0), written in C#.

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

## NuGet package
The NuGet package `keystoneengine.csharp` is maintained to reflect the latest version of the bindings and the library. It can either be downloaded using Visual Studio or by [browsing NuGet directly](https://www.nuget.org/packages/keystoneengine.csharp/). The package already embeds the 32/64-bit native dynamic-link libraries of Keystone.

## Found an issue or bug ?
Feel free to open a GitHub issue on [the official repository of Keystone](https://github.com/keystone-engine/keystone/issues) and ping the contributors.


## Contributors
Authors:

- Grégoire Geis ([https://github.com/71](@71))
- Jämes Ménétrey ([@ZenLulz](https://github.com/ZenLulz/))
- Marco Fornaro ([@chaplin89](https://github.com/chaplin89))

### Want to contribute ?
Hey you! Your help is more than welcome! Things to keep in mind when working on the .NET bindings for Keystone:

- Think about the backward compatibility; while code refactoring is a good practice, changing entirely the API *may* result in struggles.
- Elaborate the unit tests that prove your code is working. Test all the paths of the newly added functions/classes. Keep the code coverage high!
- Please; write the required *XML Documentation Comments*, so every developer has the chance to understand your code.
- Update the changelog with a summary of your changes.

#### Version notation
The version of the .NET bindings for Keystone is indicated in the Visual Studio project file. The major, minor and incremental versions (w.x.y) match the version of the library Keystone that the bindings are developed with. The build number (the .z in w.x.y.z) is incremented for each newer version of the .NET bindings. Please, don't forget to increment this version when you submit a pull request.

On the last commit for a pull request, please create a tag called `csharp-bindings-w.x.y.z`.

#### Pull request submission
Ping the contributors of the .NET bindings when submitting a pull request, so your changes can be peer reviewed.

#### NuGet package update
Once your pull request has been accepted, please contact [@ZenLulz](https://github.com/ZenLulz/) so either he updates the library for you or add you to the project as a contributor on nuget.org. An example of *nupkg* is provided in this folder, as it requires to have a very specific configuration, because it embeds unmanaged libraries. The picture *nuget-package-config.png* details the structure and content of a NuGet package, ready to be deployed. Please reuse and test the package before pushing it onto nuget.org, as there is no possible roll back.