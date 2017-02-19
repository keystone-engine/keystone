# keystone 

C# bindings for the [keystone](http://www.keystone-engine.org/) engine.

## Instructions

Open the csproj file and compile the assembly.
Once compiled, include the assembly in your project.
Make sure the compiled keystone.dll is in the same directory.

## Sample

```csharp
using Keystone;

namespace Keystone_RunTests
{
    class Program
    {
        static void RunX86()
        {
            Engine eng = new Engine();
            Constants.ks_err err = eng.Open(Constants.ks_arch.KS_ARCH_X86, Constants.ks_mode.KS_MODE_32);
            if (err != Constants.ks_err.KS_ERR_OK)
            {
                Console.WriteLine(String.Format("Failed to open keystone engine: 0x{0:X4}", err));
                return;
            }

            Console.WriteLine(String.Format("Engine Pointer: 0x{0:X8}", eng.Pointer()));

            List<byte> asm = new List<byte>();
            int r = eng.Assemble("nop; jmp 0x0;", 0, ref asm);
            Console.WriteLine("Assemble Result: " + r.ToString());
            if (r == 0)
            {
                for (int i = 0; i < asm.Count; i++)
                {
                    Console.Write(String.Format("{0:X2} ", asm[i]));
                }

                Console.WriteLine("");
            }

            err = eng.Close();
            if (err != Constants.ks_err.KS_ERR_OK)
            {
                Console.WriteLine(String.Format("Failed to close keystone engine: 0x{0:X4}", err));
                return;
            }
        }
	}
}
```

## Contributors
- Andrew Artz (@keyboardsmoke)