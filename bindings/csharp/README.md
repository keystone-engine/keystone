# Keystone.Net
.Net bindings for Keystone

## Usage

 ```csharp
 using(var keystone = new Keystone(KeystoneArchitecture.KS_ARCH_X86, KeystoneMode.KS_MODE_32, false))
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
    
    KeystoneEncoded enc = keystone.Assemble("xor eax, eax; jmp _j1", address);
    
    ...
 }
