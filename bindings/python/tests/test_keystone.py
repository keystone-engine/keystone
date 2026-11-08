import threading
import unittest

from keystone import Arch, ArmItMode, Keystone, KeystoneError, KsErr, Radix, X86Syntax


def resolve(symbol):
   return {"symBackward": 0, "symForward": 0x20}.get(symbol)


class KeystoneTest(unittest.TestCase):
   def test_x64_bigint(self):
      ks = Keystone(Arch.X64)
      expected = bytes.fromhex("48bf5544332211000000")
      self.assertEqual(ks.asm("mov rdi, 0x1122334455").bytes, expected)
      self.assertEqual(ks.asm("movabs rdi, 0x1122334455").bytes, expected)

   def test_nasm(self):
      ks = Keystone(Arch.X86)
      ks.x86_syntax = X86Syntax.NASM
      self.assertEqual(
         ks.asm("mov dword [eax], 0x42424242").bytes, bytes.fromhex("c70042424242")
      )
      self.assertEqual(
         ks.asm("add eax, ebx; inc ecx this comment is ignored\ninc edx").bytes,
         b"\x01\xd8\x42",
      )

   def test_dollar_is_pc(self):
      self.assertEqual(Keystone(Arch.X86).asm("jmp $", 0x1000).bytes, b"\xeb\xfe")

   def test_radix_before_first_asm(self):
      ks = Keystone(Arch.X86)
      self.assertIs(ks.radix, Radix.DECIMAL)
      ks.radix = Radix.HEXADECIMAL
      self.assertEqual(ks.asm("mov eax, 1").bytes, bytes.fromhex("b801000000"))
      self.assertIs(ks.radix, Radix.HEXADECIMAL)

   def test_arm_symbol_resolver(self):
      ks = Keystone(Arch.ARM)
      ks.symbol_resolver = resolve
      self.assertEqual(
         ks.asm("sub r0, r0, r0\nsub r1, r1, r1\nbl symBackward").bytes[-4:],
         bytes.fromhex("fcffffeb"),
      )
      self.assertEqual(ks.asm("bl symForward").bytes, bytes.fromhex("060000eb"))

   def test_thumb_symbol_resolver(self):
      ks = Keystone(Arch.THUMB)
      ks.symbol_resolver = resolve
      self.assertEqual(
         ks.asm("sub r0, r0, r0\nsub r0, r0, r0\nbl symBackward").bytes[-4:],
         bytes.fromhex("fff7faff"),
      )
      self.assertEqual(ks.asm("bl symForward").bytes, bytes.fromhex("00f00ef8"))

   def test_implicit_it_counts_toward_branch_address(self):
      ks = Keystone(Arch.THUMB)
      ks.arm_it_mode = ArmItMode.ALWAYS
      self.assertEqual(
         ks.asm("addeq r0, r1\nb 0x100").bytes, bytes.fromhex("08bf08447ce0")
      )

   def test_set_arch_clears_resolver(self):
      ks = Keystone(Arch.X86)
      ks.symbol_resolver = lambda _: 0x1000
      ks.arch = Arch.AARCH64
      self.assertIsNone(ks.symbol_resolver)
      self.assertEqual(ks.asm("mov x0, #1").bytes, bytes.fromhex("200080d2"))

   def test_error_locations(self):
      with self.assertRaises(KeystoneError) as caught:
         Keystone(Arch.X64).asm("nop\nfoo\nbar rax")
      self.assertIs(caught.exception.code, KsErr.ASM_MNEMONIC_FAIL)
      self.assertEqual(
         [(at.line, at.column) for at in caught.exception.locations], [(2, 1), (3, 1)]
      )

   def test_missing_symbol(self):
      with self.assertRaises(KeystoneError) as caught:
         Keystone(Arch.X86).asm("call missing")
      self.assertIs(caught.exception.code, KsErr.ASM_MISSING_SYMBOL)

   def test_resolver_exception_propagates(self):
      ks = Keystone(Arch.X86)
      ks.symbol_resolver = lambda _: 1 // 0
      with self.assertRaises(ZeroDivisionError):
         ks.asm("call missing")
      ks.symbol_resolver = None
      self.assertEqual(ks.asm("nop").bytes, b"\x90")

   def test_resolver_cannot_reenter(self):
      ks = Keystone(Arch.X86)

      def reenter(_):
         ks.radix = Radix.HEXADECIMAL
         return 0

      ks.symbol_resolver = reenter
      with self.assertRaises(RuntimeError):
         ks.asm("call missing")

   def test_closed_engine(self):
      with Keystone(Arch.X86) as ks:
         pass
      with self.assertRaises(KeystoneError) as caught:
         ks.asm("nop")
      self.assertIs(caught.exception.code, KsErr.HANDLE)

   def test_embedded_nul(self):
      with self.assertRaises(ValueError):
         Keystone(Arch.X86).asm("nop\0nop")

   def test_engines_in_parallel(self):
      source = "inc eax\n" * 5000
      results = [None] * 4

      def work(index):
         results[index] = Keystone(Arch.X86).asm(source).bytes

      threads = [threading.Thread(target=work, args=(i,)) for i in range(4)]
      for thread in threads:
         thread.start()
      for thread in threads:
         thread.join()
      self.assertEqual(results, [b"\x40" * 5000] * 4)


if __name__ == "__main__":
   unittest.main()
