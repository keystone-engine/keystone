using System;
using NUnit.Framework;
using Shouldly;

namespace Keystone.Tests
{
    [TestFixture]
    public class ExecutionTests
    {
        [OneTimeSetUp]
        public static void InitializeKeystone()
        {
            // Ensures the lib could be loaded
            Engine.IsArchitectureSupported(Architecture.X86).ShouldBeTrue();
        }

        [Test]
        public void ShouldEmitValidX86Data()
        {
            using (Engine engine = new Engine(Architecture.X86, Mode.X32) { ThrowOnError = true })
            {
                engine.Assemble("nop", 0).Buffer.ShouldBe(new byte[] { 0x90 });
                engine.Assemble("add eax, eax", 0).Buffer.ShouldBe(new byte[] { 0x01, 0xC0 });
            }
        }

        [Test]
        public void ShouldEmitValidARMData()
        {
            using (Engine engine = new Engine(Architecture.ARM, Mode.ARM) { ThrowOnError = true })
            {
                engine.Assemble("mul r1, r0, r0", 0).Buffer.ShouldBe(new byte[] { 0x90, 0x00, 0x01, 0xE0 });
            }
        }

        [Test]
        public void ShouldThrowOnError()
        {
            using (Engine engine = new Engine(Architecture.ARM, Mode.ARM) { ThrowOnError = false })
            {
                engine.Assemble("push eax, 0x42", 0).ShouldBeNull();
                engine.Assemble("doesntexist", 0).ShouldBeNull();
            }

            using (Engine engine = new Engine(Architecture.ARM, Mode.ARM) { ThrowOnError = true })
            {
                Should.Throw<KeystoneException>(() => engine.Assemble("push eax, 0x42", 0));
                Should.Throw<KeystoneException>(() => engine.Assemble("doestexist", 0));
            }
        }

        [Test, Ignore("Feature requires Keystone built after October 7th 2016.")]
        public void ShouldHaveValidExample()
        {
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
        }
    }
}
