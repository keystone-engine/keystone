using NUnit.Framework;
using System;
using System.Globalization;
using System.Linq;
using TechTalk.SpecFlow;

namespace KeystoneNET.Tests
{
    [Binding]
    class CompilationSteps
    {
        [Given(@"An instance of Keystone built for (.*) in mode (.*)")]
        public void GivenAnInstanceOfKeystoneBuiltForInMode(string p0, string p1)
        {
            var arch = (KeystoneArchitecture)Enum.Parse(typeof(KeystoneArchitecture), $"KS_ARCH_{p0}");
            var mode = (KeystoneMode)Enum.Parse(typeof(KeystoneMode), $"KS_MODE_{p1}");

            var keystone = new Keystone(arch, mode, false);
            ScenarioContext.Current.Add("keystoneInstance", keystone);
        }

        [Given(@"The statement\(s\) ""(.*)""")]
        public void GivenTheStatements(string p0)
        {
            ScenarioContext.Current.Add("statements", p0);
        }

        [When(@"I compile the statement\(s\) with Keystone")]
        public void WhenICompileTheStatementWithKeystone()
        {
            var statements = ScenarioContext.Current["statements"] as string;
            var engine = ScenarioContext.Current["keystoneInstance"] as Keystone;
            var result = engine.Assemble(statements, 0);

            ScenarioContext.Current.Add("assembleResult", result);
        }

        [Given(@"A dummy symbols resolver")]
        public void GivenADummySymbolsResolver()
        {
            var engine = ScenarioContext.Current["keystoneInstance"] as Keystone;

            engine.ResolveSymbol += (string symbol, ref ulong address) =>
            {
                address = 0xababab;
                return true;
            };            
        }


        [Then(@"the result is (.*)")]
        public void ThenTheResultIs(string p0)
        {
            string[] bytes = p0.Split(',');
            var expectedBytes = bytes.Select(x => byte.Parse(x, NumberStyles.HexNumber))
                                     .ToList();

            var result = ScenarioContext.Current["assembleResult"] as KeystoneEncoded;
            var engine = ScenarioContext.Current["keystoneInstance"] as Keystone;

            Assert.AreEqual(KeystoneError.KS_ERR_OK, engine.GetLastKeystoneError());
            Assert.AreEqual(expectedBytes.Count, result.Buffer.Length);

            for(int i=0; i< expectedBytes.Count; i++)
                Assert.AreEqual(result.Buffer[i], expectedBytes[i]);
        }

        [Then(@"The last error is (.*)")]
        public void ThenTheLastErrorIs(string error)
        {
            var errorType = (KeystoneError)Enum.Parse(typeof(KeystoneError), $"KS_ERR_{error}");
            var engine = ScenarioContext.Current["keystoneInstance"] as Keystone;
            Assert.AreEqual(engine.GetLastKeystoneError(), errorType);
        }

        [AfterScenario]
        public void ReleaseKeystone()
        {
            var engine = ScenarioContext.Current["keystoneInstance"] as Keystone;
            if (engine != null)
                engine.Dispose();
        }
    }
}
