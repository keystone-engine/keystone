from keystone import *
import regress

# Author: Edward Larson

class TestAddressConsistency(regress.RegressTest):
    def kstest_address_consistency(self, inst_assembly):
        ks = Ks(KS_ARCH_PPC, KS_MODE_32 | KS_MODE_BIG_ENDIAN)


        # relative branch to its own address should always be encoded with branch target 0
        start_address = 0x1000
        branch_assembly = "b 0x1004"
        branch_mc = [0x48, 0x00, 0x00, 0x00]

        code = inst_assembly + "; " + branch_assembly

        encoding, count = ks.asm(code, start_address)

        last_instruction_mc = encoding[-4:]

        self.assertEqual(branch_mc, last_instruction_mc)

    def runTest(self):
        # un-aliased instructions
        self.kstest_address_consistency("nop")
        self.kstest_address_consistency("add 0, 0, 0")

        # aliased instructions
        self.kstest_address_consistency("dcbtt 0, 0")
        self.kstest_address_consistency("dcbtct 0, 0, 0")
        self.kstest_address_consistency("dcbtstct 0, 0, 0")
        self.kstest_address_consistency("la 1, 0, 1")
        self.kstest_address_consistency("subi 0, 0, 0")
        self.kstest_address_consistency("subis 0, 0, 0")
        self.kstest_address_consistency("subic 0, 0, 0")
        self.kstest_address_consistency("subic. 0, 0, 0")
        self.kstest_address_consistency("extlwi 0, 0, 0, 0")
        self.kstest_address_consistency("extrwi 0, 0, 0, 0")
        self.kstest_address_consistency("inslwi 0, 0, 0, 0")
        self.kstest_address_consistency("insrwi 0, 0, 0, 0")
        self.kstest_address_consistency("rotrwi 0, 0, 0")
        self.kstest_address_consistency("slwi 0, 0, 0")
        self.kstest_address_consistency("srwi 0, 0, 0")
        self.kstest_address_consistency("clrrwi 0, 0, 0")
        self.kstest_address_consistency("clrlslwi 0, 0, 0, 0")
        self.kstest_address_consistency("extldi 0, 0, 0, 0")
        self.kstest_address_consistency("extrdi 0, 0, 0, 0")
        self.kstest_address_consistency("insrdi 0, 0, 0, 0")
        self.kstest_address_consistency("rotrdi 0, 0, 0")
        self.kstest_address_consistency("sldi 0, 0, 0")
        self.kstest_address_consistency("srdi 0, 0, 0")
        self.kstest_address_consistency("clrrdi 0, 0, 0")
        self.kstest_address_consistency("clrlsldi 0, 0, 0, 0")
        self.kstest_address_consistency("rlwinm 0, 0, 0, 1")
        self.kstest_address_consistency("rlwimi 0, 0, 0, 1")
        self.kstest_address_consistency("rlwnm 0, 0, 0, 1")
        self.kstest_address_consistency("mftb 0, 0")
