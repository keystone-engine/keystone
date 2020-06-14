from keystone import *
import regress

# Github issue #427
# Author: Edward Larson

class TestAddressConsistency(regress.RegressTest):
    def kstest_address_consistency(self, preceding_assembly, start_address=0x1000, branch_address=0x1004):
        """
        Check that a relative branch to itself at branch_address emits the same machine code, independent of the
        inst_Assembly comes before it.
        :param preceding_assembly: Instruction(s) to be assembled before the branch instruction
        :param start_address: VM address of the beginning of preceding_assembly
        :param branch_address: VM address of the branch instruction
        :return:
        """
        ks = Ks(KS_ARCH_PPC, KS_MODE_32 | KS_MODE_BIG_ENDIAN)

        branch_assembly = 'b ' + hex(branch_address)
        expected_branch_encoding, _ = ks.asm(branch_assembly, branch_address)

        code = preceding_assembly + "; " + branch_assembly

        encoding, count = ks.asm(code, start_address)
        emitted_branch_encoding = encoding[-4:]

        self.assertEqual(emitted_branch_encoding, expected_branch_encoding)

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
