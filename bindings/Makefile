# Keystone Engine
# By Nguyen Anh Quynh & Dang Hoang Vu, 2015
TMPDIR = /tmp/keystone_sample

DIFF = diff -u -w

SAMPLE_ARM = $(TMPDIR)/sample_arm
SAMPLE_ARM64 = $(TMPDIR)/sample_arm64
SAMPLE_MIPS = $(TMPDIR)/sample_mips
SAMPLE_M68K = $(TMPDIR)/sample_m68k
SAMPLE_SPARC = $(TMPDIR)/sample_sparc
SAMPLE_X86 = $(TMPDIR)/sample_x86
SAMPLE_RISCV = $(TMPDIR)/sample_riscv

.PHONY: all expected python rust go nodejs ruby

all:
	cd python && $(MAKE) gen_const
	cd nodejs && $(MAKE) gen_const
	python const_generator.py rust
	python const_generator.py go
	cd ruby && $(MAKE) gen_const
	python const_generator.py powershell

samples: expected python

sample_python: expected python

expected:
	cd ../samples && $(MAKE)
	mkdir -p $(TMPDIR)
	../samples/sample_arm > $(SAMPLE_ARM)_e
	../samples/sample_arm64 > $(SAMPLE_ARM64)_e
	../samples/sample_mips > $(SAMPLE_MIPS)_e
	../samples/sample_sparc > $(SAMPLE_SPARC)_e
	../samples/sample_m68k > $(SAMPLE_M68K)_e
	../samples/sample_x86 > $(SAMPLE_X86)_e
	../samples/sample_riscv > $(SAMPLE_RISCV)_e

python: FORCE
	cd python && $(MAKE)
	python python/sample_arm.py > $(SAMPLE_ARM)_o
	python python/sample_arm64.py > $(SAMPLE_ARM64)_o
	python python/sample_mips.py > $(SAMPLE_MIPS)_o
	python python/sample_sparc.py > $(SAMPLE_SPARC)_o
	python python/sample_m68k.py > $(SAMPLE_M68K)_o
	python python/sample_x86.py > $(SAMPLE_X86)_o
	python python/sample_riscv.py > $(SAMPLE_RISCV)_o
	$(MAKE) sample_diff

ruby: FORCE
	cd ruby && $(MAKE)

nodejs: FORCE
	cd nodejs && $(MAKE)

rust: FORCE
	cd rust && $(MAKE)

go: FORCE
	cd go && $(MAKE)

ocaml: FORCE
	cd ocaml && $(MAKE)

sample_diff: FORCE
	$(DIFF) $(SAMPLE_ARM)_e $(SAMPLE_ARM)_o
	$(DIFF) $(SAMPLE_ARM64)_e $(SAMPLE_ARM64)_o
	$(DIFF) $(SAMPLE_MIPS)_e $(SAMPLE_MIPS)_o
	$(DIFF) $(SAMPLE_SPARC)_e $(SAMPLE_SPARC)_o
	$(DIFF) $(SAMPLE_M68K)_e $(SAMPLE_M68K)_o
	$(DIFF) $(SAMPLE_X86)_e $(SAMPLE_X86)_o
	$(DIFF) $(SAMPLE_RISCV)_e $(SAMPLE_RISCV)_o

clean:
	rm -rf $(TMPDIR)
	cd python && $(MAKE) clean
	cd rust && $(MAKE) clean
	cd go && $(MAKE) clean
	cd nodejs && $(MAKE) clean
	cd ruby && $(MAKE) clean
	cd ocaml && $(MAKE) clean

check:
	cd python && $(MAKE) check
	cd rust && $(MAKE) check
	cd go && $(MAKE) check
	cd nodejs && $(MAKE) check
	cd ruby && $(MAKE) check

FORCE:
