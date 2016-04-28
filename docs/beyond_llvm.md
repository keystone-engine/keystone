## Keystone & LLVM

Keystone engine is based on the [MC component](http://blog.llvm.org/2010/04/intro-to-llvm-mc-project.html) of the LLVM compiler infrastructure, which among many stuffs has an assembler engine inside. LLVM even has a tool named *llvm-mc* that can be used to compile input string of assembly instructions.

While Keystone reuses a part of LLVM as its core (with quite a few of changes to adapt to our design), there is a major difference between them. Notably, Keystone can do whatever LLVM does in term of assembling, but beyond that our engine can do more & do better in some aspects.

The section below highlights the areas where Keystone shines.

- **Framework**: *llvm-mc* is a tool, but not a framework. Therefore, it is very tricky to build your own assembler tools on of LLVM, while this is the main purpose of Keystone. Keystone's API makes it easy to handle errors, report internal status of its core or change compilation mode at runtime, etc.

- **Lightweight**: Keystone is much more lightweight than LLVM because we stripped all the subsystems that do not involve in assembler. As a result, Keystone is more than 10 times smaller in size and in memory consumption. Initial verson of Keystone takes only 30 seconds to compile on a laptop, while LLVM needs 15 minutes to build.

- **Flexibility**: LLVM's assembler is much more restricted. For example, it only accepts assembly in LLVM syntax. On the contrary, Keystone is going to support all kind of input, ranging from Nasm, Masm, etc.

- **Capability**: LLVM is for compiling & linking, so (understandably) some of its technical choices are not inline with an independent assembler like Keystone. For example, LLVM always put code and data in separate sections. However, it is very common for assembly to mix code and data in the same section (think about shellcode). Keystone is made to handle this kind of input very well.

- **Binding**: As a framework, Keystone supports multiple bindings on top of the core, starting with Python (more bindings will be added later). This makes it easy to be adopted by developers.

With all that said, LLVM is an awesome project, which Keystone was born from. However, Keystone is not just LLVM, but offering more because it has been designed & implemented to be an independent framework.
