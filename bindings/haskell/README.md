# Keystone Haskell bindings
## Building
1. Install the core Keystone Assembler as a dependency:

   Follow docs/COMPILE.md in the root directory to compile & install the core.
2. Change into the Haskell bindings directory, build and install:

    ```
$ cd bindings/haskell
$ cabal install
```

If you are installing into a sandbox, run `cabal sandbox init` before
installing Keystone's dependencies.

If the build fails, install c2hs manually `cabal install c2hs` (note that this
will probably also require you to run `cabal install alex` and `cabal install
happy` as well). If you are NOT using a sandbox, ensure that `$HOME/.cabal/bin`
is on your PATH.

To build a sample (after having built and installed the Haskell bindings):

```
$ cd bindings/haskell
$ ghc --make samples/Sample.hs
```

## Using as a dependency
### In a Cabal project
Add the following to the `cabal.project` file in the project root:

```text
source-repository-package
  type: git
  location: https://github.com/keystone-engine/keystone
  subdir:
    bindings/haskell
  tag: master

-- if the file didn't already exist, add the following also
packages: .
```

### In a Stack project
Add the following to the `stack.yaml` file in the project root:

```yaml
extra-deps:
- git: https://github.com/keystone-engine/keystone
  subdir: bindings/haskell
```
