# Updating LLVM

These scripts move keystone's vendored LLVM to a new release. You'll need a
full LLVM clone with tags, which defaults to `~/projects/forks/llvm-project`
(set `KS_LLVM_ROOT` to use another one). Everything they write along the way
goes in `.llvm-sync/`, which is gitignored.

The examples below move to `llvmorg-24.1.0`. Start on a fresh change, so the
audit at the end has something to compare against:

```sh
jj new -m 'llvm: port keystone to llvm 24.1.0'
```

## 1. Find what changed

```sh
nu tools/sync.nu scope --to llvmorg-24.1.0
nu tools/sync.nu analyze
```

`scope` lists the files upstream changed since the release keystone is on now,
out of the ones keystone still has. `analyze` then figures out which release
each of those files actually matches, since some were last synced from an older
one, and merging against the wrong base produces bogus conflicts.

## 2. Merge the source

```sh
nu tools/sync.nu merge --to llvmorg-24.1.0
nu tools/sync.nu resolve --apply
```

`merge` does a three-way merge of each file, with keystone's changes on one
side and upstream's on the other. `resolve --apply` settles the conflicts that
have an obvious answer, like both sides making the same edit or upstream only
touching code keystone commented out. Whatever's left needs a human, and is
listed in `.llvm-sync/semantic.txt`. Fix those by hand before moving on.

## 3. Update the tests

```sh
nu tools/sync.nu tests plan --to llvmorg-24.1.0
nu tools/sync.nu tests apply --to llvmorg-24.1.0
```

`plan` sorts the test fixtures into ones keystone never touched, which get
replaced with upstream's copy, and ones it customized, which get merged.
`apply` does both, and deletes the fixtures upstream removed.

## 4. Regenerate the tablegen output

```sh
git -C ~/projects/forks/llvm-project checkout llvmorg-24.1.0
nu tools/tablegen.nu regenerate --at llvmorg-24.1.0
```

This builds `llvm-tblgen` for the new release if it needs to and regenerates
every `.inc` file keystone uses. `--at` has to match what the clone has checked
out, and the script refuses to run if it doesn't.

## 5. Check the result

```sh
nu tools/sync.nu audit --before @-
```

`audit` looks for code that was live before the merge and is commented out
after it, which is the usual way a merge quietly breaks keystone. Once you've
gone through what it finds, build, run the tests with
`cargo nextest run --release --features arch_all`, and bump `CURRENT` at the
top of `sync.nu` to the new tag.
