#!/usr/bin/env nu

# Syncs TableGen-generated .inc files from upstream LLVM

use sync.nu *

let KEYSTONE_ROOT = (ks-root)
let LLVM_ROOT = (llvm-root)
let TBLGEN_BUILD_DIR = $"($LLVM_ROOT)/build-tblgen"

const TABLEGEN_TARGETS = [
   {suffix: "GenAsmMatcher.inc", gen: "-gen-asm-matcher"}
   {suffix: "GenInstrInfo.inc", gen: "-gen-instr-info"}
   {suffix: "GenMCCodeEmitter.inc", gen: "-gen-emitter"}
   {suffix: "GenRegisterInfo.inc", gen: "-gen-register-info", siblings: ["Enums.inc" "MCDesc.inc" "Header.inc" "TargetDesc.inc"]}
   {suffix: "GenSubtargetInfo.inc", gen: "-gen-subtarget"}
   {suffix: "GenSystemOperands.inc", gen: "-gen-searchable-tables"}
   {suffix: "GenSystemRegister.inc", gen: "-gen-searchable-tables"}
   {suffix: "GenSearchableTables.inc", gen: "-gen-searchable-tables"}
   {suffix: "GenCompressInstEmitter.inc", gen: "-gen-compress-inst-emitter"}
   {suffix: "GenMnemonicTables.inc", gen: "-gen-x86-mnemonic-tables -asmwriternum=1"}
   {suffix: "GenInstrMapping.inc", gen: "-gen-x86-instr-mapping"}
   {suffix: "GenTargetFeatures.inc", gen: "-gen-target-features", output_dir: "llvm/include/llvm/TargetParser"}
   {suffix: "TargetParserDef.inc", gen: "-gen-arm-target-def", output_dir: "llvm/include/llvm/TargetParser"}
   {suffix: "TargetParserDef.inc", gen: "-gen-riscv-target-def", output_dir: "llvm/include/llvm/TargetParser"}
]

# Manually-maintained files that need to be copied from upstream (not generated)
# Paths are relative to KEYSTONE_ROOT/LLVM_ROOT for matching
const MANUAL_FILES = {
   AArch64: [
      "llvm/include/llvm/TargetParser/AArch64CPUFeatures.inc"
      "llvm/include/llvm/TargetParser/AArch64FeatPriorities.inc"
   ]
}

# Get used .inc files
def get_used_inc_files [] {
   cd $KEYSTONE_ROOT
   rg '#include\s+"[^"]*\.inc"' llvm --glob '*.cpp' --glob '*.h' --glob '*.inc' --no-filename
   | lines
   | each { |line|
      # #include "filename"
      let parts = ($line | parse '{_}"{file}"')
      if ($parts | is-empty) {
         null
      } else {
         $parts | get file | first
      }
   }
   | where { |x| $x != null }
   | str replace --regex 'GenRegisterInfo(Enums|MCDesc|Header|TargetDesc)\.inc$' 'GenRegisterInfo.inc'
   | uniq
}

def rewrite_namespace [file: string] {
   open --raw $file
   | str replace --regex --all '\bllvm::' 'llvm_ks::'
   | str replace --regex --all '\busing namespace llvm;' 'using namespace llvm_ks;'
   | str replace --regex --all '\bnamespace llvm\b' 'namespace llvm_ks'
   | save -f $file
}

# Only Hexagon's packet checker reads scheduling data.
def strip_sched_models [file: string] {
   let lines = (open --raw $file | lines)
   let rows = ($lines | enumerate)
   let start = ($rows | where item == "#ifdef DBGFIELD" | get index.0?)
   let end = ($rows | where item == "// Sorted (by key) array of values for CPU subtype." | get index.0?)
   if $start == null or $end == null {
      error make {msg: $"($file): scheduling tables not found"}
   }

   let text = (($lines | first $start) ++ ($lines | skip $end) | str join "\n")
   let stripped = ($text | str replace --regex '\w+SchedModels, \n(\s+)\w+WriteProcResTable, \w+WriteLatencyTable, \w+ReadAdvanceTable, \n(\s+)(?:\w+Stages, \w+OperandCycles, \w+ForwardingPaths|nullptr, nullptr, nullptr)\);' "nullptr, \n${1}nullptr, nullptr, nullptr, \n${2}nullptr, nullptr, nullptr);")
   if $stripped == $text {
      error make {msg: $"($file): MCSubtargetInfo constructor call not found"}
   }
   $"($stripped)\n" | save -f $file
}

def llvm-head-tag [] {
   do -i { cd $LLVM_ROOT; ^git describe --tags --exact-match HEAD } | complete | get stdout | str trim
}

def ensure_tblgen_built [tag: string] {
   let tblgen_binary = $"($TBLGEN_BUILD_DIR)/bin/llvm-tblgen"
   let stamp = $"($TBLGEN_BUILD_DIR)/.tag"
   let stamped = if ($stamp | path exists) { open --raw $stamp | str trim } else { "" }

   if ($tblgen_binary | path exists) and $stamped == $tag {
      print $"Using existing llvm-tblgen for ($tag): ($tblgen_binary)"
      return $tblgen_binary
   }

   print "llvm-tblgen not found, building it from source"

   cd $LLVM_ROOT

   mkdir $TBLGEN_BUILD_DIR
   cd $TBLGEN_BUILD_DIR

   print "Configuring CMake"
   let cmake_result = (do -i {
      cmake -G Ninja ../llvm -DCMAKE_BUILD_TYPE=Release -DLLVM_TARGETS_TO_BUILD="" -DLLVM_ENABLE_PROJECTS=""
   } | complete)

   if $cmake_result.exit_code != 0 {
      print $"x CMake configuration failed: ($cmake_result.stderr)"
      return null
   }

   print "Building llvm-tblgen"
   let build_result = (do -i { ninja llvm-tblgen } | complete)

   if $build_result.exit_code != 0 {
      print $"x Build failed: ($build_result.stderr)"
      return null
   }

   if ($tblgen_binary | path exists) {
      $tag | save -f $"($TBLGEN_BUILD_DIR)/.tag"
      print $"✔ Built llvm-tblgen for ($tag): ($tblgen_binary)\n"
      $tblgen_binary
   } else {
      print "x Build succeeded but binary not found"
      null
   }
}

def get_target_from_inc [inc_file: string] {
   let base = ($inc_file | path basename)
   let patterns = $TABLEGEN_TARGETS | get suffix

   for pattern in $patterns {
      if ($base | str ends-with $pattern) {
         return ($base | str replace $pattern "")
      }
   }

   null
}

def get_all_targets [] {
   let used_inc = (get_used_inc_files)

   $used_inc
   | each { |inc| get_target_from_inc $inc }
   | where { |t| $t != null }
   | uniq
}

# Regenerate .inc files
def "main regenerate" [
   ...targets: string  # Target names (e.g., AArch64 X86 ARM), empty = all targets
   --at: string = $CURRENT  # LLVM tag the clone must be checked out at
   --dry-run           # Show commands without running
] {
   let head = (llvm-head-tag)
   if $head != $at {
      error make {msg: $"($LLVM_ROOT) is at '($head)', expected ($at). Check out ($at) before regenerating."}
   }

   let tblgen = ensure_tblgen_built $at

   if $tblgen == null {
      error make {msg: "failed to build llvm-tblgen"}
   }

   cd $LLVM_ROOT

   let targets_to_process = if ($targets | is-empty) {
      print "No targets specified, regenerating ALL targets\n"
      get_all_targets
   } else {
      $targets
   }

   print $"Regenerating ($targets_to_process | length) targets\n"

   let used_inc = (get_used_inc_files)

   # Target name mapping (inc file prefix -> llvm directory name)
   const TARGET_MAP = {
      "PPC": "PowerPC",
      "R600": "AMDGPU"
   }

   let all_jobs = ($targets_to_process | each { |target|
      let llvm_target = if ($target in ($TARGET_MAP | columns)) {
         $TARGET_MAP | get $target
      } else {
         $target
      }

      # Special cases for .td filenames that don't match the directory name
      let td_filename = if $target in ($TARGET_MAP | columns) { $target } else { $llvm_target }
      let upstream_td_file = $"llvm/lib/Target/($llvm_target)/($td_filename).td"

      if not ($"($LLVM_ROOT)/($upstream_td_file)" | path exists) {
         return [{
            target: $target
            inc: null
            status: "error"
            message: "TD file not found"
         }]
      }

      let target_incs = ($used_inc | where { |inc| ($inc | path basename) | str starts-with $target })

      if ($target_incs | is-empty) {
         return [{
            target: $target
            inc: null
            status: "skipped"
            message: "No .inc files found"
         }]
      }

      $target_incs | each { |inc|
         {
            target: $target
            llvm_target: $llvm_target
            inc: $inc
            upstream_td_file: $upstream_td_file
         }
      }
   } | flatten)

   let file_results = ($all_jobs | par-each { |job|
      if $job.inc == null {
         return $job
      }

      let gen_type_list = ($TABLEGEN_TARGETS | where { |t| $job.inc | str ends-with $t.suffix })

      if ($gen_type_list | is-empty) {
         return {
            target: $job.target
            inc: $job.inc
            success: false
            error: "Unknown generator"
         }
      }

      # For TargetParserDef.inc, match by target name
      let gen_type = if ($job.inc | str ends-with "TargetParserDef.inc") {
         if $job.target in ["AArch64", "ARM"] {
            $gen_type_list | where { |t| $t.gen == "-gen-arm-target-def" } | first
         } else if $job.target == "RISCV" {
            $gen_type_list | where { |t| $t.gen == "-gen-riscv-target-def" } | first
         } else {
            $gen_type_list | first
         }
      } else {
         $gen_type_list | first
      }

      let output_file = if ($gen_type.output_dir? != null) {
        let inc_basename = ($job.inc | path basename)
        $"($KEYSTONE_ROOT)/($gen_type.output_dir)/($inc_basename)"
      } else {
        $"($KEYSTONE_ROOT)/llvm/lib/Target/($job.llvm_target)/($job.inc)"
      }
      let cmd = $"($tblgen) -I ($LLVM_ROOT)/llvm/include -I ($LLVM_ROOT)/llvm/lib/Target/($job.llvm_target) ($LLVM_ROOT)/($job.upstream_td_file) ($gen_type.gen) -o ($output_file)"

      if $dry_run {
         return {
            target: $job.target
            inc: $job.inc
            success: true
            dry_run: true
            cmd: $cmd
         }
      } else {
         let result = (do -i { bash -c $cmd } | complete)
         if $result.exit_code == 0 {
            rewrite_namespace $output_file
            if $gen_type.gen == "-gen-subtarget" and $job.llvm_target != "Hexagon" {
               strip_sched_models $output_file
            }
            let stem = ($output_file | str replace --regex '\.inc$' '')
            for suffix in ($gen_type.siblings? | default []) {
               rewrite_namespace $"($stem)($suffix)"
            }
         }
         return {
            target: $job.target
            inc: $job.inc
            success: ($result.exit_code == 0)
            error: (if $result.exit_code != 0 { $result.stderr } else { null })
         }
      }
   })

   let results = ($file_results | group-by target | items { |target, items|
      let error_items = ($items | where { |i| $i.status? != null })
      if ($error_items | length) > 0 {
         let first_error = ($error_items | first)
         return {
            target: $target
            status: $first_error.status
            message: $first_error.message
         }
      }

      # Get list of manual files for this target to exclude from failure reporting
      let manual_files = if ($target in ($MANUAL_FILES | columns)) {
         ($MANUAL_FILES | get $target | each { |f| $f | str replace "llvm/include/" "" })
      } else {
         []
      }

      # Filter out manual files from failure counts
      let successful = ($items | where success == true | length)
      let failed_items = ($items | where { |i|
         $i.success == false and not ($i.inc in $manual_files)
      })
      let failed = ($failed_items | length)

      {
         target: $target
         status: (if $failed > 0 { "partial" } else { "success" })
         successful: $successful
         failed: $failed
         details: $failed_items
      }
   })

   print "=== Results ==="
   for result in $results {
      if $result.status == "success" {
         print $"✔ ($result.target): ($result.successful) files generated"
      } else if $result.status == "partial" {
         print $"⚠  ($result.target): ($result.successful) succeeded, ($result.failed) failed"
      } else if $result.status == "skipped" {
         print $"⊘  ($result.target): ($result.message)"
      } else {
         print $"x ($result.target): ($result.message)"
      }
   }

   let failed_targets = ($results | where status in ["partial", "error"])
   if ($failed_targets | length) > 0 {
      print "\n=== Failures ==="
      for result in $failed_targets {
         print $"\n($result.target):"
         if ($result.details? | is-not-empty) {
            for detail in $result.details {
               if $detail.success == false {
                  print $"  x ($detail.inc): ($detail.error)"
               }
            }
         }
      }
      error make {msg: $"($failed_targets | length) targets failed to regenerate"}
   }

   if not $dry_run {
      let success_count = ($results | where status == "success" | length)
      print $"\n✔ Regenerated ($success_count) targets successfully"

      # Sync manual files for targets that were processed
      let manual_targets = ($targets_to_process | where { |t| $t in ($MANUAL_FILES | columns) })
      if ($manual_targets | length) > 0 {
         print $"\n=== Syncing manual files ==="
         for target in $manual_targets {
            let files = ($MANUAL_FILES | get $target)
            for file in $files {
               let src = $"($LLVM_ROOT)/($file)"
               let dst = $"($KEYSTONE_ROOT)/($file)"

               if ($src | path exists) {
                  print $"Copying: ($file)"
                  cp $src $dst
                  rewrite_namespace $dst
               } else {
                  print $"⊘ Skipping ($file): Source not found"
               }
            }
         }
      }

      print "\nReview changes with: git diff"
   }
}

def main [] {
   print "usage: nu tools/tablegen.nu regenerate [TARGETS]   (empty = all)"
}
