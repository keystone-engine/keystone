#!/usr/bin/env nu

export const CURRENT = "llvmorg-23.1.1"

export def ks-root [] {
   ^jj workspace root | str trim
}

export def llvm-root [] {
   $env | get -o KS_LLVM_ROOT | default $"($env.HOME)/projects/forks/llvm-project"
}

def base-candidates [majors: int, refs: string] {
   if not ($refs | is-empty) { return ($refs | split row ",") }
   let all = (do { cd (llvm-root); ^git tag -l 'llvmorg-*' }
      | lines
      | parse 'llvmorg-{ma}.{mi}.{pa}'
      | where pa =~ '^[0-9]+$'
      | each { |r| {
         ma: ($r.ma | into int)
         tag: $"llvmorg-($r.ma).($r.mi).($r.pa)"
         n: ((($r.ma | into int) * 1000000) + (($r.mi | into int) * 1000) + ($r.pa | into int))
      } }
      | sort-by n)
   let here = ($all | where tag == $CURRENT)
   if ($here | is-empty) {
      error make {msg: $"($CURRENT) is not a tag in (llvm-root), fetch tags first"}
   }
   $all
   | where n <= ($here | first | get n)
   | group-by { |r| $r.ma | into string }
   | items { |_, rows| $rows | last }
   | sort-by n
   | last $majors
   | get tag
}

def state-dir [] {
   let d = $"(ks-root)/.llvm-sync"
   mkdir $d
   $d
}

def ns-rewrite [text: string] {
   $text
   | str replace --regex --all '\bllvm::' 'llvm_ks::'
   | str replace --regex --all '\busing namespace llvm;' 'using namespace llvm_ks;'
   | str replace --regex --all '\} // end namespace llvm\b' '} // end namespace llvm_ks'
   | str replace --regex --all '\} // namespace llvm\b' '} // namespace llvm_ks'
   | str replace --regex --all '\bnamespace llvm\b' 'namespace llvm_ks'
}

def verify-ref [ref: string] {
   let r = (do -i { cd (llvm-root); ^git rev-parse --verify $"($ref)^{commit}" } | complete)
   if $r.exit_code != 0 {
      error make {msg: $"'($ref)' is not a commit in (llvm-root), fetch tags first"}
   }
}

def show-at [ref: string, path: string] {
   let r = (do -i { cd (llvm-root); ^git show $"($ref):($path)" } | complete)
   if $r.exit_code == 0 { $r.stdout } else { null }
}

def slug [path: string] {
   $path | str replace --all "/" "_"
}

def strip-comment [l: string] {
   $l | str replace --regex '^(\s*)//\s?(.*)$' '${1}${2}'
}

def comment-col0 [ls: list] {
   $ls | each { |l| if ($l | str trim | is-empty) { "//" } else { $"// ($l)" } }
}

def comment-indent [ls: list] {
   $ls | each { |l|
      if ($l | str trim | is-empty) { "//" } else { $l | str replace --regex '^(\s*)(.*)$' '${1}// ${2}' }
   }
}

def comment-style [ls: list] {
   let c = ($ls | where { |l| ($l | str trim) starts-with "//" })
   if ($c | is-empty) { return "col0" }
   let at0 = ($c | where { |l| $l starts-with "//" } | length)
   if $at0 * 2 >= ($c | length) { "col0" } else { "indent" }
}

def fully-commented [ls: list] {
   let real = ($ls | where { |l| not ($l | str trim | is-empty) })
   (not ($real | is-empty)) and ($real | all { |l| ($l | str trim) starts-with "//" })
}

def main [] {
   print "subcommands: scope | analyze | merge | resolve | tests | audit"
   print "see the comment header of this file, or tools/README.md"
}

def "main scope" [--from: string = $CURRENT, --to: string] {
   if ($to | is-empty) { error make {msg: "--to <llvmorg-tag> is required"} }
   verify-ref $from
   verify-ref $to
   let ks = (ks-root)
   let state = (state-dir)

   let changed = (do { cd (llvm-root); ^git diff --name-status $"($from)..($to)" -- llvm/ } | lines | each { |l|
      let p = ($l | split row "\t")
      {status: ($p.0 | str substring 0..1), old: $p.1, path: ($p | last)}
   })

   let hits = ($changed | where { |r| $"($ks)/($r.path)" | path exists })
   let src = ($hits
      | where { |r| not ($r.path | str starts-with "llvm/test/") }
      | where { |r| not ($r.path | str ends-with ".inc") })
   let tests = ($hits | where { |r| ($r.status != "D") and ($r.path | str starts-with "llvm/test/") })
   let gone = ($changed
      | where { |r| $r.status in ["D" "R"] }
      | where { |r| ($r.old | str starts-with "llvm/test/") and ($"($ks)/($r.old)" | path exists) })

   $src | get path | save -f $"($state)/src.txt"
   $tests | get path | save -f $"($state)/tests.txt"
   $gone | get old | save -f $"($state)/tests-delete.txt"
   print $"($changed | length) changed upstream, ($hits | length) present here: ($src | length) source, ($tests | length) test, ($gone | length) test removed upstream"
}

def distance [path: string, ref: string, work: string] {
   let up = (show-at $ref $path)
   if $up == null { return 999999 }
   let f = $"($work)/dist_(slug $path)_(slug $ref)"
   (ns-rewrite $up) | save -f $f
   let r = (do -i { ^git diff --no-index --numstat $f $"((ks-root))/($path)" } | complete)
   rm -f $f
   if ($r.stdout | str trim | is-empty) { return 0 }
   let parts = ($r.stdout | lines | first | split row "\t")
   (($parts.0 | into int) + ($parts.1 | into int))
}

const MARGIN = 3

def "main analyze" [--majors: int = 5, --refs: string = "", --at: string = $CURRENT] {
   let state = (state-dir)
   let work = (mktemp -d)
   let candidates = (base-candidates $majors $refs)
   let files = (open $"($state)/src.txt" | lines | where { |f|
      ($f | str ends-with ".cpp") or ($f | str ends-with ".h") or ($f | str ends-with ".def")
   })

   let rows = ($files | par-each { |f|
      let ds = ($candidates | each { |r| {ref: $r, d: (distance $f $r $work)} })
      let dflt = ($ds | where ref == $at | first | get d)
      let best = ($ds | reduce -f null { |it, acc| if $acc == null or $it.d < $acc.d { $it } else { $acc } })
      let chosen = (if ($dflt - $best.d) > $MARGIN { $best.ref } else { $at })
      {file: $f, base: $chosen, gap: ($dflt - $best.d)}
   })

   rm -rf $work

   $rows | to json | save -f $"($state)/base.json"
   let odd = ($rows | where base != $at)
   print $"($odd | length) of ($rows | length) files predate ($at)"
   $odd | select file base gap | sort-by gap --reverse | print -e
}

def "main merge" [--to: string, --only: string = "", --dry-run] {
   if ($to | is-empty) { error make {msg: "--to <llvmorg-tag> is required"} }
   verify-ref $to
   let ks = (ks-root)
   let state = (state-dir)
   let work = (mktemp -d)
   let bases = (open $"($state)/base.json" | reduce -f {} { |it, acc| $acc | insert $it.file $it.base })
   let files = (if ($only | is-empty) { $bases | columns } else { open $only | lines })

   let results = ($files | par-each { |f|
      let from = ($bases | get $f)
      let base_txt = (show-at $from $f)
      let their_txt = (show-at $to $f)

      if $base_txt == null { return {file: $f, status: "no-base"} }
      if $their_txt == null { return {file: $f, status: "deleted-upstream"} }

      let bf = $"($work)/(slug $f).base"
      let tf = $"($work)/(slug $f).theirs"
      let of = $"($work)/(slug $f).ours"
      (ns-rewrite $base_txt) | save -f $bf
      (ns-rewrite $their_txt) | save -f $tf
      open --raw $"($ks)/($f)" | save -f $of

      let r = (do -i { ^git merge-file -p --diff3 --diff-algorithm=patience $of $bf $tf } | complete)
      if $r.exit_code > 127 { return {file: $f, status: "merge-error", message: $r.stderr} }
      if not $dry_run { $r.stdout | save -f $"($ks)/($f)" }
      {file: $f, base: $from, status: (if $r.exit_code == 0 { "clean" } else { "conflict" }), conflicts: $r.exit_code}
   })

   rm -rf $work

   let bad = ($results | where status == "conflict")
   $bad | get file | save -f $"($state)/conflicts.txt"
   $results | group-by status | transpose status n | update n { |r| $r.n | length } | print -e
   $bad | select file conflicts | sort-by conflicts --reverse | print -e
   let failed = ($results | where status == "merge-error")
   if not ($failed | is-empty) {
      $failed | print -e
      error make {msg: $"($failed | length) source files could not be merged"}
   }
}

def parse-conflicts [path: string] {
   let lines = (open --raw $path | lines)
   mut out = []
   mut blocks = []
   mut i = 0
   let n = ($lines | length)

   while $i < $n {
      let l = ($lines | get $i)
      if ($l | str starts-with "<<<<<<<") {
         mut ours = []
         mut base = []
         mut theirs = []
         mut phase = "ours"
         $i = $i + 1
         while $i < $n {
            let c = ($lines | get $i)
            if ($c | str starts-with "|||||||") { $phase = "base"; $i = $i + 1; continue }
            if ($c | str starts-with "=======") and $phase == "base" { $phase = "theirs"; $i = $i + 1; continue }
            if ($c | str starts-with ">>>>>>>") { break }
            if $phase == "ours" { $ours = ($ours | append $c) }
            if $phase == "base" { $base = ($base | append $c) }
            if $phase == "theirs" { $theirs = ($theirs | append $c) }
            $i = $i + 1
         }
         $blocks = ($blocks | append {ours: $ours, base: $base, theirs: $theirs})
         $out = ($out | append "\u{0}CONFLICT\u{0}")
      } else {
         $out = ($out | append $l)
      }
      $i = $i + 1
   }
   {lines: $out, blocks: $blocks}
}

def render-conflict [b: record] {
   ["<<<<<<< ours"] | append $b.ours | append ["||||||| base"] | append $b.base | append ["======="] | append $b.theirs | append [">>>>>>> theirs"]
}

def rebuild [p: record, keep: closure] {
   mut out = []
   mut bi = 0
   for l in $p.lines {
      if $l == "\u{0}CONFLICT\u{0}" {
         let b = ($p.blocks | get $bi)
         let r = (do $keep $b $bi)
         $out = (if $r == null { $out | append (render-conflict $b) } else { $out | append $r })
         $bi = $bi + 1
      } else {
         $out = ($out | append $l)
      }
   }
   ($out | str join "\n") + "\n"
}

def recomment [b: record] {
   if (comment-style $b.ours) == "col0" { comment-col0 $b.theirs } else { comment-indent $b.theirs }
}

def strip-abi [s: string] {
   $s | str replace --regex --all 'LLVM_ABI\s+' ''
}

def classify [b: record] {
   let o = ($b.ours | str join "\n")
   let s = ($b.base | str join "\n")
   let t = ($b.theirs | str join "\n")
   if $o == $t { return "both-same" }
   if $o == $s { return "ours-noop" }
   if $t == $s { return "theirs-noop" }
   if (fully-commented $b.ours) and ((($b.ours | each { |l| strip-comment $l }) | str join "\n") == $s) { return "commented" }
   if (strip-abi $t) == (strip-abi $s) { return "abi-only" }
   "semantic"
}

def resolution [b: record, kind: string] {
   match $kind {
      "both-same" => $b.ours
      "ours-noop" => $b.theirs
      "theirs-noop" => $b.ours
      "abi-only" => $b.ours
      "commented" => (recomment $b)
      _ => null
   }
}

const KINDS = ["both-same" "ours-noop" "theirs-noop" "abi-only" "commented" "semantic"]

def "main resolve" [--apply, --list: string = ""] {
   let ks = (ks-root)
   let state = (state-dir)
   let src = (if ($list | is-empty) { $"($state)/conflicts.txt" } else { $list })
   let files = (open $src | lines)

   let report = ($files | par-each { |f|
      let p = (parse-conflicts $"($ks)/($f)")
      let kinds = ($p.blocks | each { |b| classify $b })
      if $apply {
         (rebuild $p { |b, i| resolution $b ($kinds | get $i) }) | save -f $"($ks)/($f)"
      }
      {file: $f, total: ($kinds | length), semantic: ($kinds | where $it == "semantic" | length)}
      | merge ($kinds | uniq -c | reduce -f {} { |it, acc| $acc | insert $it.value $it.count })
   })

   let all = ($report | reduce -f {} { |it, acc|
      $KINDS | reduce -f $acc { |k, a| $a | upsert $k (($a | get -o $k | default 0) + ($it | get -o $k | default 0)) }
   })
   $all | transpose kind n | where n > 0 | sort-by n --reverse | print -e

   let left = ($report | where semantic > 0)
   $left | get file | save -f $"($state)/semantic.txt"
   print $"($left | length) files need judgment \(($left | get semantic | append 0 | math sum) blocks\)"
   $left | select file semantic | sort-by semantic --reverse | print -e
}

def "main tests" [] {
   print "subcommands: tests detect | tests plan | tests apply"
}

def "main tests detect" [--majors: int = 5, --refs: string = "", --sample: int = 250] {
   let ks = (ks-root)
   let candidates = (base-candidates $majors $refs)
   cd $ks
   let files = (glob "llvm/test/**/*" | where { |f| ($f | path type) == "file" }
      | each { |f| $f | str replace $"($ks)/" "" })
   let picked = ($files | shuffle | first (if ($files | length) < $sample { $files | length } else { $sample }))

   print $"keystone test files: ($files | length), sampling ($picked | length)"

   let rows = ($picked | par-each { |f|
      let ours = (open --raw $"($ks)/($f)" | hash md5)
      $candidates | each { |r|
         let up = (show-at $r $f)
         {ref: $r, ok: (if $up == null { false } else { ($up | hash md5) == $ours })}
      }
   } | flatten)

   $rows | group-by ref | transpose ref rows
   | insert matched { |r| $r.rows | where ok | length }
   | insert pct { |r| (($r.matched * 100) / ($r.rows | length)) | math round --precision 1 }
   | select ref matched pct | sort-by matched --reverse | print -e
}

def "main tests plan" [--base: string = $CURRENT, --to: string] {
   if ($to | is-empty) { error make {msg: "--to <llvmorg-tag> is required"} }
   verify-ref $base
   verify-ref $to
   let ks = (ks-root)
   let state = (state-dir)
   let files = (open $"($state)/tests.txt" | lines)

   let rows = ($files | par-each { |f|
      let ours = (open --raw $"($ks)/($f)" | hash md5)
      let b = (show-at $base $f)
      let t = (show-at $to $f)
      let bh = (if $b == null { null } else { $b | hash md5 })
      let th = (if $t == null { null } else { $t | hash md5 })

      let cat = if $th == null {
         "deleted-upstream"
      } else if $ours == $th {
         "already-current"
      } else if $bh != null and $ours == $bh {
         "clean-replace"
      } else {
         "customized"
      }
      {file: $f, cat: $cat}
   })

   $rows | group-by cat | transpose cat rows | insert n { |r| $r.rows | length } | select cat n | sort-by n --reverse | print -e
   $rows | where cat == "clean-replace" | get file | save -f $"($state)/tests-replace.txt"
   $rows | where cat == "customized" | get file | save -f $"($state)/tests-custom.txt"
}

def "main tests apply" [--base: string = $CURRENT, --to: string] {
   if ($to | is-empty) { error make {msg: "--to <llvmorg-tag> is required"} }
   verify-ref $base
   verify-ref $to
   let ks = (ks-root)
   let state = (state-dir)
   let work = (mktemp -d)

   let replace = (open $"($state)/tests-replace.txt" | lines)
   $replace | par-each { |f| (show-at $to $f) | save -f $"($ks)/($f)" } | ignore
   print $"replaced ($replace | length) uncustomised test files with the ($to) version"

   let gone = (open $"($state)/tests-delete.txt" | lines)
   $gone | each { |f| rm -f $"($ks)/($f)" } | ignore
   print $"deleted ($gone | length) test files upstream removed"

   let custom = (open $"($state)/tests-custom.txt" | lines)
   let results = ($custom | par-each { |f|
      let b = (show-at $base $f)
      let t = (show-at $to $f)
      if $b == null or $t == null { return {file: $f, status: "no-base"} }

      let bf = $"($work)/(slug $f).base"
      let tf = $"($work)/(slug $f).theirs"
      let of = $"($work)/(slug $f).ours"
      $b | save -f $bf
      $t | save -f $tf
      open --raw $"($ks)/($f)" | save -f $of

      let r = (do -i { ^git merge-file -q --ours -p $of $bf $tf } | complete)
      if $r.exit_code > 127 { return {file: $f, status: "error", message: $r.stderr} }
      $r.stdout | save -f $"($ks)/($f)"
      {file: $f, status: (if $r.exit_code == 0 { "clean" } else { "resolved-ours" })}
   })

   $results | where status == "resolved-ours" | get file | save -f $"($state)/tests-dropped-upstream.txt"

   rm -rf $work

   $results | group-by status | transpose status rows | insert n { |r| $r.rows | length } | select status n | print -e
   let bad = ($results | where status == "error")
   if not ($bad | is-empty) {
      $bad | print -e
      error make {msg: $"($bad | length) test files could not be merged"}
   }
}

def "main audit" [--before: string] {
   cd (ks-root)
   if ($before | is-empty) {
      error make {msg: "audit needs --before <rev>"}
   }
   let probe = (do -i { ^jj log -r $before --no-graph -T 'commit_id ++ "\n"' } | complete)
   if $probe.exit_code != 0 {
      error make {msg: $"'($before)' is not a revision in this repo"}
   }
   let revs = ($probe.stdout | lines | where { |l| not ($l | str trim | is-empty) })
   if ($revs | length) != 1 {
      error make {msg: $"'($before)' resolves to ($revs | length) revisions, audit needs exactly one"}
   }
   let files = (^rg -l --glob '*.h' --glob '*.cpp' --glob '*.def' '' llvm/lib llvm/include | lines)

   let hits = ($files | par-each { |f|
      let pre = (do -i { ^jj file show -r $before $f } | complete)
      if $pre.exit_code != 0 { return null }

      let pre_live = ($pre.stdout | lines
         | where { |l| not (($l | str trim) starts-with "//") }
         | where { |l| ($l | str trim | str length) > 6 })
      let now = (open --raw $f | lines)
      let now_live = ($now | where { |l| not (($l | str trim) starts-with "//") })
      let now_commented = ($now | where { |l| ($l | str trim) starts-with "//" } | each { |l| strip-comment $l })

      let lost = ($pre_live
         | where { |l| $l in $now_commented }
         | where { |l| not ($l in $now_live) }
         | where { |l| ($l | str contains "(") or ($l | str contains "class ") or ($l | str contains "enum ") })

      if ($lost | is-empty) { null } else { {file: $f, n: ($lost | length), lines: $lost} }
   } | compact)

   if ($hits | is-empty) {
      print $"commented: ok, nothing live at ($before) is commented out now"
   } else {
      print $"commented: ($hits | length) file\(s\) lost a previously-live declaration:"
      $hits | select file n | sort-by n --reverse | print -e
      $hits | to json | save -f $"((state-dir))/commented.json"
   }
}
