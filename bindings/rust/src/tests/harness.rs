extern crate alloc;
extern crate std;

use alloc::{
   borrow::ToOwned as _,
   string::{
      String,
      ToString as _,
   },
   vec::Vec,
};
use std::{
   fs,
   path::{
      Path,
      PathBuf,
   },
   println,
   sync::{
      Arc,
      atomic::{
         AtomicBool,
         Ordering,
      },
   },
};

use crate::{
   Keystone,
   Result,
};

pub struct ParsedTest<M> {
   pub instruction: String,
   pub encoding:    Vec<u8>,
   pub mode:        M,
}

fn strip_hex_prefix(text: &str) -> &str {
   text.strip_prefix("0x").unwrap_or(text)
}

pub fn parse_encoding_bytes(bracket_contents: &str) -> Option<Vec<u8>> {
   let trimmed = bracket_contents
      .trim()
      .trim_start_matches('[')
      .trim_end_matches(']');

   if trimmed.is_empty() {
      return None;
   }

   let mut out = Vec::new();
   for raw in trimmed.split(',') {
      let item = raw.trim();
      if item.is_empty() {
         return None;
      }

      if item == "A" {
         return None;
      }
      if let Some((before, after)) = item.split_once('\'') {
         if after.trim_end_matches('\'').contains('A') {
            return None;
         }
         return parse_byte(strip_hex_prefix(before.trim())).map(|byte| {
            let mut bytes = out.clone();
            bytes.push(byte);
            bytes
         });
      }

      let body = strip_hex_prefix(item);
      if body.is_empty() {
         return None;
      }

      if let Some(bin) = item.strip_prefix("0b") {
         if bin.chars().any(|ch| ch != '0' && ch != '1') {
            return None;
         }
         out.push(u8::from_str_radix(bin, 2).ok()?);
         continue;
      }

      if body.chars().any(|ch| ch == 'A') {
         return None;
      }

      out.push(parse_byte(body)?);
   }

   if out.is_empty() { None } else { Some(out) }
}

fn parse_byte(text: &str) -> Option<u8> {
   u8::from_str_radix(text, 16).ok()
}

fn strip_marker(text: &str) -> &str {
   let trimmed = text.trim_start();
   for marker in ["//", ";", "#"] {
      if let Some(rest) = trimmed.strip_prefix(marker) {
         return rest.trim_start();
      }
   }
   trimmed
}

fn check_body<'text>(line: &'text str, prefix: &str) -> Option<&'text str> {
   strip_marker(line).strip_prefix(strip_marker(prefix))
}

pub fn all_run_lines_negate(content: &str, run_prefixes: &[&str]) -> bool {
   let lines: Vec<&str> = content
      .lines()
      .filter(|line| {
         let trimmed = line.trim();
         run_prefixes
            .iter()
            .any(|prefix| trimmed.starts_with(prefix))
            && line.contains("llvm-mc")
      })
      .collect();
   !lines.is_empty() && lines.iter().all(|entry| entry.contains(" not "))
}

pub fn header_lines(content: &str, n: usize) -> impl Iterator<Item = &str> {
   content.lines().take(n).map(str::trim)
}

pub fn extract_flag<'text>(line: &'text str, flag: &str) -> Option<&'text str> {
   let after = line.split(flag).nth(1)?;
   let val = after.split_whitespace().next()?;
   if val.is_empty() { None } else { Some(val) }
}

fn collect_test_files(dir: impl AsRef<Path>) -> Vec<PathBuf> {
   let mut out = Vec::new();
   walk(dir.as_ref(), &mut out);
   out.sort();
   out
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
   let Ok(entries) = fs::read_dir(dir) else {
      return;
   };
   for entry in entries.flatten() {
      let path = entry.path();
      if path.is_dir() {
         walk(&path, out);
      } else if path.extension().is_some_and(|ext| ext == "s") {
         out.push(path);
      }
   }
}

pub fn assemble_and_assert(
   ks: &mut Keystone,
   instruction: &str,
   expected: &[u8],
   source: &str,
   mode_label: &str,
) {
   println!("Testing instruction: {instruction} with encoding: {expected:?} in mode: {mode_label}");
   match assemble(ks, instruction) {
      Ok(bytes) => {
         assert_eq!(
            bytes, expected,
            "{mode_label} Instruction '{instruction}' produced incorrect encoding from file \
             {source}"
         );
      },
      Err(err) => {
         panic!("Failed to assemble instruction '{instruction}' from file {source}: {err}");
      },
   }
}

const REBASE: u64 = 0x1234_5670;

/// Keystone reads a numeric branch target as an absolute address, so only these
/// encodings legitimately change with the base.
fn base_dependent(instruction: &str) -> bool {
   instruction.lines().any(|raw| {
      let line = raw.trim().to_lowercase();
      let (mnemonic, operands) = line.split_once(char::is_whitespace).unwrap_or((&line, ""));
      ["b", "j", "cb", "tb", "call", "adr"]
         .iter()
         .any(|prefix| mnemonic.starts_with(prefix))
         || mnemonic.ends_with("sppc")
         || (mnemonic == "ldr"
            && operands
               .split_once(',')
               .is_some_and(|(_, rest)| rest.trim().starts_with('#')))
   })
}

/// Assembles at 0 with external symbols as 0, and again at [`REBASE`] unless
/// the instruction is [`base_dependent`] or external, asserting both match.
#[expect(
   clippy::panic_in_result_fn,
   reason = "a rebased mismatch is a test failure, not an assembly error"
)]
pub fn assemble(ks: &mut Keystone, instruction: &str) -> Result<Vec<u8>> {
   let external = Arc::new(AtomicBool::new(false));
   let seen = Arc::clone(&external);
   ks.set_symbol_resolver(move |_, value| {
      seen.store(true, Ordering::Relaxed);
      *value = 0;
      true
   })?;

   let bytes = ks.asm(instruction.as_bytes(), 0)?.bytes;
   if !base_dependent(instruction) && !external.load(Ordering::Relaxed) {
      let rebased = ks
         .asm(instruction.as_bytes(), REBASE)
         .map(|assembly| assembly.bytes);
      assert_eq!(
         rebased.as_deref().ok(),
         Some(bytes.as_slice()),
         "'{instruction}' changed when assembled at {REBASE:#x}"
      );
   }
   Ok(bytes)
}

pub fn inline_check<'line>(
   line: &'line str,
   prefix: &str,
   separator: &str,
) -> Option<(&'line str, Vec<u8>)> {
   let next = std::format!("{}-NEXT:", prefix.trim_end_matches(':'));
   let body = check_body(line, prefix).or_else(|| check_body(line, &next))?;
   let (inst, enc) = body.trim().split_once(strip_marker(separator))?;
   let instruction = inst.trim().trim_end_matches(['#', ';', '/']).trim();
   if instruction.is_empty() {
      return None;
   }
   Some((instruction, enc_of(enc, Enc::Bracket)?))
}

pub fn parse_inline_check_lines<M>(
   content: &str,
   comment_prefix: &str,
   enc_separator: &str,
   mode: M,
) -> Vec<ParsedTest<M>>
where
   M: Copy,
{
   content
      .lines()
      .filter_map(|line| inline_check(line.trim(), comment_prefix, enc_separator))
      .map(|(instruction, encoding)| {
         ParsedTest {
            instruction: instruction.to_owned(),
            encoding,
            mode,
         }
      })
      .collect()
}

fn split_instruction<'line>(
   line: &'line str,
   inst_prefix: &str,
   enc_prefix: &str,
) -> Option<&'line str> {
   if check_body(line, enc_prefix).is_some() {
      return None;
   }
   check_body(line, inst_prefix)
      .map(str::trim)
      .filter(|body| !body.is_empty() && !body.contains("encoding:"))
}

pub fn parse_split_check_lines<M>(
   content: &str,
   inst_prefix: &str,
   enc_prefix: &str,
   mode: M,
) -> Vec<ParsedTest<M>>
where
   M: Copy,
{
   let lines: Vec<&str> = content.lines().map(str::trim).collect();
   let mut out = Vec::new();
   for (idx, line) in lines.iter().enumerate() {
      let Some(instruction) = split_instruction(line, inst_prefix, enc_prefix) else {
         continue;
      };
      if lines
         .get(idx + 1)
         .is_some_and(|next| split_instruction(next, inst_prefix, enc_prefix).is_some())
      {
         continue;
      }
      let found = lines
         .iter()
         .skip(idx + 1)
         .take(5)
         .take_while(|cand| split_instruction(cand, inst_prefix, enc_prefix).is_none())
         .find_map(|cand| check_body(cand, enc_prefix))
         .and_then(|body| enc_of(body, Enc::Bracket));
      if let Some(encoding) = found {
         out.push(ParsedTest {
            instruction: instruction.to_owned(),
            encoding,
            mode,
         });
      }
   }
   out
}

pub fn has_mcpu_flag(content: &str) -> bool {
   header_lines(content, 30).any(|line| line.contains("-mcpu="))
}

pub fn reset_and_apply_features(ks: &mut Keystone, features: Option<&str>, source: &str) {
   let feat = features.unwrap_or("");
   if !feat.is_empty() {
      println!("Setting features `{feat}` from file {source}");
   }
   ks.set_feature(feat)
      .unwrap_or_else(|err| panic!("Failed to set features `{feat}` from file {source}: {err}"));
}

#[derive(Clone, Copy)]
pub enum Shape {
   Inline {
      check: &'static str,
      enc:   &'static str,
   },
   Split {
      inst: &'static str,
      enc:  &'static str,
   },
}

pub fn fixtures(dir: &str, run_prefixes: &[&str], skip_mcpu: bool) -> Vec<(String, String)> {
   let root = std::format!("{}/../../llvm/test/MC/{dir}", env!("CARGO_MANIFEST_DIR"));
   collect_test_files(&root)
      .into_iter()
      .filter_map(|path| {
         let content = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("Could not read fixture {}\n{err}", path.display()));
         if all_run_lines_negate(&content, run_prefixes) {
            return None;
         }
         if skip_mcpu && has_mcpu_flag(&content) {
            return None;
         }
         Some((path.display().to_string(), content))
      })
      .collect()
}

pub fn mattr(content: &str, run_prefixes: &[&str]) -> Option<String> {
   for line in header_lines(content, 20) {
      if !run_prefixes.iter().any(|prefix| line.starts_with(prefix)) || line.contains(" not ") {
         continue;
      }
      // Both `-mattr=+x` and `-mattr +x` appear in the fixtures.
      let mut vals: Vec<&str> = Vec::new();
      let mut toks = line.split_whitespace().peekable();
      while let Some(tok) = toks.next() {
         if let Some(val) = tok
            .strip_prefix("-mattr=")
            .or_else(|| tok.strip_prefix("--mattr="))
         {
            if !val.is_empty() {
               vals.push(val);
            }
         } else if tok == "-mattr" || tok == "--mattr" {
            if let Some(peeked) = toks.peek() {
               vals.push(peeked);
            }
         }
      }
      if !vals.is_empty() {
         return Some(vals.join(","));
      }
   }
   None
}

fn parse_cases<M>(content: &str, shapes: &[Shape], mode: M) -> Vec<ParsedTest<M>>
where
   M: Copy,
{
   let mut out = Vec::new();
   for shape in shapes {
      match *shape {
         Shape::Inline { check, enc } => {
            out.extend(parse_inline_check_lines(content, check, enc, mode));
         },
         Shape::Split { inst, enc } => {
            out.extend(parse_split_check_lines(content, inst, enc, mode));
         },
      }
   }
   out
}

pub fn run_cases(
   ks: &mut Keystone,
   content: &str,
   shapes: &[Shape],
   label: &'static str,
   source: &str,
) {
   for case in parse_cases(content, shapes, label) {
      assemble_and_assert(ks, &case.instruction, &case.encoding, source, case.mode);
   }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Enc {
   Bracket,
   Word,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Dir {
   Above,
   Below,
   #[cfg(feature = "arch_amdgpu")]
   BelowGuarded,
   Auto,
}

#[expect(
   clippy::little_endian_bytes,
   reason = "fixture word encoding is explicitly little endian"
)]
pub fn enc_of(line: &str, enc: Enc) -> Option<Vec<u8>> {
   match enc {
      Enc::Bracket => {
         let body = line.split("encoding:").nth(1).unwrap_or(line);
         let start = body.find('[')?;
         let end = body.get(start..)?.find(']')?;
         parse_encoding_bytes(body.get(start..=start + end)?)
      },
      Enc::Word => {
         let (word, remaining) = line.trim().split_once(char::is_whitespace)?;
         let rest = remaining.trim();
         if word.len() != 8 || !word.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return None;
         }
         if !rest.starts_with('{') || !rest.ends_with('}') {
            return None;
         }
         Some(u32::from_str_radix(word, 16).ok()?.to_le_bytes().to_vec())
      },
   }
}

pub fn parse_adjacent<M>(
   content: &str,
   check: &str,
   enc: Enc,
   dir: Dir,
   is_src: fn(&str) -> bool,
   mode: M,
) -> Vec<ParsedTest<M>>
where
   M: Copy,
{
   let lines: Vec<&str> = content.lines().map(str::trim).collect();
   let next = std::format!("{}-NEXT:", check.trim_end_matches(':'));

   let src_near = |i: usize, down: bool| -> Option<&str> {
      let mut j = i;
      for _ in 0_usize..2_usize {
         j = if down { j + 1 } else { j.checked_sub(1)? };
         let line = *lines.get(j)?;
         if is_src(line) {
            return Some(line);
         }
         if !line.is_empty() {
            return None;
         }
      }
      None
   };

   let checks: Vec<(usize, Vec<u8>)> = lines
      .iter()
      .enumerate()
      .filter_map(|(i, line)| {
         let body = check_body(line, check).or_else(|| check_body(line, next.as_str()))?;
         enc_of(body, enc).map(|bytes| (i, bytes))
      })
      .collect();

   let resolved_dir = if dir == Dir::Auto {
      let below = checks
         .iter()
         .filter(|&&(i, _)| src_near(i, true).is_some())
         .count();
      let above = checks
         .iter()
         .filter(|&&(i, _)| src_near(i, false).is_some())
         .count();
      if below >= above {
         Dir::Below
      } else {
         Dir::Above
      }
   } else {
      dir
   };

   checks
      .into_iter()
      .filter_map(|(i, encoding)| {
         let src = match resolved_dir {
            Dir::Above | Dir::Auto => src_near(i, false),
            Dir::Below => src_near(i, true),
            #[cfg(feature = "arch_amdgpu")]
            Dir::BelowGuarded => {
               src_near(i, true)
                  .filter(|_| {
                     lines
                        .get(i + 2)
                        .is_none_or(|next_line| next_line.is_empty() || !is_src(next_line))
                  })
                  .or_else(|| src_near(i, false))
            },
         }?;
         Some(ParsedTest {
            instruction: src.to_owned(),
            encoding,
            mode,
         })
      })
      .collect()
}
