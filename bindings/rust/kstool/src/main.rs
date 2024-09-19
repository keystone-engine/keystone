use argh::FromArgs;
use std::ffi::CString;
use std::fmt;
use std::io;
use std::str::FromStr;

use keystone::{Arch, Keystone, Mode};

struct InvalidFromat;

impl fmt::Display for InvalidFromat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "one of (raw, hex)")
    }
}

impl FromStr for FormatOuput {
    type Err = InvalidFromat;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let this = match s {
            "raw" => Self::Raw,
            "hex" => Self::Hex,
            _ => return Err(InvalidFromat),
        };
        Ok(this)
    }
}

#[derive(Clone, Copy, Default)]
enum FormatOuput {
    #[default]
    Hex,
    Raw,
    // String, // as python str
    // Elf,
}

#[derive(FromArgs)]
/// Assemble shellcode into bytes
struct Args {
    // print version
    //#[argh(switch, short = 'v')]
    //version: bool,
    /// output format (defaults to hex for ttys, otherwise raw)
    #[argh(option, short = 'f')]
    format: Option<FormatOuput>,
    // output filename (defaults to stdout)
    //#[argh(option, short = 'o')]
    //output: Option<PathBuf>,
    /// arch/mode (defaults to x64)
    #[argh(option, short = 'c')]
    mode: Option<String>,
    /// input filename
    #[argh(switch, short = 'i')]
    infile: bool,
    /// assembly strings or infile with -i
    #[argh(positional)]
    asm: String,
}

fn main() -> Result<(), i32> {
    let args: Args = argh::from_env();
    let mode = args.mode.as_deref().unwrap_or("x64");
    let (arch, mode) = match mode {
        "x16" => (Arch::X86, Mode::MODE_16),
        "x32" => (Arch::X86, Mode::MODE_32),
        "x64" => (Arch::X86, Mode::MODE_64),
        "arm" => (Arch::ARM, Mode::ARM | Mode::LITTLE_ENDIAN),
        "armbe" => (Arch::ARM, Mode::ARM | Mode::BIG_ENDIAN),
        "thumb" => (Arch::ARM, Mode::THUMB | Mode::LITTLE_ENDIAN),
        "thumbbe" => (Arch::ARM, Mode::THUMB | Mode::LITTLE_ENDIAN),
        "armv8" => (Arch::ARM, Mode::ARM | Mode::LITTLE_ENDIAN | Mode::V8),
        "armv8be" => (Arch::ARM, Mode::ARM | Mode::BIG_ENDIAN | Mode::V8),
        "thumbv8" => (Arch::ARM, Mode::THUMB | Mode::LITTLE_ENDIAN | Mode::V8),
        "thumbv8be" => (Arch::ARM, Mode::THUMB | Mode::BIG_ENDIAN | Mode::V8),
        "arm64" => (Arch::ARM64, Mode::LITTLE_ENDIAN),
        "hexagon" => (Arch::HEXAGON, Mode::BIG_ENDIAN),
        "mips" => (Arch::MIPS, Mode::MIPS32 | Mode::LITTLE_ENDIAN),
        "mipsbe" => (Arch::MIPS, Mode::MIPS32 | Mode::BIG_ENDIAN),
        "mips64" => (Arch::MIPS, Mode::LITTLE_ENDIAN),
        "mips64be" => (Arch::MIPS, Mode::BIG_ENDIAN),
        "ppc32be" => (Arch::PPC, Mode::PPC32 | Mode::BIG_ENDIAN),
        "ppc64" => (Arch::PPC, Mode::PPC64 | Mode::LITTLE_ENDIAN),
        "ppc64be" => (Arch::PPC, Mode::PPC64 | Mode::BIG_ENDIAN),
        "sparc" => (Arch::SPARC, Mode::SPARC32 | Mode::LITTLE_ENDIAN),
        "sparcbe" => (Arch::SPARC, Mode::SPARC32 | Mode::BIG_ENDIAN),
        "sparc64be" => (Arch::SPARC, Mode::SPARC64 | Mode::BIG_ENDIAN),
        "systemz" => (Arch::SYSTEMZ, Mode::BIG_ENDIAN),
        "evm" => (Arch::EVM, Mode::LITTLE_ENDIAN),
        "riscv32" => (Arch::RISCV, Mode::RISCV32 | Mode::LITTLE_ENDIAN),
        "riscv64" => (Arch::RISCV, Mode::RISCV64 | Mode::LITTLE_ENDIAN),
        _ => {
            eprintln!("invalid arch/mode: {mode}");
            return Err(1);
        }
    };
    let engine = Keystone::new(arch, mode).expect("could not initialize Keystone engine");

    let asm = if args.infile {
        let Ok(data) = std::fs::read(&args.asm) else {
            panic!("cannot read filename {path}", path = &args.asm);
        };
        CString::from_vec_with_nul(data).expect("file shouldn't contains NUL bytes")
    } else {
        CString::new(args.asm).expect("assembly contains NUL bytes")
    };

    let result = engine.asm(&asm, 0).expect("could not assemble");
    let output_format = args.format.unwrap_or(FormatOuput::default());
    match output_format {
        FormatOuput::Hex => {
            println!("{result}");
        }
        FormatOuput::Raw => {
            use io::Write;
            let stdout = io::stdout();
            let mut handle = stdout.lock();
            handle
                .write_all(&result.as_bytes())
                .expect("cannot write to stdout");
        }
    }

    Ok(())
}
