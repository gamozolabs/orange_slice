use std::process::Command;
use std::path::Path;

fn nasm(in_asm: &str, out_obj: &str)
{
    if Path::new(out_obj).exists() {
        std::fs::remove_file(out_obj).expect("Failed to remove old object");
    }

    let status = Command::new("nasm")
        .args(&["-f", "win32", "-o", out_obj, in_asm])
        .status().expect("Failed to run nasm");

    /* Check for command success */
    assert!(status.success(), "NASM command failed");

    /* Ensure output file was created */
    assert!(Path::new(out_obj).exists(), "NASM did not generate expected file");
}

fn main()
{
    nasm("src/asm_routines.asm", "target/asm_routines.obj");
}

