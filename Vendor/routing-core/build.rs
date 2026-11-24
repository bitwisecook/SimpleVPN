// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

use std::{
    env,
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

fn run(tool: &mut Command) {
    let status = tool.status().unwrap_or_else(|e| panic!("{tool:?}: {e}"));
    assert!(status.success(), "{tool:?} exited with {status}");
}

fn collect(dir: &Path) -> Vec<PathBuf> {
    println!("cargo:rerun-if-changed={}", dir.display());
    let mut files: Vec<_> = fs::read_dir(dir)
        .expect("policy image directory")
        .map(|f| f.expect("read directory entry").path())
        .filter(|p| p.extension().is_some_and(|e| e == "rcr"))
        .collect();
    files.sort();
    files
}

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("cargo output directory"));
    let mut files = collect(Path::new("policies"));
    println!("cargo:rerun-if-env-changed=SIMPLEVPN_AOT_DIR");
    if let Some(dir) = env::var_os("SIMPLEVPN_AOT_DIR") {
        files.extend(collect(Path::new(&dir)));
    }
    println!("cargo:rerun-if-env-changed=CC");
    println!("cargo:rerun-if-env-changed=AR");
    println!("cargo:rerun-if-env-changed=SIMPLEVPN_LLVM_OPT");
    let opt = env::var_os("SIMPLEVPN_LLVM_OPT").map(PathBuf::from);
    // Textual optimized IR can contain version-specific LLVM attributes.
    // Always use clang from the same toolchain as an explicitly selected opt.
    let cc = opt
        .as_ref()
        .map(|path| path.with_file_name("clang").into_os_string())
        .or_else(|| env::var_os("CC"))
        .unwrap_or_else(|| "clang".into());
    let target = env::var("TARGET").expect("target triple");
    assert!(files.len() <= 128, "at most 128 signed native images");
    let mut registry = String::from("pub(super) fn select(image: &[u8]) -> Option<Kernel> {\n");
    let mut objects = Vec::new();
    let mut total = 0;
    for (i, path) in files.iter().enumerate() {
        let size = fs::metadata(path).unwrap().len();
        total += size;
        assert!(
            size <= 16 << 20 && total <= 64 << 20,
            "excessive policy image size"
        );
        let image = fs::read(path).unwrap();
        let ir = routing_ir::llvm::compile(&image, i)
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let input = out.join(format!("policy_{i}.ll"));
        let object = out.join(format!("policy_{i}.o"));
        fs::write(&input, ir).unwrap();
        if let Some(opt) = &opt {
            let optimized = out.join(format!("policy_{i}.optimized.ll"));
            run(Command::new(opt)
                .args(["-S", "-passes=sroa,mem2reg,sccp,gvn,adce,simplifycfg"])
                .arg(&input)
                .arg("-o")
                .arg(&optimized));
            fs::rename(optimized, &input).unwrap();
        }
        // Clang's standard O2 pipeline is available in the Xcode toolchain. It
        // promotes slots to SSA, propagates constants, numbers values and runs DCE.
        run(Command::new(&cc)
            .args([
                "-target",
                &target,
                "-Wno-override-module",
                "-O2",
                "-c",
                "-x",
                "ir",
            ])
            .arg(&input)
            .arg("-o")
            .arg(&object));
        let path = fs::canonicalize(path).unwrap();
        writeln!(registry," unsafe extern \"C\" {{ fn rc_policy_{i}(context: *mut c_void, limit: u32); }}\n if image == include_bytes!({path:?}) {{ return Some(rc_policy_{i}); }}").unwrap();
        objects.push(object);
    }
    registry.push_str(" None\n}\n");
    fs::write(out.join("policy_registry.rs"), registry).unwrap();
    if !objects.is_empty() {
        let archive = out.join("libroute_policies.a");
        if archive.exists() {
            fs::remove_file(&archive).unwrap();
        }
        run(
            Command::new(env::var_os("AR").unwrap_or_else(|| "ar".into()))
                .arg("crs")
                .arg(&archive)
                .args(&objects),
        );
        println!("cargo:rustc-link-search=native={}", out.display());
        println!("cargo:rustc-link-lib=static=route_policies");
    }
}
