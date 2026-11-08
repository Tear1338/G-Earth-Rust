use std::{env, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=resources/gearth_icon.res");
    println!("cargo:rerun-if-env-changed=WINDRES");
    if env::var_os("CARGO_FEATURE_DESKTOP").is_none()
        || env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows")
    {
        return;
    }
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let resource = manifest.join("resources/gearth_icon.res");
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    let resource = if target_env == "msvc" {
        resource
    } else if target_env == "gnu" {
        let target = env::var("TARGET").unwrap();
        let compiler = env::var_os("WINDRES").unwrap_or_else(|| {
            if env::var("HOST").unwrap_or_default().contains("windows") {
                "windres".into()
            } else {
                let prefix = match target.as_str() {
                    "x86_64-pc-windows-gnu" => "x86_64-w64-mingw32",
                    "i686-pc-windows-gnu" => "i686-w64-mingw32",
                    _ => panic!("unsupported Windows GNU target: {target}"),
                };
                format!("{prefix}-windres").into()
            }
        });
        let output = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("gearth_icon.o");
        let format = match target.as_str() {
            "x86_64-pc-windows-gnu" => "pe-x86-64",
            "i686-pc-windows-gnu" => "pe-i386",
            _ => panic!("unsupported Windows GNU target: {target}"),
        };
        let status = Command::new(compiler)
            .arg("-J")
            .arg("res")
            .arg("-O")
            .arg("coff")
            .arg("-F")
            .arg(format)
            .arg("-i")
            .arg(&resource)
            .arg("-o")
            .arg(&output)
            .status()
            .expect("failed to run windres for the Windows application icon");
        assert!(
            status.success(),
            "windres failed to compile the Windows application icon"
        );
        output
    } else {
        panic!("unsupported Windows toolchain for the application icon: {target_env}");
    };
    println!(
        "cargo:rustc-link-arg-bin=gearth-desktop={}",
        resource.display()
    );
}
