// Build script. The DEFAULT build does nothing here — only the optional
// `gpu-opencl` feature needs help locating the OpenCL import library to link
// against. Keeping this a no-op otherwise preserves the portable server/CI build.

use std::env;

fn main() {
    // Nothing to do unless the real GPU miner is being compiled in.
    if env::var("CARGO_FEATURE_GPU_OPENCL").is_err() {
        return;
    }

    // 1) Explicit override always wins (any OS / custom SDK install).
    if let Ok(dir) = env::var("OPENCL_LIB_DIR") {
        println!("cargo:rustc-link-search=native={}", dir);
        return;
    }

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();

    if target_os == "windows" && target_arch == "x86_64" {
        // Windows has an OpenCL runtime (OpenCL.dll from the GPU driver) but often
        // no SDK import library. We vendor an import lib generated from the ICD
        // loader's exports so `-lOpenCL` resolves at link time. At RUNTIME the
        // miner still uses the driver's OpenCL.dll.
        let manifest = env::var("CARGO_MANIFEST_DIR").unwrap();
        let vendor = format!("{}/engine/mining/gpu/opencl", manifest);
        println!("cargo:rustc-link-search=native={}", vendor);
        println!("cargo:rerun-if-changed={}/OpenCL.lib", vendor);
    }
    // On Linux/macOS the ICD's libOpenCL.{so,dylib} is on the standard search
    // path, so `-lOpenCL` resolves with no help from us.

    println!("cargo:rerun-if-env-changed=OPENCL_LIB_DIR");
}
