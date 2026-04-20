use std::env;
use std::path::PathBuf;

fn main() {
    // Get the directory containing the C codebase (1 level up)
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let parent_dir = PathBuf::from(&manifest_dir)
        .parent()
        .unwrap()
        .to_string_lossy()
        .to_string();
    //let c_lib_path = format!("{}/{}", parent_dir, "C/target") ; 
    let c_lib_path = format!("{}/C/target", parent_dir)  ; 
    dbg!(&c_lib_path) ; 
    // Tell cargo to look for C libraries in the parent directory
    println!("cargo:rustc-link-search=native={}", c_lib_path);

    // Add the C header directory
    //println!("cargo:rustc-link-search={}/include", c_lib_dir);

    // Link against C library (adjust library name as needed)
    // println!("cargo:rustc-link-lib=static=your_c_lib");
    println!("cargo:rustc-link-lib=static=loader");
    println!("cargo:rustc-link-lib=bpf");

    // Tell cargo to rebuild if C files change
    println!("cargo:rerun-if-changed={}", c_lib_path);
}
