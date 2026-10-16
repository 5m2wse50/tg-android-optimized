fn main() {
    // Generates UniFFI scaffolding into the crate at build time (runs in CI, not locally).
    uniffi_build::generate_scaffolding("./src/lib.rs")
        .expect("uniffi scaffolding generation failed");
}
