// SYNTHETIC FIXTURE — fake Rust to exercise critlover's greppers; not a real program, not exploitable.
// One unsafe block so sink-grep.sh's `native` class has a deterministic Rust hit.
fn copy_from_raw(p: *const u8, n: usize) -> &'static [u8] {
    unsafe { std::slice::from_raw_parts(p, n) }  // native (rust unsafe) sink
}
