//! Prints the Blake3 digest (hex) of a file; edge/rules/build.sh uses it to pin rule components.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args().nth(1).ok_or("usage: edge-hash <file>")?;
    println!("{}", difme_edge_core::integrity::hex_digest(&std::fs::read(path)?));
    Ok(())
}
