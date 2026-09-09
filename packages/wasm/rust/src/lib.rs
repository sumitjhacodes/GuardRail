use wasm_bindgen::prelude::*;

/// Placeholder WASM entry — expand with compiled SQL/XSS automata when rustc is available.
#[wasm_bindgen]
pub fn match_union_select(input: &str) -> bool {
    input.to_ascii_uppercase().contains("UNION SELECT")
}

#[wasm_bindgen]
pub fn version() -> String {
    "0.3.0".into()
}
