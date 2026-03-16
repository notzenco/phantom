pub mod string_encryption;

pub use string_encryption::StringEncryptionPass;

use phantom_core::pass::Pass;

/// Return a pass by name, or `None` if unknown.
pub fn get_pass(name: &str) -> Option<Box<dyn Pass>> {
    match name {
        "string_encryption" => Some(Box::new(StringEncryptionPass::new())),
        _ => None,
    }
}

/// List all available pass names.
pub fn available_passes() -> Vec<&'static str> {
    vec!["string_encryption"]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_known_pass() {
        let pass = get_pass("string_encryption");
        assert!(pass.is_some());
        assert_eq!(pass.unwrap().info().name, "string_encryption");
    }

    #[test]
    fn get_unknown_pass() {
        assert!(get_pass("nonexistent").is_none());
    }

    #[test]
    fn available_passes_list() {
        let passes = available_passes();
        assert_eq!(passes, vec!["string_encryption"]);
    }
}
