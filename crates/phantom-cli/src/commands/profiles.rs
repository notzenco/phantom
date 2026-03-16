use std::path::Path;

use anyhow::Result;

/// List available protection profiles.
pub fn run(profile_file: Option<&Path>) -> Result<()> {
    for profile in crate::profiles::list_profiles(profile_file)? {
        let passes = if profile.passes.is_empty() {
            "<none>".to_string()
        } else {
            profile.passes.join(", ")
        };
        println!("{} [{}]: {}", profile.name, profile.source, passes);
    }

    Ok(())
}
