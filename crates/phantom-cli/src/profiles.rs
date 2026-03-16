use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;

const BUILTIN_PROFILES: &[(&str, &[&str])] = &[("strings", &["string_encryption"])];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileDefinition {
    pub name: String,
    pub passes: Vec<String>,
    pub source: ProfileSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileSource {
    BuiltIn,
    File(PathBuf),
}

impl std::fmt::Display for ProfileSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BuiltIn => write!(f, "built-in"),
            Self::File(path) => write!(f, "file {}", path.display()),
        }
    }
}

#[derive(Debug, Deserialize)]
struct ProfilesFile {
    #[serde(default)]
    profiles: BTreeMap<String, Vec<String>>,
}

/// Resolve the effective pass list for `protect`.
pub fn resolve_passes(
    profile_name: Option<&str>,
    profile_file: Option<&Path>,
    explicit_passes: &[String],
) -> Result<Vec<String>> {
    let mut passes = Vec::new();

    if let Some(profile_name) = profile_name {
        let profile = find_profile(profile_name, profile_file)?;
        validate_passes(
            &profile.passes,
            &format!("profile '{}' ({})", profile.name, profile.source),
        )?;
        passes.extend(profile.passes);
    }

    validate_passes(explicit_passes, "explicit --passes")?;
    passes.extend(explicit_passes.iter().cloned());

    Ok(stable_dedupe(passes))
}

/// List built-in profiles and any profiles loaded from an explicit TOML file.
pub fn list_profiles(profile_file: Option<&Path>) -> Result<Vec<ProfileDefinition>> {
    let mut profiles = builtin_profiles()?;
    if let Some(path) = profile_file {
        profiles.extend(load_file_profiles(path)?);
    }
    Ok(profiles)
}

fn find_profile(name: &str, profile_file: Option<&Path>) -> Result<ProfileDefinition> {
    if let Some(profile) = builtin_profiles()?
        .into_iter()
        .find(|profile| profile.name == name)
    {
        return Ok(profile);
    }

    if let Some(path) = profile_file {
        let file_profiles = load_file_profiles(path)?;
        if let Some(profile) = file_profiles
            .into_iter()
            .find(|profile| profile.name == name)
        {
            return Ok(profile);
        }

        let available = list_profile_names(path)?;
        bail!(
            "Unknown profile '{name}' in {}. Available profiles: {}",
            path.display(),
            available.join(", ")
        );
    }

    let builtin_names = builtin_profiles()?
        .into_iter()
        .map(|profile| profile.name)
        .collect::<Vec<_>>();
    bail!(
        "Unknown profile '{name}'. Available built-in profiles: {}",
        builtin_names.join(", ")
    )
}

fn builtin_profiles() -> Result<Vec<ProfileDefinition>> {
    let profiles = BUILTIN_PROFILES
        .iter()
        .map(|(name, passes)| ProfileDefinition {
            name: (*name).to_string(),
            passes: passes.iter().map(|pass| (*pass).to_string()).collect(),
            source: ProfileSource::BuiltIn,
        })
        .collect::<Vec<_>>();

    for profile in &profiles {
        validate_passes(
            &profile.passes,
            &format!("profile '{}' ({})", profile.name, profile.source),
        )?;
    }

    Ok(profiles)
}

fn load_file_profiles(path: &Path) -> Result<Vec<ProfileDefinition>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read profile file {}", path.display()))?;
    let parsed: ProfilesFile = toml::from_str(&text)
        .with_context(|| format!("Failed to parse profile file {}", path.display()))?;

    let builtin_names = BUILTIN_PROFILES
        .iter()
        .map(|(name, _)| *name)
        .collect::<HashSet<_>>();

    let mut profiles = Vec::with_capacity(parsed.profiles.len());
    for (name, passes) in parsed.profiles {
        if builtin_names.contains(name.as_str()) {
            bail!(
                "Profile '{}' in {} collides with a built-in profile name",
                name,
                path.display()
            );
        }

        let profile = ProfileDefinition {
            name,
            passes,
            source: ProfileSource::File(path.to_path_buf()),
        };
        validate_passes(
            &profile.passes,
            &format!("profile '{}' ({})", profile.name, profile.source),
        )?;
        profiles.push(profile);
    }

    Ok(profiles)
}

fn list_profile_names(path: &Path) -> Result<Vec<String>> {
    let mut names = builtin_profiles()?
        .into_iter()
        .map(|profile| profile.name)
        .collect::<Vec<_>>();
    names.extend(
        load_file_profiles(path)?
            .into_iter()
            .map(|profile| profile.name),
    );
    Ok(names)
}

fn validate_passes(passes: &[String], owner: &str) -> Result<()> {
    let available = phantom_passes::available_passes()
        .into_iter()
        .collect::<HashSet<_>>();

    for pass_name in passes {
        if !available.contains(pass_name.as_str()) {
            return Err(anyhow!("{owner} references unknown pass '{}'", pass_name));
        }
    }

    Ok(())
}

fn stable_dedupe(passes: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut deduped = Vec::with_capacity(passes.len());

    for pass in passes {
        if seen.insert(pass.clone()) {
            deduped.push(pass);
        }
    }

    deduped
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_profile_path(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_nanos();
        std::env::temp_dir().join(format!("phantom-{name}-{unique}.toml"))
    }

    fn write_profile_file(name: &str, contents: &str) -> PathBuf {
        let path = temp_profile_path(name);
        std::fs::write(&path, contents).expect("write temp profile");
        path
    }

    #[test]
    fn resolves_builtin_profile() {
        let passes = resolve_passes(Some("strings"), None, &[]).expect("resolve builtin");
        assert_eq!(passes, vec!["string_encryption"]);
    }

    #[test]
    fn resolves_file_profile() {
        let path = write_profile_file(
            "custom-profile",
            "[profiles]\nlayered = [\"string_encryption\"]\n",
        );
        let passes =
            resolve_passes(Some("layered"), Some(&path), &[]).expect("resolve file profile");

        assert_eq!(passes, vec!["string_encryption"]);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn malformed_profile_file_errors() {
        let path = write_profile_file("malformed-profile", "[profiles\nbroken = [");
        let err = list_profiles(Some(&path)).expect_err("malformed file should fail");

        assert!(err.to_string().contains("Failed to parse profile file"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn unknown_profile_errors() {
        let err = resolve_passes(Some("missing"), None, &[]).expect_err("unknown profile");
        assert!(err.to_string().contains("Unknown profile 'missing'"));
    }

    #[test]
    fn builtin_name_collision_errors() {
        let path = write_profile_file(
            "collision-profile",
            "[profiles]\nstrings = [\"string_encryption\"]\n",
        );
        let err = list_profiles(Some(&path)).expect_err("collision should fail");

        assert!(err
            .to_string()
            .contains("collides with a built-in profile name"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn unknown_pass_in_profile_errors_with_source() {
        let path = write_profile_file(
            "unknown-pass-profile",
            "[profiles]\nbad = [\"missing_pass\"]\n",
        );
        let err = list_profiles(Some(&path)).expect_err("unknown pass should fail");
        let rendered = err.to_string();

        assert!(rendered.contains("profile 'bad'"));
        assert!(rendered.contains("unknown pass 'missing_pass'"));
        assert!(rendered.contains(&path.display().to_string()));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn merge_preserves_order_and_dedupes() {
        let passes = resolve_passes(
            Some("strings"),
            None,
            &[
                "string_encryption".to_string(),
                "string_encryption".to_string(),
            ],
        )
        .expect("resolve merged passes");

        assert_eq!(passes, vec!["string_encryption"]);
    }

    #[test]
    fn unknown_explicit_pass_errors() {
        let err = resolve_passes(None, None, &["missing_pass".to_string()])
            .expect_err("unknown explicit pass");
        assert!(err
            .to_string()
            .contains("explicit --passes references unknown pass"));
    }
}
