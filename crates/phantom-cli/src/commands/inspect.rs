use std::path::Path;

use anyhow::Result;

/// Dump PhIR for a binary.
pub fn run(input: &Path, function: Option<&str>, json: bool) -> Result<()> {
    let (_, module) = super::load(input)?;

    let functions: Vec<_> = if let Some(name) = function {
        module.functions.iter().filter(|f| f.name == name).collect()
    } else {
        module.functions.iter().collect()
    };

    if functions.is_empty() {
        if let Some(name) = function {
            anyhow::bail!("Function '{}' not found", name);
        } else {
            println!("No functions found.");
            return Ok(());
        }
    }

    if json {
        let output = serde_json::to_string_pretty(&functions)?;
        println!("{}", output);
    } else {
        for func in &functions {
            println!("{}", func);
        }
    }

    Ok(())
}
