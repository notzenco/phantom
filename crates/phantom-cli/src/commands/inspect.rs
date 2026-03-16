use std::path::PathBuf;

use anyhow::Result;
use phantom_frontends::detect_frontend;

/// Dump PhIR for a binary.
pub fn run(input: &PathBuf, function: Option<&str>, json: bool) -> Result<()> {
    let data = std::fs::read(input)?;

    let frontend = detect_frontend(&data)
        .ok_or_else(|| anyhow::anyhow!("Unsupported binary format"))?;

    let module = frontend.lift(&data)?;

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
