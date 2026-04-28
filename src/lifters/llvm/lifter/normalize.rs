use std::collections::HashMap;

pub(super) fn normalize_ir_text(ir: &str) -> String {
    let mut function_map = HashMap::<String, String>::new();
    let mut block_maps = HashMap::<String, HashMap<String, String>>::new();
    let mut helper_map = HashMap::<String, String>::new();
    let mut helper_counters = HashMap::<String, usize>::new();
    let mut function_index = 0usize;
    let mut current_function: Option<String> = None;
    let mut current_block_index = 0usize;

    for line in ir.lines() {
        if let Some(name) = parse_defined_function_name(line) {
            current_function = Some(name.clone());
            current_block_index = 0;
            block_maps.entry(name.clone()).or_default();
            if is_lifted_symbol(&name) {
                function_map.insert(name, format!("f{}", function_index));
                function_index += 1;
            }
        }

        if let (Some(function_name), Some(label)) = (&current_function, parse_block_label(line)) {
            let normalized = match label.as_str() {
                "entry" => "entry".to_string(),
                "exit" => "exit".to_string(),
                _ => {
                    let name = format!("b{}", current_block_index);
                    current_block_index += 1;
                    name
                }
            };
            block_maps
                .entry(function_name.clone())
                .or_default()
                .insert(label, normalized);
        }
    }

    let mut rewritten_lines = Vec::new();
    let mut address_map = HashMap::<u64, u64>::new();
    let mut token_map = HashMap::<u64, u64>::new();
    let mut next_address = 0u64;
    let mut next_token = 0u64;
    let mut current_function: Option<String> = None;

    for line in ir.lines() {
        if let Some(name) = parse_defined_function_name(line) {
            current_function = Some(name);
        }

        let mut rewritten = line.to_string();
        for (old, new) in &function_map {
            rewritten = rewritten.replace(&format!("@{}", old), &format!("@{}", new));
        }
        if let Some(function_name) = &current_function {
            if let Some(current_block_map) = block_maps.get(function_name) {
                for (old, new) in current_block_map {
                    rewritten = rewritten.replace(&format!("%{}", old), &format!("%{}", new));
                }
                if let Some((old, new)) = current_block_map
                    .iter()
                    .find(|(old, _)| rewritten.trim_start().starts_with(&format!("{}:", old)))
                {
                    let suffix = rewritten[old.len() + 1..].to_string();
                    rewritten = format!("{}:{}", new, suffix);
                }
            }
        }
        rewritten = normalize_helper_names(&rewritten, &mut helper_map, &mut helper_counters);
        rewritten = normalize_helper_addresses(&rewritten, &mut address_map, &mut next_address);
        rewritten = normalize_cil_metadata_tokens(&rewritten, &mut token_map, &mut next_token);
        rewritten_lines.push(rewritten);
    }

    drop_unused_exit_blocks(&rewritten_lines).join("\n")
}

fn parse_defined_function_name(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    let after_define = trimmed.strip_prefix("define ")?;
    let at = after_define.find('@')?;
    let rest = &after_define[at + 1..];
    let end = rest.find('(')?;
    Some(rest[..end].to_string())
}

fn parse_block_label(line: &str) -> Option<String> {
    if line.starts_with(' ') || line.starts_with('\t') {
        return None;
    }
    let colon = line.find(':')?;
    let label = &line[..colon];
    if label.is_empty() || label.starts_with(';') {
        return None;
    }
    Some(label.to_string())
}

fn is_lifted_symbol(name: &str) -> bool {
    name.starts_with("instruction_") || name.starts_with("block_") || name.starts_with("function_")
}

fn normalize_helper_addresses(
    line: &str,
    address_map: &mut HashMap<u64, u64>,
    next_address: &mut u64,
) -> String {
    const HELPERS: &[&str] = &[
        "@binlex_instruction_address(",
        "@binlex_term_jump(",
        "@binlex_term_branch(",
        "@binlex_term_call(",
    ];

    if !HELPERS.iter().any(|helper| line.contains(helper)) {
        return line.to_string();
    }

    let mut result = String::with_capacity(line.len());
    let bytes = line.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if i + 4 <= bytes.len() && &line[i..i + 4] == "i64 " {
            let start = i + 4;
            let mut end = start;
            while end < bytes.len() && bytes[end].is_ascii_digit() {
                end += 1;
            }
            if end > start {
                if let Ok(raw) = line[start..end].parse::<u64>() {
                    let normalized = *address_map.entry(raw).or_insert_with(|| {
                        let value = *next_address;
                        *next_address += 1;
                        value
                    });
                    result.push_str("i64 ");
                    result.push_str(&normalized.to_string());
                    i = end;
                    continue;
                }
            }
        }
        result.push(bytes[i] as char);
        i += 1;
    }
    result
}

fn normalize_helper_names(
    line: &str,
    helper_map: &mut HashMap<String, String>,
    helper_counters: &mut HashMap<String, usize>,
) -> String {
    let mut result = String::with_capacity(line.len());
    let bytes = line.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'@' {
            let start = i + 1;
            let mut end = start;
            while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
                end += 1;
            }
            if end > start {
                let symbol = &line[start..end];
                let normalized = normalize_helper_symbol(symbol, helper_map, helper_counters);
                result.push('@');
                result.push_str(&normalized);
                i = end;
                continue;
            }
        }
        result.push(bytes[i] as char);
        i += 1;
    }
    result
}

fn normalize_helper_symbol(
    symbol: &str,
    helper_map: &mut HashMap<String, String>,
    helper_counters: &mut HashMap<String, usize>,
) -> String {
    if !symbol.starts_with("binlex_") {
        return symbol.to_string();
    }
    if symbol == "binlex_instruction_address" || symbol.starts_with("llvm.") {
        return symbol.to_string();
    }
    if let Some(existing) = helper_map.get(symbol) {
        return existing.clone();
    }

    let family = if symbol.starts_with("binlex_effect_cil_") {
        "binlex_effect_cil"
    } else if symbol.starts_with("binlex_expr_cil_") {
        "binlex_expr_cil"
    } else if symbol.starts_with("binlex_term_") {
        "binlex_term"
    } else if symbol.starts_with("binlex_effect_") {
        "binlex_effect"
    } else if symbol.starts_with("binlex_expr_") {
        "binlex_expr"
    } else if symbol.starts_with("binlex_load_") {
        "binlex_load"
    } else if symbol.starts_with("binlex_store_") {
        "binlex_store"
    } else if symbol.starts_with("binlex_fence_") {
        "binlex_fence"
    } else if symbol.starts_with("binlex_trap_") {
        "binlex_trap"
    } else {
        return symbol.to_string();
    };

    let counter = helper_counters.entry(family.to_string()).or_insert(0);
    let normalized = format!("{}_{}", family, *counter);
    *counter += 1;
    helper_map.insert(symbol.to_string(), normalized.clone());
    normalized
}

fn normalize_cil_metadata_tokens(
    line: &str,
    token_map: &mut HashMap<u64, u64>,
    next_token: &mut u64,
) -> String {
    if !(line.contains("@binlex_effect_cil_") || line.contains("@binlex_expr_cil_")) {
        return line.to_string();
    }

    let mut result = String::with_capacity(line.len());
    let bytes = line.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if i + 4 <= bytes.len() && &line[i..i + 4] == "i32 " {
            let start = i + 4;
            let mut end = start;
            while end < bytes.len() && bytes[end].is_ascii_digit() {
                end += 1;
            }
            if end > start {
                if let Ok(raw) = line[start..end].parse::<u64>() {
                    let normalized = *token_map.entry(raw).or_insert_with(|| {
                        let value = *next_token;
                        *next_token += 1;
                        value
                    });
                    result.push_str("i32 ");
                    result.push_str(&normalized.to_string());
                    i = end;
                    continue;
                }
            }
        }
        result.push(bytes[i] as char);
        i += 1;
    }
    result
}

fn drop_unused_exit_blocks(lines: &[String]) -> Vec<String> {
    let exit_referenced = lines.iter().any(|line| line.contains("%exit"));
    if exit_referenced {
        return lines.to_vec();
    }

    let mut result = Vec::with_capacity(lines.len());
    let mut i = 0usize;
    while i < lines.len() {
        let line = &lines[i];
        if line.trim_start() == "exit:                                             ; No predecessors!"
            || line.trim_start() == "exit:"
            || line.trim_start().starts_with("exit: ; No predecessors!")
        {
            i += 1;
            while i < lines.len() {
                let next = &lines[i];
                if parse_block_label(next).is_some()
                    || parse_defined_function_name(next).is_some()
                    || next.trim() == "}"
                {
                    break;
                }
                i += 1;
            }
            continue;
        }
        result.push(line.clone());
        i += 1;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::normalize_ir_text;

    #[test]
    fn normalize_cil_helpers_tokens_and_unused_exit() {
        let ir = r#"; ModuleID = 'binlex'
source_filename = "binlex"

define void @function_1234() {
entry:
  br label %block_1234

block_1234:
  call void @binlex_instruction_address(i64 6442450944)
  call void (...) @binlex_effect_cil_LdArg0()
  call void @binlex_instruction_address(i64 6442450945)
  call void (...) @binlex_effect_cil_Call(i32 167772295)
  %intrinsicexpr = call i64 (...) @binlex_expr_cil_Call_target(i32 167772295)
  call void @binlex_term_call(i64 %intrinsicexpr, i64 6442450946, i1 true)
  call void @binlex_instruction_address(i64 6442450946)
  ret void

exit:                                             ; No predecessors!
  ret void
}

declare void @binlex_instruction_address(i64)
declare void @binlex_effect_cil_LdArg0(...)
declare void @binlex_effect_cil_Call(...)
declare void @binlex_term_call(i64, i64, i1)
declare i64 @binlex_expr_cil_Call_target(...)
"#;

        let normalized = normalize_ir_text(ir);
        assert!(normalized.contains("define void @f0()"));
        assert!(normalized.contains("b0:"));
        assert!(normalized.contains("@binlex_effect_cil_0"));
        assert!(normalized.contains("@binlex_effect_cil_1"));
        assert!(normalized.contains("@binlex_expr_cil_0"));
        assert!(normalized.contains("@binlex_term_0"));
        assert!(normalized.contains("@binlex_instruction_address(i64 0)"));
        assert!(normalized.contains("@binlex_instruction_address(i64 1)"));
        assert!(normalized.contains("@binlex_instruction_address(i64 2)"));
        assert!(normalized.contains("@binlex_effect_cil_1(i32 0)"));
        assert!(normalized.contains("@binlex_expr_cil_0(i32 0)"));
        assert!(!normalized.contains("167772295"));
        assert!(!normalized.contains("No predecessors!"));
        assert!(!normalized.contains("\nexit:"));
    }
}
