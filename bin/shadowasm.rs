//! shadowasm -- ShadowVM assembler and build tool.
//!
//! Usage:
//!   shadowasm build <source.sasm> [-o output.json] [--name <name>] [--check]
//!   shadowasm disassemble <bytecode_hex>
//!   shadowasm verify <package.json>
//!   shadowasm info <package.json>
//!   shadowasm help

use std::fs;
use std::process;

// Access the library crate
use shadowdag::runtime::vm::contracts::build_manifest::BuildManifest;
use shadowdag::runtime::vm::contracts::contract_abi::{AbiParam, AbiType, ContractAbi, Mutability};
use shadowdag::runtime::vm::contracts::contract_package::ContractPackage;
use shadowdag::runtime::vm::core::assembler::Assembler;
use shadowdag::runtime::vm::core::execution_trace::ExecutionTrace;
use shadowdag::runtime::vm::core::v1_spec;
use shadowdag::runtime::vm::testing::test_runner::{TestCase, TestRunner};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let command = args.get(1).map(|s| s.as_str()).unwrap_or("help");

    match command {
        "build" => cmd_build(&args),
        "disassemble" | "dis" => cmd_disassemble(&args),
        "verify" => cmd_verify(&args),
        "info" => cmd_info(&args),
        "test" => cmd_test(&args),
        "trace" => cmd_trace(&args),
        "script" => cmd_script(&args),
        "help" | "--help" | "-h" => print_help(),
        _ => {
            eprintln!("Unknown command: {}", command);
            print_help();
            process::exit(1);
        }
    }
}

fn cmd_build(args: &[String]) {
    let source_path = match args.get(2) {
        Some(p) => p,
        None => {
            eprintln!("Usage: shadowasm build <source.sasm> [-o output.json] [--name <name>]");
            process::exit(1);
        }
    };

    // Parse flags
    let mut output_path = source_path.replace(".sasm", ".pkg.json");
    let mut contract_name = source_path
        .replace(".sasm", "")
        .rsplit('/')
        .next()
        .unwrap_or("contract")
        .to_string();
    let mut check_only = false;

    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "-o" | "--output" => {
                output_path = args.get(i + 1).cloned().unwrap_or(output_path);
                i += 2;
            }
            "--name" => {
                contract_name = args.get(i + 1).cloned().unwrap_or(contract_name);
                i += 2;
            }
            "--check" => {
                check_only = true;
                i += 1;
            }
            _ => i += 1,
        }
    }

    // Read source
    let source = match fs::read_to_string(source_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to read {}: {}", source_path, e);
            process::exit(1);
        }
    };

    // Assemble
    println!("Assembling {}...", source_path);
    let bytecode = match Assembler::assemble(&source) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Assembly error: {}", e);
            process::exit(1);
        }
    };

    // V1 validation
    if let Err((pos, byte)) = v1_spec::validate_v1_bytecode(&bytecode) {
        eprintln!("ERROR: Non-v1 opcode 0x{:02X} at position {}", byte, pos);
        process::exit(1);
    }

    // --check: validate only, don't write output files
    if check_only {
        println!(
            "  \u{2713} Build check passed ({} bytes, {} gas est.)",
            bytecode.len(),
            32_000 + bytecode.len() as u64 * 200
        );
        return;
    }

    // Parse ABI from comments
    let abi = parse_abi_from_source(&source, &contract_name);

    // Build package
    let package = ContractPackage::new(&contract_name, bytecode.clone(), abi);

    // Build manifest
    let mut manifest = BuildManifest::new("shadowasm", env!("CARGO_PKG_VERSION"));
    manifest.add_source(source_path, source.as_bytes());
    manifest.set_bytecode_hash(&bytecode);

    // Write package
    let json = match package.to_json() {
        Ok(j) => j,
        Err(e) => {
            eprintln!("Serialization error: {}", e);
            process::exit(1);
        }
    };
    if let Err(e) = fs::write(&output_path, &json) {
        eprintln!("Failed to write {}: {}", output_path, e);
        process::exit(1);
    }

    // Write manifest alongside
    let manifest_path = output_path.replace(".pkg.json", ".manifest.json");
    if let Ok(mj) = manifest.to_json() {
        let _ = fs::write(&manifest_path, mj);
    }

    println!("  Contract:     {}", contract_name);
    println!("  Bytecode:     {} bytes", package.code_size());
    println!("  Hash:         {}", &package.bytecode_hash);
    println!("  VM version:   {}", package.vm_version);
    println!("  Gas estimate: {}", package.estimated_deploy_gas());
    println!("  Package:      {}", output_path);
    println!("  Manifest:     {}", manifest_path);
    println!("\nBuild successful.");
}

fn cmd_disassemble(args: &[String]) {
    let hex_or_path = match args.get(2) {
        Some(h) => h,
        None => {
            eprintln!("Usage: shadowasm disassemble <hex_or_file>");
            process::exit(1);
        }
    };

    // Try as file first, then as hex string
    let bytecode = if std::path::Path::new(hex_or_path).exists() {
        // It's a package file
        let json = fs::read_to_string(hex_or_path).unwrap_or_default();
        if let Ok(pkg) = ContractPackage::from_json(&json) {
            pkg.bytecode
        } else {
            hex::decode(hex_or_path).unwrap_or_else(|_| {
                eprintln!("Invalid hex or package file");
                process::exit(1);
            })
        }
    } else {
        hex::decode(hex_or_path).unwrap_or_else(|e| {
            eprintln!("Invalid hex: {}", e);
            process::exit(1);
        })
    };

    println!("{}", Assembler::disassemble(&bytecode));
}

fn cmd_verify(args: &[String]) {
    let path = match args.get(2) {
        Some(p) => p,
        None => {
            eprintln!("Usage: shadowasm verify <package.json>");
            process::exit(1);
        }
    };

    let json = fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("Failed to read {}: {}", path, e);
        process::exit(1);
    });

    let package = ContractPackage::from_json(&json).unwrap_or_else(|e| {
        eprintln!("Invalid package: {}", e);
        process::exit(1);
    });

    if package.verify() {
        println!("Bytecode integrity verified");
        println!("  Name:     {}", package.name);
        println!("  Hash:     {}", package.bytecode_hash);
        println!("  Size:     {} bytes", package.code_size());
        println!("  VM:       v{}", package.vm_version);
    } else {
        eprintln!("Bytecode hash MISMATCH -- artifact may be tampered");
        process::exit(1);
    }

    // V1 validation
    match v1_spec::validate_v1_bytecode(&package.bytecode) {
        Ok(()) => println!("  V1 spec:  all opcodes valid"),
        Err((pos, byte)) => {
            eprintln!(
                "  V1 spec:  invalid opcode 0x{:02X} at position {}",
                byte, pos
            );
            process::exit(1);
        }
    }
}

fn cmd_info(args: &[String]) {
    let path = match args.get(2) {
        Some(p) => p,
        None => {
            eprintln!("Usage: shadowasm info <package.json>");
            process::exit(1);
        }
    };

    let json = fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("Failed to read {}: {}", path, e);
        process::exit(1);
    });
    let package = ContractPackage::from_json(&json).unwrap_or_else(|e| {
        eprintln!("Invalid package: {}", e);
        process::exit(1);
    });

    println!("Contract Package: {}", package.name);
    println!("  Bytecode size:    {} bytes", package.code_size());
    println!("  Bytecode hash:    {}", package.bytecode_hash);
    println!("  VM version:       {}", package.vm_version);
    println!("  Format version:   {}", package.format_version);
    println!("  Deploy gas est:   {}", package.estimated_deploy_gas());
    if let Some(ref sh) = package.source_hash {
        println!("  Source hash:      {}", sh);
    }

    // ABI summary
    let funcs: Vec<&str> = package
        .abi
        .functions
        .iter()
        .map(|f| f.name.as_str())
        .collect();
    let events: Vec<&str> = package.abi.events.iter().map(|e| e.name.as_str()).collect();
    if !funcs.is_empty() {
        println!("  Functions:        {}", funcs.join(", "));
    }
    if !events.is_empty() {
        println!("  Events:           {}", events.join(", "));
    }
}

fn cmd_test(args: &[String]) {
    let source_path = match args.get(2) {
        Some(p) => p.clone(),
        None => {
            eprintln!("Usage: shadowasm test <source.sasm>");
            process::exit(1);
        }
    };

    // Read and assemble the contract
    let source = match fs::read_to_string(&source_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to read {}: {}", source_path, e);
            process::exit(1);
        }
    };

    let bytecode = match Assembler::assemble(&source) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Assembly error: {}", e);
            process::exit(1);
        }
    };

    // Parse test cases from source comments
    // Format: ;; @test <name> [calldata_hex] [expect:success|revert] [gas:<max>]
    let tests = parse_tests_from_source(&source);

    if tests.is_empty() {
        println!(
            "No tests found in {}. Add ;; @test annotations.",
            source_path
        );
        println!("Example: ;; @test store_value 00000000000000000000000000000000000000000000000000000000000000ff");
        return;
    }

    // Run tests
    let mut runner = TestRunner::new();
    if let Err(e) = runner.fund_account("test_caller", 1_000_000_000) {
        eprintln!("Fund failed: {}", e);
        process::exit(1);
    }
    match runner.deploy_bytecode(bytecode, "test_caller") {
        Ok(_) => {}
        Err(e) => {
            eprintln!("Deploy failed: {}", e);
            process::exit(1);
        }
    }

    println!("Running {} tests from {}...\n", tests.len(), source_path);

    for test in &tests {
        runner.run_test(test);
    }

    runner.print_summary();

    let failed = runner.results().iter().filter(|r| !r.passed).count();
    if failed > 0 {
        process::exit(1);
    }
}

fn parse_tests_from_source(source: &str) -> Vec<TestCase> {
    let mut tests = Vec::new();
    for line in source.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(";; @test ") {
            let parts: Vec<&str> = rest.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }

            let name = parts[0].to_string();
            let calldata = parts
                .get(1)
                .and_then(|h| hex::decode(h).ok())
                .unwrap_or_default();

            let mut expect_revert = false;
            let mut max_gas = None;

            for p in &parts[2..] {
                if *p == "expect:revert" {
                    expect_revert = true;
                }
                if let Some(g) = p.strip_prefix("gas:") {
                    max_gas = g.parse().ok();
                }
            }

            tests.push(TestCase {
                name,
                calldata,
                expect_success: !expect_revert,
                expect_revert,
                max_gas,
                ..Default::default()
            });
        }
    }
    tests
}

fn cmd_trace(args: &[String]) {
    let source_or_hex = match args.get(2) {
        Some(p) => p,
        None => {
            eprintln!("Usage: shadowasm trace <source.sasm|bytecode_hex> [calldata_hex]");
            process::exit(1);
        }
    };
    let calldata = args
        .get(3)
        .and_then(|h| hex::decode(h).ok())
        .unwrap_or_default();

    // Get bytecode
    let bytecode = if source_or_hex.ends_with(".sasm") {
        let source = fs::read_to_string(source_or_hex).unwrap_or_else(|e| {
            eprintln!("Failed to read: {}", e);
            process::exit(1);
        });
        Assembler::assemble(&source).unwrap_or_else(|e| {
            eprintln!("Assembly error: {}", e);
            process::exit(1);
        })
    } else if source_or_hex.ends_with(".json") {
        let json = fs::read_to_string(source_or_hex).unwrap_or_default();
        ContractPackage::from_json(&json)
            .map(|p| p.bytecode)
            .unwrap_or_else(|e| {
                eprintln!("Invalid package: {}", e);
                process::exit(1);
            })
    } else {
        hex::decode(source_or_hex).unwrap_or_else(|e| {
            eprintln!("Invalid hex: {}", e);
            process::exit(1);
        })
    };

    // Execute and trace
    let mut runner = TestRunner::new();
    if let Err(e) = runner.fund_account("tracer", 1_000_000_000) {
        eprintln!("Fund failed: {}", e);
        process::exit(1);
    }
    match runner.deploy_bytecode(bytecode, "tracer") {
        Ok(_) => {}
        Err(e) => {
            eprintln!("Deploy failed: {}", e);
            process::exit(1);
        }
    }

    let result = runner.run_test(&TestCase {
        name: "trace".into(),
        calldata,
        ..Default::default()
    });

    // Build trace from result
    let mut trace = ExecutionTrace::new(runner.contract_addr(), "tracer", 0, 10_000_000);
    trace.gas_used = result.gas_used;
    trace.success = result.passed;

    println!("{}", trace.format_pretty());
    println!("Gas used: {}", result.gas_used);
    println!(
        "Status:   {}",
        if result.passed { "SUCCESS" } else { "FAILED" }
    );
    if let Some(ref msg) = result.message {
        println!("Message:  {}", msg);
    }
}

/// Parse ABI annotations from source comments.
/// Format: ;; @fn transfer(uint64,address):bool
///         ;; @event Transfer(address,address,uint64)
fn parse_abi_from_source(source: &str, name: &str) -> ContractAbi {
    let mut abi = ContractAbi::new(name);

    for (line_num, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if let Some(ann) = trimmed.strip_prefix(";; @fn ") {
            // Parse: name(type1,type2):return_type
            if let Some((sig, ret)) = ann.split_once(':') {
                if let Some((fname, params_str)) = sig.split_once('(') {
                    let params_str = params_str.trim_end_matches(')');
                    let inputs: Vec<AbiParam> = if params_str.is_empty() {
                        vec![]
                    } else {
                        let mut parsed = Vec::new();
                        for (i, t) in params_str.split(',').enumerate() {
                            // AbiType::from_str now returns Result and rejects
                            // unknown type names. Skip the bad parameter and
                            // print a warning so the user can fix the typo
                            // instead of getting a silent `Bytes` default.
                            let abi_type = match AbiType::from_str(t.trim()) {
                                Ok(t) => t,
                                Err(e) => {
                                    eprintln!(
                                        "warning: line {} fn {}: skipping parameter {}: {}",
                                        line_num + 1,
                                        fname.trim(),
                                        i,
                                        e
                                    );
                                    continue;
                                }
                            };
                            parsed.push(AbiParam {
                                name: format!("arg{}", i),
                                abi_type,
                                indexed: false,
                            });
                        }
                        parsed
                    };
                    let outputs = match AbiType::from_str(ret.trim()) {
                        Ok(t) => vec![AbiParam {
                            name: "result".into(),
                            abi_type: t,
                            indexed: false,
                        }],
                        Err(e) => {
                            eprintln!(
                                "warning: line {} fn {}: skipping return type: {}",
                                line_num + 1,
                                fname.trim(),
                                e
                            );
                            vec![]
                        }
                    };
                    abi.add_function(fname.trim(), inputs, outputs, Mutability::Mutable);
                }
            }
        } else if let Some(ann) = trimmed.strip_prefix(";; @event ") {
            if let Some((ename, params_str)) = ann.split_once('(') {
                let params_str = params_str.trim_end_matches(')');
                let params: Vec<AbiParam> = if params_str.is_empty() {
                    vec![]
                } else {
                    let mut parsed = Vec::new();
                    for (i, t) in params_str.split(',').enumerate() {
                        let abi_type = match AbiType::from_str(t.trim()) {
                            Ok(t) => t,
                            Err(e) => {
                                eprintln!(
                                    "warning: line {} event {}: skipping parameter {}: {}",
                                    line_num + 1,
                                    ename.trim(),
                                    i,
                                    e
                                );
                                continue;
                            }
                        };
                        parsed.push(AbiParam {
                            name: format!("param{}", i),
                            abi_type,
                            indexed: i == 0,
                        });
                    }
                    parsed
                };
                abi.add_event(ename.trim(), params);
            }
        }
    }

    abi
}

fn cmd_script(args: &[String]) {
    let source_path = match args.get(2) {
        Some(p) => p,
        None => {
            eprintln!("Usage: shadowasm script <source.sasm> [--network <name>] [--broadcast]");
            process::exit(1);
        }
    };

    let mut network = "local".to_string();
    let mut broadcast = false;
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--network" => {
                network = args.get(i + 1).cloned().unwrap_or(network);
                i += 2;
            }
            "--broadcast" => {
                broadcast = true;
                i += 1;
            }
            "--dry-run" => {
                broadcast = false;
                i += 1;
            } // Explicit dry-run (default behavior)
            _ => i += 1,
        }
    }

    let source = match fs::read_to_string(source_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to read {}: {}", source_path, e);
            process::exit(1);
        }
    };

    // Parse script actions from source
    let actions = parse_script_actions(&source);
    if actions.is_empty() {
        println!("No script actions found. Use ;; @deploy and ;; @call annotations.");
        return;
    }

    println!("Running script {} on {}...", source_path, network);
    if broadcast {
        println!("  Mode: BROADCAST (changes will be submitted to network)");
    } else {
        println!("  Mode: DRY-RUN (local execution only)");
    }

    use shadowdag::runtime::vm::testing::script_runner::*;

    let mut runner = match ScriptRunner::new(&network, "script_deployer") {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: invalid deployment network '{}': {}", network, e);
            std::process::exit(1);
        }
    };
    if let Err(e) = runner.fund_deployer(1_000_000_000_000) {
        eprintln!("error: fund_deployer failed: {}", e);
        std::process::exit(1);
    }

    let results = runner.execute(&actions);
    runner.print_summary();

    // Save manifest
    let manifest_path = source_path.replace(".sasm", ".deployment.json");
    if let Ok(json) = runner.manifest().to_json() {
        if let Err(e) = fs::write(&manifest_path, json) {
            eprintln!("Failed to write manifest: {}", e);
        } else {
            println!("\n  Manifest saved: {}", manifest_path);
        }
    }

    let failed = results.iter().any(|r| !r.success);
    if failed {
        process::exit(1);
    }
}

fn parse_script_actions(
    source: &str,
) -> Vec<shadowdag::runtime::vm::testing::script_runner::ScriptAction> {
    use shadowdag::runtime::vm::contracts::contract_abi::ContractAbi;
    use shadowdag::runtime::vm::core::assembler::Assembler;
    use shadowdag::runtime::vm::testing::script_runner::ScriptAction;

    let mut actions = Vec::new();
    let mut current_deploy_name: Option<String> = None;
    let mut current_source = String::new();

    for line in source.lines() {
        let trimmed = line.trim();

        if let Some(rest) = trimmed.strip_prefix(";; @deploy ") {
            // Flush previous deploy
            if let Some(ref name) = current_deploy_name {
                if let Ok(bytecode) = Assembler::assemble(&current_source) {
                    actions.push(ScriptAction::Deploy {
                        name: name.clone(),
                        bytecode,
                        value: 0,
                        gas_limit: 10_000_000,
                        abi: ContractAbi::new(name),
                    });
                }
                current_source.clear();
            }
            current_deploy_name = Some(rest.trim().to_string());
        } else if let Some(rest) = trimmed.strip_prefix(";; @call ") {
            let parts: Vec<&str> = rest.split_whitespace().collect();
            if let Some(contract_name) = parts.first() {
                let calldata = parts
                    .get(1)
                    .and_then(|h| hex::decode(h).ok())
                    .unwrap_or_default();
                actions.push(ScriptAction::Call {
                    contract_name: contract_name.to_string(),
                    calldata,
                    value: 0,
                    gas_limit: 10_000_000,
                });
            }
        } else if let Some(rest) = trimmed.strip_prefix(";; @fund ") {
            let parts: Vec<&str> = rest.split_whitespace().collect();
            if parts.len() >= 2 {
                if let Ok(amount) = parts[1].parse::<u64>() {
                    actions.push(ScriptAction::Fund {
                        address: parts[0].to_string(),
                        amount,
                    });
                }
            }
        } else if let Some(rest) = trimmed.strip_prefix(";; @log ") {
            actions.push(ScriptAction::Log {
                message: rest.to_string(),
            });
        } else if current_deploy_name.is_some() && !trimmed.starts_with(";;") {
            current_source.push_str(line);
            current_source.push('\n');
        }
    }

    // Flush last deploy
    if let Some(ref name) = current_deploy_name {
        if let Ok(bytecode) = Assembler::assemble(&current_source) {
            actions.push(ScriptAction::Deploy {
                name: name.clone(),
                bytecode,
                value: 0,
                gas_limit: 10_000_000,
                abi: ContractAbi::new(name),
            });
        }
    }

    actions
}

fn print_help() {
    println!("shadowasm -- ShadowVM Assembler & Build Tool");
    println!();
    println!("Usage:");
    println!("  shadowasm build <source.sasm> [-o output.json] [--name <name>] [--check]");
    println!("  shadowasm disassemble <hex_or_package.json>");
    println!("  shadowasm verify <package.json>");
    println!("  shadowasm info <package.json>");
    println!("  shadowasm test <source.sasm>");
    println!("  shadowasm trace <source.sasm|bytecode_hex> [calldata_hex]");
    println!("  shadowasm script <source.sasm> [--network <name>] [--broadcast] [--dry-run]");
    println!("  shadowasm help");
    println!();
    println!("Build Flags:");
    println!(
        "  --check              Validate only — assemble + V1 check, no output files (CI mode)"
    );
    println!(
        "  --dry-run            Script dry-run — local execution only, no broadcast (default)"
    );
    println!();
    println!("ABI Annotations (in .sasm source comments):");
    println!("  ;; @fn transfer(uint64,address):bool");
    println!("  ;; @event Transfer(address,address,uint64)");
    println!();
    println!("Test Annotations (in .sasm source comments):");
    println!("  ;; @test <name> [calldata_hex] [expect:revert] [gas:<max>]");
    println!();
    println!("Script Annotations (in .sasm deployment scripts):");
    println!("  ;; @deploy <ContractName>    -- Deploy the following assembly as a contract");
    println!("  ;; @call <ContractName> [hex] -- Call a deployed contract with optional calldata");
    println!("  ;; @fund <address> <amount>  -- Fund an address with balance");
    println!("  ;; @log <message>            -- Print a log message during script execution");
    println!();
    println!("Build output:");
    println!("  <name>.pkg.json             -- Contract package (bytecode + ABI + hashes)");
    println!("  <name>.manifest.json        -- Build manifest (compiler + source hashes)");
    println!("  <name>.deployment.json      -- Deployment manifest (addresses + network info)");
}
