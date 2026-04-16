// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// ShadowLang — High-level smart contract language for ShadowDAG.
//
// Compiles a Solidity-like syntax to ShadowASM assembly, which is then
// assembled to bytecode by the existing Assembler.
//
// Supported constructs:
//   - contract Name { ... }
//   - storage varName: type = initial;
//   - fn name(params) -> returnType { ... }
//   - let x = expr;
//   - x = expr;
//   - if (condition) { ... } else { ... }
//   - while (condition) { ... }
//   - return expr;
//   - require(condition);
//   - emit EventName(args);
//
// Types: uint64, address, bool
// Operators: + - * / % == != < > && || !
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

/// Compile ShadowLang source code to ShadowASM assembly.
///
/// Returns the ShadowASM text that can be fed to `Assembler::assemble()`.
pub fn compile(source: &str) -> Result<String, CompileError> {
    let tokens = Lexer::tokenize(source)?;
    let ast = Parser::parse(&tokens)?;
    let asm = CodeGen::generate(&ast)?;
    Ok(asm)
}

/// Compile ShadowLang source code directly to bytecode.
pub fn compile_to_bytecode(source: &str) -> Result<Vec<u8>, String> {
    let asm = compile(source).map_err(|e| e.to_string())?;
    crate::runtime::vm::core::assembler::Assembler::assemble(&asm)
        .map_err(|e| e.to_string())
}

// ═══════════════════════════════════════════════════════════════════════════
//                              ERRORS
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct CompileError {
    pub message: String,
    pub line: usize,
}

impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//                              LEXER
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, PartialEq)]
enum Token {
    // Keywords
    Contract,
    Storage,
    Fn,
    Let,
    If,
    Else,
    While,
    Return,
    Require,
    Emit,
    // Types
    Uint64,
    Address,
    Bool,
    True,
    False,
    // Operators
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    Eq,
    EqEq,
    NotEq,
    Lt,
    Gt,
    And,
    Or,
    Not,
    Arrow, // ->
    // Delimiters
    LParen,
    RParen,
    LBrace,
    RBrace,
    Comma,
    Colon,
    Semi,
    // Literals
    Number(u64),
    Ident(String),
    StringLit(String),
    // Meta
    Eof,
}

struct Lexer;

impl Lexer {
    fn tokenize(source: &str) -> Result<Vec<(Token, usize)>, CompileError> {
        let mut tokens = Vec::new();
        let mut chars: Vec<char> = source.chars().collect();
        let mut pos = 0;
        let mut line = 1;

        while pos < chars.len() {
            let ch = chars[pos];

            // Skip whitespace
            if ch == '\n' {
                line += 1;
                pos += 1;
                continue;
            }
            if ch.is_whitespace() {
                pos += 1;
                continue;
            }

            // Skip comments
            if ch == '/' && pos + 1 < chars.len() && chars[pos + 1] == '/' {
                while pos < chars.len() && chars[pos] != '\n' {
                    pos += 1;
                }
                continue;
            }

            // Numbers
            if ch.is_ascii_digit() {
                let start = pos;
                while pos < chars.len() && chars[pos].is_ascii_digit() {
                    pos += 1;
                }
                let num_str: String = chars[start..pos].iter().collect();
                let num = num_str.parse::<u64>().map_err(|_| CompileError {
                    message: format!("invalid number: {}", num_str),
                    line,
                })?;
                tokens.push((Token::Number(num), line));
                continue;
            }

            // Identifiers and keywords
            if ch.is_ascii_alphabetic() || ch == '_' {
                let start = pos;
                while pos < chars.len() && (chars[pos].is_ascii_alphanumeric() || chars[pos] == '_')
                {
                    pos += 1;
                }
                let word: String = chars[start..pos].iter().collect();
                let tok = match word.as_str() {
                    "contract" => Token::Contract,
                    "storage" => Token::Storage,
                    "fn" => Token::Fn,
                    "let" => Token::Let,
                    "if" => Token::If,
                    "else" => Token::Else,
                    "while" => Token::While,
                    "return" => Token::Return,
                    "require" => Token::Require,
                    "emit" => Token::Emit,
                    "uint64" => Token::Uint64,
                    "address" => Token::Address,
                    "bool" => Token::Bool,
                    "true" => Token::True,
                    "false" => Token::False,
                    _ => Token::Ident(word),
                };
                tokens.push((tok, line));
                continue;
            }

            // String literals
            if ch == '"' {
                pos += 1;
                let start = pos;
                while pos < chars.len() && chars[pos] != '"' {
                    pos += 1;
                }
                let s: String = chars[start..pos].iter().collect();
                pos += 1; // skip closing quote
                tokens.push((Token::StringLit(s), line));
                continue;
            }

            // Multi-char operators
            match ch {
                '-' if pos + 1 < chars.len() && chars[pos + 1] == '>' => {
                    tokens.push((Token::Arrow, line));
                    pos += 2;
                    continue;
                }
                '=' if pos + 1 < chars.len() && chars[pos + 1] == '=' => {
                    tokens.push((Token::EqEq, line));
                    pos += 2;
                    continue;
                }
                '!' if pos + 1 < chars.len() && chars[pos + 1] == '=' => {
                    tokens.push((Token::NotEq, line));
                    pos += 2;
                    continue;
                }
                '&' if pos + 1 < chars.len() && chars[pos + 1] == '&' => {
                    tokens.push((Token::And, line));
                    pos += 2;
                    continue;
                }
                '|' if pos + 1 < chars.len() && chars[pos + 1] == '|' => {
                    tokens.push((Token::Or, line));
                    pos += 2;
                    continue;
                }
                _ => {}
            }

            // Single-char operators
            let tok = match ch {
                '+' => Token::Plus,
                '-' => Token::Minus,
                '*' => Token::Star,
                '/' => Token::Slash,
                '%' => Token::Percent,
                '=' => Token::Eq,
                '<' => Token::Lt,
                '>' => Token::Gt,
                '!' => Token::Not,
                '(' => Token::LParen,
                ')' => Token::RParen,
                '{' => Token::LBrace,
                '}' => Token::RBrace,
                ',' => Token::Comma,
                ':' => Token::Colon,
                ';' => Token::Semi,
                _ => {
                    return Err(CompileError {
                        message: format!("unexpected character: '{}'", ch),
                        line,
                    })
                }
            };
            tokens.push((tok, line));
            pos += 1;
        }

        tokens.push((Token::Eof, line));
        Ok(tokens)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//                              AST
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
struct Contract {
    name: String,
    storage_vars: Vec<StorageVar>,
    functions: Vec<Function>,
    events: Vec<String>,
}

#[derive(Debug, Clone)]
struct StorageVar {
    name: String,
    ty: String,
    slot: usize,
    initial: Option<u64>,
}

#[derive(Debug, Clone)]
struct Function {
    name: String,
    params: Vec<(String, String)>,
    return_type: Option<String>,
    body: Vec<Statement>,
}

#[derive(Debug, Clone)]
enum Statement {
    Let {
        name: String,
        value: Expr,
    },
    Assign {
        name: String,
        value: Expr,
    },
    If {
        condition: Expr,
        then_body: Vec<Statement>,
        else_body: Vec<Statement>,
    },
    While {
        condition: Expr,
        body: Vec<Statement>,
    },
    Return(Expr),
    Require(Expr),
    Emit {
        event: String,
        args: Vec<Expr>,
    },
    ExprStmt(Expr),
}

#[derive(Debug, Clone)]
enum Expr {
    Number(u64),
    Bool(bool),
    Ident(String),
    BinaryOp {
        left: Box<Expr>,
        op: BinOp,
        right: Box<Expr>,
    },
    UnaryOp {
        op: UnaryOp,
        expr: Box<Expr>,
    },
    Call {
        name: String,
        args: Vec<Expr>,
    },
}

#[derive(Debug, Clone)]
enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Eq,
    NotEq,
    Lt,
    Gt,
    And,
    Or,
}

#[derive(Debug, Clone)]
enum UnaryOp {
    Not,
}

// ═══════════════════════════════════════════════════════════════════════════
//                              PARSER
// ═══════════════════════════════════════════════════════════════════════════

struct Parser;

impl Parser {
    fn parse(tokens: &[(Token, usize)]) -> Result<Contract, CompileError> {
        let mut pos = 0;

        // Expect: contract Name {
        Self::expect(tokens, &mut pos, &Token::Contract)?;
        let name = Self::expect_ident(tokens, &mut pos)?;
        Self::expect(tokens, &mut pos, &Token::LBrace)?;

        let mut storage_vars = Vec::new();
        let mut functions = Vec::new();
        let mut events = Vec::new();
        let mut slot_counter = 0;

        while pos < tokens.len() && tokens[pos].0 != Token::RBrace {
            match &tokens[pos].0 {
                Token::Storage => {
                    pos += 1;
                    let var_name = Self::expect_ident(tokens, &mut pos)?;
                    Self::expect(tokens, &mut pos, &Token::Colon)?;
                    let ty = Self::expect_type(tokens, &mut pos)?;
                    let initial = if pos < tokens.len() && tokens[pos].0 == Token::Eq {
                        pos += 1;
                        let n = Self::expect_number(tokens, &mut pos)?;
                        Some(n)
                    } else {
                        None
                    };
                    Self::expect(tokens, &mut pos, &Token::Semi)?;
                    storage_vars.push(StorageVar {
                        name: var_name,
                        ty,
                        slot: slot_counter,
                        initial,
                    });
                    slot_counter += 1;
                }
                Token::Fn => {
                    functions.push(Self::parse_function(tokens, &mut pos)?);
                }
                Token::Emit => {
                    // Event declaration: emit EventName;
                    pos += 1;
                    let event_name = Self::expect_ident(tokens, &mut pos)?;
                    Self::expect(tokens, &mut pos, &Token::Semi)?;
                    events.push(event_name);
                }
                _ => {
                    return Err(CompileError {
                        message: format!("unexpected token in contract body: {:?}", tokens[pos].0),
                        line: tokens[pos].1,
                    });
                }
            }
        }
        Self::expect(tokens, &mut pos, &Token::RBrace)?;

        Ok(Contract {
            name,
            storage_vars,
            functions,
            events,
        })
    }

    fn parse_function(
        tokens: &[(Token, usize)],
        pos: &mut usize,
    ) -> Result<Function, CompileError> {
        Self::expect(tokens, pos, &Token::Fn)?;
        let name = Self::expect_ident(tokens, pos)?;
        Self::expect(tokens, pos, &Token::LParen)?;

        let mut params = Vec::new();
        while *pos < tokens.len() && tokens[*pos].0 != Token::RParen {
            let pname = Self::expect_ident(tokens, pos)?;
            Self::expect(tokens, pos, &Token::Colon)?;
            let pty = Self::expect_type(tokens, pos)?;
            params.push((pname, pty));
            if *pos < tokens.len() && tokens[*pos].0 == Token::Comma {
                *pos += 1;
            }
        }
        Self::expect(tokens, pos, &Token::RParen)?;

        let return_type = if *pos < tokens.len() && tokens[*pos].0 == Token::Arrow {
            *pos += 1;
            Some(Self::expect_type(tokens, pos)?)
        } else {
            None
        };

        Self::expect(tokens, pos, &Token::LBrace)?;
        let body = Self::parse_block(tokens, pos)?;
        Self::expect(tokens, pos, &Token::RBrace)?;

        Ok(Function {
            name,
            params,
            return_type,
            body,
        })
    }

    fn parse_block(
        tokens: &[(Token, usize)],
        pos: &mut usize,
    ) -> Result<Vec<Statement>, CompileError> {
        let mut stmts = Vec::new();
        while *pos < tokens.len() && tokens[*pos].0 != Token::RBrace {
            stmts.push(Self::parse_statement(tokens, pos)?);
        }
        Ok(stmts)
    }

    fn parse_statement(
        tokens: &[(Token, usize)],
        pos: &mut usize,
    ) -> Result<Statement, CompileError> {
        let line = tokens[*pos].1;
        match &tokens[*pos].0 {
            Token::Let => {
                *pos += 1;
                let name = Self::expect_ident(tokens, pos)?;
                Self::expect(tokens, pos, &Token::Eq)?;
                let value = Self::parse_expr(tokens, pos)?;
                Self::expect(tokens, pos, &Token::Semi)?;
                Ok(Statement::Let { name, value })
            }
            Token::If => {
                *pos += 1;
                Self::expect(tokens, pos, &Token::LParen)?;
                let condition = Self::parse_expr(tokens, pos)?;
                Self::expect(tokens, pos, &Token::RParen)?;
                Self::expect(tokens, pos, &Token::LBrace)?;
                let then_body = Self::parse_block(tokens, pos)?;
                Self::expect(tokens, pos, &Token::RBrace)?;
                let else_body = if *pos < tokens.len() && tokens[*pos].0 == Token::Else {
                    *pos += 1;
                    Self::expect(tokens, pos, &Token::LBrace)?;
                    let body = Self::parse_block(tokens, pos)?;
                    Self::expect(tokens, pos, &Token::RBrace)?;
                    body
                } else {
                    Vec::new()
                };
                Ok(Statement::If {
                    condition,
                    then_body,
                    else_body,
                })
            }
            Token::While => {
                *pos += 1;
                Self::expect(tokens, pos, &Token::LParen)?;
                let condition = Self::parse_expr(tokens, pos)?;
                Self::expect(tokens, pos, &Token::RParen)?;
                Self::expect(tokens, pos, &Token::LBrace)?;
                let body = Self::parse_block(tokens, pos)?;
                Self::expect(tokens, pos, &Token::RBrace)?;
                Ok(Statement::While { condition, body })
            }
            Token::Return => {
                *pos += 1;
                let value = Self::parse_expr(tokens, pos)?;
                Self::expect(tokens, pos, &Token::Semi)?;
                Ok(Statement::Return(value))
            }
            Token::Require => {
                *pos += 1;
                Self::expect(tokens, pos, &Token::LParen)?;
                let condition = Self::parse_expr(tokens, pos)?;
                Self::expect(tokens, pos, &Token::RParen)?;
                Self::expect(tokens, pos, &Token::Semi)?;
                Ok(Statement::Require(condition))
            }
            Token::Ident(_) => {
                let name = Self::expect_ident(tokens, pos)?;
                if *pos < tokens.len() && tokens[*pos].0 == Token::Eq {
                    *pos += 1;
                    let value = Self::parse_expr(tokens, pos)?;
                    Self::expect(tokens, pos, &Token::Semi)?;
                    Ok(Statement::Assign { name, value })
                } else if *pos < tokens.len() && tokens[*pos].0 == Token::LParen {
                    *pos += 1;
                    let mut args = Vec::new();
                    while *pos < tokens.len() && tokens[*pos].0 != Token::RParen {
                        args.push(Self::parse_expr(tokens, pos)?);
                        if *pos < tokens.len() && tokens[*pos].0 == Token::Comma {
                            *pos += 1;
                        }
                    }
                    Self::expect(tokens, pos, &Token::RParen)?;
                    Self::expect(tokens, pos, &Token::Semi)?;
                    Ok(Statement::ExprStmt(Expr::Call { name, args }))
                } else {
                    Err(CompileError {
                        message: format!("expected '=' or '(' after identifier '{}'", name),
                        line,
                    })
                }
            }
            _ => Err(CompileError {
                message: format!("unexpected token: {:?}", tokens[*pos].0),
                line,
            }),
        }
    }

    fn parse_expr(
        tokens: &[(Token, usize)],
        pos: &mut usize,
    ) -> Result<Expr, CompileError> {
        Self::parse_or(tokens, pos)
    }

    fn parse_or(tokens: &[(Token, usize)], pos: &mut usize) -> Result<Expr, CompileError> {
        let mut left = Self::parse_and(tokens, pos)?;
        while *pos < tokens.len() && tokens[*pos].0 == Token::Or {
            *pos += 1;
            let right = Self::parse_and(tokens, pos)?;
            left = Expr::BinaryOp {
                left: Box::new(left),
                op: BinOp::Or,
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn parse_and(tokens: &[(Token, usize)], pos: &mut usize) -> Result<Expr, CompileError> {
        let mut left = Self::parse_comparison(tokens, pos)?;
        while *pos < tokens.len() && tokens[*pos].0 == Token::And {
            *pos += 1;
            let right = Self::parse_comparison(tokens, pos)?;
            left = Expr::BinaryOp {
                left: Box::new(left),
                op: BinOp::And,
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn parse_comparison(
        tokens: &[(Token, usize)],
        pos: &mut usize,
    ) -> Result<Expr, CompileError> {
        let mut left = Self::parse_additive(tokens, pos)?;
        while *pos < tokens.len() {
            let op = match &tokens[*pos].0 {
                Token::EqEq => BinOp::Eq,
                Token::NotEq => BinOp::NotEq,
                Token::Lt => BinOp::Lt,
                Token::Gt => BinOp::Gt,
                _ => break,
            };
            *pos += 1;
            let right = Self::parse_additive(tokens, pos)?;
            left = Expr::BinaryOp {
                left: Box::new(left),
                op,
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn parse_additive(
        tokens: &[(Token, usize)],
        pos: &mut usize,
    ) -> Result<Expr, CompileError> {
        let mut left = Self::parse_multiplicative(tokens, pos)?;
        while *pos < tokens.len() {
            let op = match &tokens[*pos].0 {
                Token::Plus => BinOp::Add,
                Token::Minus => BinOp::Sub,
                _ => break,
            };
            *pos += 1;
            let right = Self::parse_multiplicative(tokens, pos)?;
            left = Expr::BinaryOp {
                left: Box::new(left),
                op,
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn parse_multiplicative(
        tokens: &[(Token, usize)],
        pos: &mut usize,
    ) -> Result<Expr, CompileError> {
        let mut left = Self::parse_unary(tokens, pos)?;
        while *pos < tokens.len() {
            let op = match &tokens[*pos].0 {
                Token::Star => BinOp::Mul,
                Token::Slash => BinOp::Div,
                Token::Percent => BinOp::Mod,
                _ => break,
            };
            *pos += 1;
            let right = Self::parse_unary(tokens, pos)?;
            left = Expr::BinaryOp {
                left: Box::new(left),
                op,
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn parse_unary(tokens: &[(Token, usize)], pos: &mut usize) -> Result<Expr, CompileError> {
        if *pos < tokens.len() && tokens[*pos].0 == Token::Not {
            *pos += 1;
            let expr = Self::parse_primary(tokens, pos)?;
            return Ok(Expr::UnaryOp {
                op: UnaryOp::Not,
                expr: Box::new(expr),
            });
        }
        Self::parse_primary(tokens, pos)
    }

    fn parse_primary(tokens: &[(Token, usize)], pos: &mut usize) -> Result<Expr, CompileError> {
        if *pos >= tokens.len() {
            return Err(CompileError {
                message: "unexpected end of input".into(),
                line: 0,
            });
        }
        let line = tokens[*pos].1;
        match &tokens[*pos].0 {
            Token::Number(n) => {
                let n = *n;
                *pos += 1;
                Ok(Expr::Number(n))
            }
            Token::True => {
                *pos += 1;
                Ok(Expr::Bool(true))
            }
            Token::False => {
                *pos += 1;
                Ok(Expr::Bool(false))
            }
            Token::Ident(name) => {
                let name = name.clone();
                *pos += 1;
                if *pos < tokens.len() && tokens[*pos].0 == Token::LParen {
                    *pos += 1;
                    let mut args = Vec::new();
                    while *pos < tokens.len() && tokens[*pos].0 != Token::RParen {
                        args.push(Self::parse_expr(tokens, pos)?);
                        if *pos < tokens.len() && tokens[*pos].0 == Token::Comma {
                            *pos += 1;
                        }
                    }
                    Self::expect(tokens, pos, &Token::RParen)?;
                    Ok(Expr::Call { name, args })
                } else {
                    Ok(Expr::Ident(name))
                }
            }
            Token::LParen => {
                *pos += 1;
                let expr = Self::parse_expr(tokens, pos)?;
                Self::expect(tokens, pos, &Token::RParen)?;
                Ok(expr)
            }
            _ => Err(CompileError {
                message: format!("unexpected token in expression: {:?}", tokens[*pos].0),
                line,
            }),
        }
    }

    // Helper methods
    fn expect(
        tokens: &[(Token, usize)],
        pos: &mut usize,
        expected: &Token,
    ) -> Result<(), CompileError> {
        if *pos >= tokens.len() {
            return Err(CompileError {
                message: format!("expected {:?}, got end of input", expected),
                line: 0,
            });
        }
        if std::mem::discriminant(&tokens[*pos].0) != std::mem::discriminant(expected) {
            return Err(CompileError {
                message: format!("expected {:?}, got {:?}", expected, tokens[*pos].0),
                line: tokens[*pos].1,
            });
        }
        *pos += 1;
        Ok(())
    }

    fn expect_ident(tokens: &[(Token, usize)], pos: &mut usize) -> Result<String, CompileError> {
        if *pos >= tokens.len() {
            return Err(CompileError {
                message: "expected identifier".into(),
                line: 0,
            });
        }
        if let Token::Ident(name) = &tokens[*pos].0 {
            let name = name.clone();
            *pos += 1;
            Ok(name)
        } else {
            Err(CompileError {
                message: format!("expected identifier, got {:?}", tokens[*pos].0),
                line: tokens[*pos].1,
            })
        }
    }

    fn expect_number(tokens: &[(Token, usize)], pos: &mut usize) -> Result<u64, CompileError> {
        if *pos >= tokens.len() {
            return Err(CompileError {
                message: "expected number".into(),
                line: 0,
            });
        }
        if let Token::Number(n) = &tokens[*pos].0 {
            let n = *n;
            *pos += 1;
            Ok(n)
        } else {
            Err(CompileError {
                message: format!("expected number, got {:?}", tokens[*pos].0),
                line: tokens[*pos].1,
            })
        }
    }

    fn expect_type(tokens: &[(Token, usize)], pos: &mut usize) -> Result<String, CompileError> {
        if *pos >= tokens.len() {
            return Err(CompileError {
                message: "expected type".into(),
                line: 0,
            });
        }
        let ty = match &tokens[*pos].0 {
            Token::Uint64 => "uint64",
            Token::Address => "address",
            Token::Bool => "bool",
            _ => {
                return Err(CompileError {
                    message: format!("expected type (uint64/address/bool), got {:?}", tokens[*pos].0),
                    line: tokens[*pos].1,
                })
            }
        };
        *pos += 1;
        Ok(ty.to_string())
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//                           CODE GENERATION
// ═══════════════════════════════════════════════════════════════════════════

struct CodeGen {
    output: String,
    label_counter: usize,
    locals: HashMap<String, usize>, // local variable name → stack position
    storage_map: HashMap<String, usize>, // storage variable → slot number
}

impl CodeGen {
    fn generate(contract: &Contract) -> Result<String, CompileError> {
        let mut gen = Self {
            output: String::new(),
            label_counter: 0,
            locals: HashMap::new(),
            storage_map: HashMap::new(),
        };

        // Header comments (ABI annotations)
        gen.output.push_str(&format!(";; Contract: {}\n", contract.name));
        for func in &contract.functions {
            let params: Vec<String> = func.params.iter().map(|(_, t)| t.clone()).collect();
            let ret = func.return_type.as_deref().unwrap_or("void");
            gen.output.push_str(&format!(
                ";; @fn {}({}){}\n",
                func.name,
                params.join(","),
                if ret != "void" {
                    format!(":{}", ret)
                } else {
                    String::new()
                }
            ));
        }
        gen.output.push('\n');

        // Build storage map
        for var in &contract.storage_vars {
            gen.storage_map.insert(var.name.clone(), var.slot);
        }

        // Generate code for the FIRST function (default entry point)
        // In a real compiler, we'd use function selectors. For now,
        // the contract just executes the first function.
        if let Some(func) = contract.functions.first() {
            gen.locals.clear();
            gen.generate_function_body(&func.body)?;
        }

        gen.emit("STOP");
        Ok(gen.output)
    }

    fn generate_function_body(&mut self, stmts: &[Statement]) -> Result<(), CompileError> {
        for stmt in stmts {
            self.generate_statement(stmt)?;
        }
        Ok(())
    }

    fn generate_statement(&mut self, stmt: &Statement) -> Result<(), CompileError> {
        match stmt {
            Statement::Let { name, value } => {
                // Evaluate the expression (pushes result onto stack)
                self.generate_expr(value)?;
                // The value is now on top of the stack — track it
                let pos = self.locals.len();
                self.locals.insert(name.clone(), pos);
            }
            Statement::Assign { name, value } => {
                // Check if it's a storage variable
                if let Some(&slot) = self.storage_map.get(name.as_str()) {
                    self.generate_expr(value)?;
                    self.emit(&format!("PUSH1 {}", slot));
                    self.emit("SSTORE");
                } else {
                    // Local variable — just evaluate and track
                    self.generate_expr(value)?;
                }
            }
            Statement::If {
                condition,
                then_body,
                else_body,
            } => {
                let else_label = self.new_label("else");
                let end_label = self.new_label("endif");

                // Condition
                self.generate_expr(condition)?;
                self.emit("ISZERO"); // invert: jump to else if condition is false
                self.emit(&format!("PUSH4 {}", else_label));
                self.emit("JUMPI");

                // Then body
                self.generate_function_body(then_body)?;
                self.emit(&format!("PUSH4 {}", end_label));
                self.emit("JUMP");

                // Else body
                self.emit(&format!("{}: JUMPDEST", else_label));
                if !else_body.is_empty() {
                    self.generate_function_body(else_body)?;
                }

                self.emit(&format!("{}: JUMPDEST", end_label));
            }
            Statement::While { condition, body } => {
                let loop_label = self.new_label("loop");
                let end_label = self.new_label("endwhile");

                self.emit(&format!("{}: JUMPDEST", loop_label));

                // Condition
                self.generate_expr(condition)?;
                self.emit("ISZERO");
                self.emit(&format!("PUSH4 {}", end_label));
                self.emit("JUMPI");

                // Body
                self.generate_function_body(body)?;

                // Loop back
                self.emit(&format!("PUSH4 {}", loop_label));
                self.emit("JUMP");

                self.emit(&format!("{}: JUMPDEST", end_label));
            }
            Statement::Return(expr) => {
                self.generate_expr(expr)?;
                // Store return value in memory[0] and RETURN
                self.emit("PUSH1 0");
                self.emit("MSTORE");
                self.emit("PUSH1 32");
                self.emit("PUSH1 0");
                self.emit("RETURN");
            }
            Statement::Require(condition) => {
                let ok_label = self.new_label("require_ok");
                self.generate_expr(condition)?;
                self.emit(&format!("PUSH4 {}", ok_label));
                self.emit("JUMPI");
                // Condition failed — revert
                self.emit("PUSH1 0");
                self.emit("PUSH1 0");
                self.emit("REVERT");
                self.emit(&format!("{}: JUMPDEST", ok_label));
            }
            Statement::Emit { event: _, args } => {
                // Simple LOG implementation
                for arg in args.iter().rev() {
                    self.generate_expr(arg)?;
                }
                match args.len() {
                    0 => self.emit("LOG0"),
                    1 => self.emit("LOG1"),
                    2 => self.emit("LOG2"),
                    _ => self.emit("LOG3"),
                }
            }
            Statement::ExprStmt(expr) => {
                self.generate_expr(expr)?;
                self.emit("POP"); // discard result
            }
        }
        Ok(())
    }

    fn generate_expr(&mut self, expr: &Expr) -> Result<(), CompileError> {
        match expr {
            Expr::Number(n) => {
                if *n <= 255 {
                    self.emit(&format!("PUSH1 {}", n));
                } else if *n <= 65535 {
                    self.emit(&format!("PUSH2 {}", n));
                } else {
                    self.emit(&format!("PUSH8 {}", n));
                }
            }
            Expr::Bool(b) => {
                self.emit(&format!("PUSH1 {}", if *b { 1 } else { 0 }));
            }
            Expr::Ident(name) => {
                // Check if it's a storage variable
                if let Some(&slot) = self.storage_map.get(name.as_str()) {
                    self.emit(&format!("PUSH1 {}", slot));
                    self.emit("SLOAD");
                } else {
                    // Local variable — DUP from stack (simplified)
                    self.emit("DUP");
                }
            }
            Expr::BinaryOp { left, op, right } => {
                self.generate_expr(left)?;
                self.generate_expr(right)?;
                match op {
                    BinOp::Add => self.emit("ADD"),
                    BinOp::Sub => self.emit("SUB"),
                    BinOp::Mul => self.emit("MUL"),
                    BinOp::Div => self.emit("DIV"),
                    BinOp::Mod => self.emit("MOD"),
                    BinOp::Eq => self.emit("EQ"),
                    BinOp::NotEq => {
                        self.emit("EQ");
                        self.emit("ISZERO");
                    }
                    BinOp::Lt => self.emit("LT"),
                    BinOp::Gt => self.emit("GT"),
                    BinOp::And => self.emit("AND"),
                    BinOp::Or => self.emit("OR"),
                }
            }
            Expr::UnaryOp { op, expr } => {
                self.generate_expr(expr)?;
                match op {
                    UnaryOp::Not => self.emit("ISZERO"),
                }
            }
            Expr::Call { name, args } => {
                // Built-in functions
                match name.as_str() {
                    "caller" => self.emit("CALLER"),
                    "callvalue" => self.emit("CALLVALUE"),
                    "timestamp" => self.emit("TIMESTAMP"),
                    "balance" => {
                        if let Some(arg) = args.first() {
                            self.generate_expr(arg)?;
                        }
                        self.emit("BALANCE");
                    }
                    "sha256" => {
                        if let Some(arg) = args.first() {
                            self.generate_expr(arg)?;
                        }
                        self.emit("SHA256");
                    }
                    _ => {
                        // Unknown function — emit as comment
                        self.emit(&format!("; call {}()", name));
                    }
                }
            }
        }
        Ok(())
    }

    fn emit(&mut self, instruction: &str) {
        self.output.push_str(instruction);
        self.output.push('\n');
    }

    fn new_label(&mut self, prefix: &str) -> String {
        self.label_counter += 1;
        format!("{}_{}", prefix, self.label_counter)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//                              TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compile_counter_contract() {
        let source = r#"
            contract Counter {
                storage counter: uint64 = 0;

                fn increment() {
                    counter = counter + 1;
                }
            }
        "#;

        let asm = compile(source).expect("compilation failed");
        assert!(asm.contains("SLOAD"));
        assert!(asm.contains("SSTORE"));
        assert!(asm.contains("ADD"));
        assert!(asm.contains("PUSH1 1"));
        assert!(asm.contains("@fn increment"));
    }

    #[test]
    fn compile_with_if() {
        let source = r#"
            contract Guard {
                storage value: uint64 = 0;

                fn set_if_positive(x: uint64) {
                    if (x > 0) {
                        value = x;
                    }
                }
            }
        "#;

        let asm = compile(source).expect("compilation failed");
        assert!(asm.contains("GT"));
        assert!(asm.contains("JUMPI"));
        assert!(asm.contains("JUMPDEST"));
    }

    #[test]
    fn compile_with_require() {
        let source = r#"
            contract Safe {
                storage owner: uint64 = 0;

                fn only_owner() {
                    require(caller() == 42);
                    owner = 1;
                }
            }
        "#;

        let asm = compile(source).expect("compilation failed");
        assert!(asm.contains("CALLER"));
        assert!(asm.contains("EQ"));
        assert!(asm.contains("REVERT"));
    }

    #[test]
    fn compile_to_bytecode_works() {
        let source = r#"
            contract Simple {
                storage x: uint64 = 0;

                fn inc() {
                    x = x + 1;
                }
            }
        "#;

        let bytecode = compile_to_bytecode(source);
        assert!(bytecode.is_ok());
        assert!(!bytecode.unwrap().is_empty());
    }
}
