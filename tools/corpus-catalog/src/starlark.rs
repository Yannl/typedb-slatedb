//! A deliberately small Starlark reader for TypeDB's BUILD files.
//!
//! Scope: enough to enumerate every top-level rule call and read its attributes, so the
//! catalogue can reconcile BUILD-declared test targets against the generated Cargo
//! manifests (brief §21.10, §22.2). It is not a Starlark evaluator — `glob()` and
//! `select()` are kept as structured calls for the caller to resolve against the real
//! filesystem, and anything it cannot parse is reported rather than skipped.
//!
//! The "no unknown macro" rule (brief §1.5 Mode S) depends on this reader failing loudly,
//! so every unparseable construct surfaces as an error, never as an empty result.

use std::collections::BTreeMap;

use anyhow::{bail, Result};

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Str(String),
    List(Vec<Value>),
    Dict(Vec<(Value, Value)>),
    /// An unevaluated call such as `glob([...])` or `select({...})`.
    Call { name: String, args: Vec<Value>, kwargs: BTreeMap<String, Value> },
    /// A bare identifier or numeric literal (e.g. `True`, `None`, `1`).
    Ident(String),
}

impl Value {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    /// Every string literal reachable from this value, including inside `glob`/`select`.
    pub fn strings(&self) -> Vec<&str> {
        let mut out = Vec::new();
        self.collect_strings(&mut out);
        out
    }

    fn collect_strings<'a>(&'a self, out: &mut Vec<&'a str>) {
        match self {
            Value::Str(s) => out.push(s),
            Value::List(items) => items.iter().for_each(|i| i.collect_strings(out)),
            Value::Dict(pairs) => pairs.iter().for_each(|(k, v)| {
                k.collect_strings(out);
                v.collect_strings(out);
            }),
            Value::Call { args, kwargs, .. } => {
                args.iter().for_each(|a| a.collect_strings(out));
                kwargs.values().for_each(|a| a.collect_strings(out));
            }
            Value::Ident(_) => {}
        }
    }
}

/// One top-level rule invocation in a BUILD file.
#[derive(Debug, Clone)]
pub struct RuleCall {
    pub rule: String,
    pub attrs: BTreeMap<String, Value>,
    /// 1-based line of the opening call, for source anchors.
    pub line: usize,
}

impl RuleCall {
    pub fn name(&self) -> Option<&str> {
        self.attrs.get("name").and_then(Value::as_str)
    }

    pub fn attr_strings(&self, key: &str) -> Vec<&str> {
        self.attrs.get(key).map(Value::strings).unwrap_or_default()
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(text: &'a str) -> Self {
        Self { bytes: text.as_bytes(), pos: 0 }
    }

    fn line_of(&self, pos: usize) -> usize {
        self.bytes[..pos.min(self.bytes.len())]
            .iter()
            .filter(|&&b| b == b'\n')
            .count()
            + 1
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    /// Skip whitespace, `#` comments, and line continuations.
    fn skip_trivia(&mut self) {
        loop {
            match self.peek() {
                Some(b) if b.is_ascii_whitespace() => self.pos += 1,
                Some(b'#') => {
                    while let Some(b) = self.peek() {
                        self.pos += 1;
                        if b == b'\n' {
                            break;
                        }
                    }
                }
                Some(b'\\') if self.bytes.get(self.pos + 1) == Some(&b'\n') => self.pos += 2,
                _ => return,
            }
        }
    }

    fn read_string(&mut self) -> Result<String> {
        let quote = self.peek().unwrap();
        // Triple-quoted strings appear in docstrings; handle them so they cannot
        // swallow the rest of the file.
        let triple = self.bytes[self.pos..].starts_with(b"\"\"\"")
            || self.bytes[self.pos..].starts_with(b"'''");
        let delim_len = if triple { 3 } else { 1 };
        self.pos += delim_len;
        let start = self.pos;
        let mut out = String::new();
        loop {
            match self.peek() {
                None => bail!("unterminated string starting at byte {start}"),
                Some(b'\\') if !triple => {
                    let escaped = self.bytes.get(self.pos + 1).copied().unwrap_or(b'\\');
                    out.push(match escaped {
                        b'n' => '\n',
                        b't' => '\t',
                        b'r' => '\r',
                        other => other as char,
                    });
                    self.pos += 2;
                }
                Some(b) if b == quote => {
                    let closes = if triple {
                        self.bytes[self.pos..].starts_with(&[quote, quote, quote])
                    } else {
                        true
                    };
                    if closes {
                        self.pos += delim_len;
                        return Ok(out);
                    }
                    out.push(b as char);
                    self.pos += 1;
                }
                Some(_) => {
                    // Preserve multi-byte UTF-8 sequences intact.
                    let rest = std::str::from_utf8(&self.bytes[self.pos..])
                        .map_err(|e| anyhow::anyhow!("non-UTF-8 BUILD content: {e}"))?;
                    let ch = rest.chars().next().unwrap();
                    out.push(ch);
                    self.pos += ch.len_utf8();
                }
            }
        }
    }

    fn read_ident(&mut self) -> String {
        let start = self.pos;
        while let Some(b) = self.peek() {
            if b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-' {
                self.pos += 1;
            } else {
                break;
            }
        }
        String::from_utf8_lossy(&self.bytes[start..self.pos]).into_owned()
    }

    /// Read one value, folding any `+` concatenation that follows it.
    fn read_value(&mut self) -> Result<Value> {
        let atom = self.read_atom()?;
        self.absorb_concat(atom)
    }

    fn read_atom(&mut self) -> Result<Value> {
        self.skip_trivia();
        match self.peek() {
            None => bail!("unexpected end of file while reading a value"),
            Some(b'"') | Some(b'\'') => {
                // Adjacent string literals concatenate, as in Python.
                let mut s = self.read_string()?;
                loop {
                    let save = self.pos;
                    self.skip_trivia();
                    match self.peek() {
                        Some(b'"') | Some(b'\'') => s.push_str(&self.read_string()?),
                        _ => {
                            self.pos = save;
                            break;
                        }
                    }
                }
                Ok(Value::Str(s))
            }
            Some(b'[') => {
                self.pos += 1;
                let mut items = Vec::new();
                loop {
                    self.skip_trivia();
                    match self.peek() {
                        Some(b']') => {
                            self.pos += 1;
                            return Ok(Value::List(items));
                        }
                        Some(b',') => self.pos += 1,
                        None => bail!("unterminated list"),
                        _ => items.push(self.read_value()?),
                    }
                }
            }
            Some(b'{') => {
                self.pos += 1;
                let mut pairs = Vec::new();
                loop {
                    self.skip_trivia();
                    match self.peek() {
                        Some(b'}') => {
                            self.pos += 1;
                            return Ok(Value::Dict(pairs));
                        }
                        Some(b',') => self.pos += 1,
                        None => bail!("unterminated dict"),
                        _ => {
                            let key = self.read_value()?;
                            self.skip_trivia();
                            if self.peek() != Some(b':') {
                                bail!("expected ':' in dict at byte {}", self.pos);
                            }
                            self.pos += 1;
                            pairs.push((key, self.read_value()?));
                        }
                    }
                }
            }
            Some(b) if b.is_ascii_alphanumeric() || b == b'_' => {
                let ident = self.read_ident();
                let save = self.pos;
                self.skip_trivia();
                if self.peek() == Some(b'(') {
                    let (args, kwargs) = self.read_call_args()?;
                    return Ok(Value::Call { name: ident, args, kwargs });
                }
                self.pos = save;
                Ok(Value::Ident(ident))
            }
            Some(b) => bail!(
                "unsupported Starlark construct starting with {:?} at line {}",
                b as char,
                self.line_of(self.pos)
            ),
        }
    }

    /// Fold `a + b + c` into a single list so callers see all elements.
    fn absorb_concat(&mut self, first: Value) -> Result<Value> {
        let save = self.pos;
        self.skip_trivia();
        if self.peek() != Some(b'+') {
            self.pos = save;
            return Ok(first);
        }
        self.pos += 1;
        let rest = self.read_value()?;
        let mut items = match first {
            Value::List(v) => v,
            other => vec![other],
        };
        match rest {
            Value::List(v) => items.extend(v),
            other => items.push(other),
        }
        Ok(Value::List(items))
    }

    fn read_call_args(&mut self) -> Result<(Vec<Value>, BTreeMap<String, Value>)> {
        debug_assert_eq!(self.peek(), Some(b'('));
        self.pos += 1;
        let mut args = Vec::new();
        let mut kwargs = BTreeMap::new();
        loop {
            self.skip_trivia();
            match self.peek() {
                Some(b')') => {
                    self.pos += 1;
                    return Ok((args, kwargs));
                }
                Some(b',') => self.pos += 1,
                None => bail!("unterminated call argument list"),
                _ => {
                    // Distinguish `key = value` from a positional value.
                    let save = self.pos;
                    let ident = self.read_ident();
                    let after_ident = self.pos;
                    self.skip_trivia();
                    if !ident.is_empty() && self.peek() == Some(b'=')
                        && self.bytes.get(self.pos + 1) != Some(&b'=')
                    {
                        self.pos += 1;
                        kwargs.insert(ident, self.read_value()?);
                    } else {
                        self.pos = save.min(after_ident.max(save));
                        self.pos = save;
                        args.push(self.read_value()?);
                    }
                }
            }
        }
    }
}

/// Substitute top-level variable references with their assigned values.
///
/// `tests/assembly/BUILD` assigns `env = select({...})` at file scope and then passes
/// `env = env` to both `rust_test` rules, so without this the assembly archive
/// environment would silently read as empty.
fn resolve(value: Value, symbols: &BTreeMap<String, Value>) -> Value {
    match value {
        Value::Ident(name) => match symbols.get(&name) {
            Some(v) => v.clone(),
            None => Value::Ident(name),
        },
        Value::List(items) => Value::List(items.into_iter().map(|i| resolve(i, symbols)).collect()),
        Value::Dict(pairs) => Value::Dict(
            pairs
                .into_iter()
                .map(|(k, v)| (resolve(k, symbols), resolve(v, symbols)))
                .collect(),
        ),
        Value::Call { name, args, kwargs } => Value::Call {
            name,
            args: args.into_iter().map(|a| resolve(a, symbols)).collect(),
            kwargs: kwargs.into_iter().map(|(k, v)| (k, resolve(v, symbols))).collect(),
        },
        other => other,
    }
}

/// Parse every top-level rule call in a BUILD file.
///
/// `load(...)` statements are returned too, so the caller can prove that no
/// test-producing macro arrives from an unexamined `.bzl` file. Top-level assignments are
/// recorded in a symbol table and substituted into later rule attributes.
pub fn parse_build_file(text: &str) -> Result<Vec<RuleCall>> {
    let mut reader = Reader::new(text);
    let mut calls = Vec::new();
    let mut symbols: BTreeMap<String, Value> = BTreeMap::new();
    loop {
        reader.skip_trivia();
        let Some(b) = reader.peek() else { break };
        if !(b.is_ascii_alphabetic() || b == b'_') {
            bail!(
                "unsupported top-level statement at line {} (starts with {:?})",
                reader.line_of(reader.pos),
                b as char
            );
        }
        let line = reader.line_of(reader.pos);
        let ident = reader.read_ident();
        reader.skip_trivia();

        match reader.peek() {
            Some(b'(') => {
                let (args, kwargs) = reader.read_call_args()?;
                let mut attrs: BTreeMap<String, Value> = kwargs
                    .into_iter()
                    .map(|(k, v)| (k, resolve(v, &symbols)))
                    .collect();
                for (i, arg) in args.into_iter().enumerate() {
                    attrs.insert(format!("__positional_{i}"), resolve(arg, &symbols));
                }
                calls.push(RuleCall { rule: ident, attrs, line });
            }
            // `name = value` at file scope, e.g. `deps = [...]` or `env = select({...})`.
            Some(b'=') if reader.bytes.get(reader.pos + 1) != Some(&b'=') => {
                reader.pos += 1;
                let value = reader.read_value()?;
                symbols.insert(ident, resolve(value, &symbols));
            }
            _ => bail!(
                "top-level identifier `{ident}` at line {line} is neither a rule call nor an \
                 assignment"
            ),
        }
    }
    Ok(calls)
}

/// The rule names that produce a test target, and nothing else may.
///
/// The first three are Rust/static-check rules that Cargo can reach. `release_validate_deps`
/// is the one that is easy to miss and is why this list is source-verified rather than
/// grepped for `_test`: at `typedb/dependencies @ a5c51254`
/// `tool/release/deps/rules.bzl` it is a *macro* (L52) expanding to
/// `_release_validate_deps_script_test` — a rule declared with `test = True` (L48) — plus a
/// `kt_jvm_test` (L62). So one call site yields two Bazel test targets, and they are
/// Kotlin/JVM, which Cargo cannot express at all. Brief §22.2 lists exactly this class
/// ("release/dependency validations") as part of the denominator.
pub const TEST_PRODUCING_RULES: [&str; 4] =
    ["rust_test", "rustfmt_test", "checkstyle_test", "release_validate_deps"];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_rust_test_with_data_and_features() {
        let calls = parse_build_file(
            r#"
# comment
load("@rules_rust//rust:defs.bzl", "rust_test")

rust_test(
    name = "test_connection",
    crate_root = "main.rs",
    srcs = glob(["*.rs"]),
    data = [
        "@typedb_behaviour//connection:database.feature",
        "@typedb_behaviour//connection:transaction.feature",
    ],
    crate_features = ["bazel"],
    tags = ["manual_build"],
)
"#,
        )
        .unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].rule, "load");
        let t = &calls[1];
        assert_eq!(t.rule, "rust_test");
        assert_eq!(t.name(), Some("test_connection"));
        assert_eq!(t.attr_strings("crate_features"), vec!["bazel"]);
        assert_eq!(t.attr_strings("srcs"), vec!["*.rs"]);
        assert_eq!(
            t.attr_strings("data"),
            vec![
                "@typedb_behaviour//connection:database.feature",
                "@typedb_behaviour//connection:transaction.feature"
            ]
        );
    }

    #[test]
    fn keeps_select_branches_visible() {
        let calls = parse_build_file(
            r#"
rust_test(
    name = "test_assembly",
    env = select({
        "@typedb_bazel_distribution//platform:is_linux_x86_64": {"ARCHIVE": "//:linux-x86_64"},
        "//conditions:default": {"ARCHIVE": "//:other"},
    }),
)
"#,
        )
        .unwrap();
        // Both branches must be visible; a select must never collapse to one value.
        let envs = calls[0].attr_strings("env");
        assert!(envs.contains(&"//:linux-x86_64"));
        assert!(envs.contains(&"//:other"));
    }

    #[test]
    fn substitutes_a_file_scope_assignment_into_a_rule() {
        // Mirrors tests/assembly/BUILD, where both failpoint and assembly targets take
        // `env = env` and the archive name lives in a file-scope select().
        let calls = parse_build_file(
            r#"
env = select({
    "//platform:is_linux_x86_64": {"TYPEDB_ASSEMBLY_ARCHIVE": "typedb-all-linux-x86_64.tar.gz"},
})

rust_test(
    name = "test_assembly",
    env = env,
)
"#,
        )
        .unwrap();
        let t = calls.iter().find(|c| c.rule == "rust_test").unwrap();
        assert!(
            t.attr_strings("env").contains(&"typedb-all-linux-x86_64.tar.gz"),
            "a file-scope variable must not read as empty"
        );
    }

    #[test]
    fn rejects_constructs_it_cannot_read() {
        // A silent empty parse would manufacture "no unknown macros"; it must error.
        assert!(parse_build_file("if True:\n    pass\n").is_err());
    }

    #[test]
    fn folds_list_concatenation() {
        let calls = parse_build_file(r#"rust_test(name = "t", deps = ["//a"] + ["//b"])"#).unwrap();
        assert_eq!(calls[0].attr_strings("deps"), vec!["//a", "//b"]);
    }
}
