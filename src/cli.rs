use clap::{ArgAction, Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};

/// Parse a signed integer that may be written in decimal (`16`, `-4`),
/// hex (`0x10`, `0X10`), binary (`0b1000`), or octal (`0o20`).
///
/// Ghidra struct offsets are conventionally written in hex; the CLI used to
/// require decimal which forced manual conversion at every callsite.
fn parse_i32_with_radix(raw: &str) -> Result<i32, String> {
    let s = raw.trim();
    let (negative, rest) = match s.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    let (radix, digits) = if let Some(d) = rest.strip_prefix("0x").or_else(|| rest.strip_prefix("0X")) {
        (16, d)
    } else if let Some(d) = rest.strip_prefix("0b").or_else(|| rest.strip_prefix("0B")) {
        (2, d)
    } else if let Some(d) = rest.strip_prefix("0o").or_else(|| rest.strip_prefix("0O")) {
        (8, d)
    } else {
        (10, rest)
    };
    let magnitude = i64::from_str_radix(digits, radix)
        .map_err(|e| format!("invalid integer `{}`: {}", raw, e))?;
    let signed = if negative { -magnitude } else { magnitude };
    i32::try_from(signed).map_err(|_| format!("value `{}` out of range for i32", raw))
}

const CLI_AFTER_HELP: &str = "\
COMMON COMMANDS:
    decompile <name|addr>            Decompile one function
    decompile-bulk --filter <substr> Decompile many in one bridge round-trip
    function list --filter <substr>  List functions by name substring
    function set-signature <name> --signature \"...\"
    type list / type get / type create / type add-field
    equate list                      Named scalar values applied to operands
    data list                        Labeled globals/tables (user-typed by default)
    x-ref to <addr|name>             Cross-references to an address
    batch <file>                     Run many CLI commands in one transaction

NOTES:
    --filter is a case-insensitive substring match on the primary name field.
    The richer grammar in src/filter.pest is parsed but not honored by list
    commands.

    List commands default to --limit 1000. Pass --limit 0 for unlimited.

    The bridge auto-starts on first use (~25s cold). After rebuilding the
    Java bridge, run `ghidra restart` to pick up changes.

    Add --json for machine output, --pretty for indented JSON. JSON
    responses are wrapped in a one-element array.

If you're in a project that has tools/ghidra/README.md, that file has the
project-specific command catalog and conventions.
";

#[derive(Parser)]
#[command(name = "ghidra")]
#[command(version, about = "Rust CLI for Ghidra reverse engineering", long_about = None)]
#[command(after_help = CLI_AFTER_HELP)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Increase log verbosity printed to stdout (-v=warn, -vv=info, -vvv=debug)
    #[arg(short, long, action = ArgAction::Count, global = true)]
    pub verbose: u8,

    /// Suppress non-essential output
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// Output as JSON
    #[arg(long, global = true)]
    pub json: bool,

    /// Output JSON with pretty formatting
    #[arg(long, global = true)]
    pub pretty: bool,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum Commands {
    /// Universal query command for any data type
    Query(QueryArgs),

    /// Project management commands
    Project(ProjectArgs),

    /// Program/binary management commands
    #[command(subcommand, alias = "prog", alias = "programs")]
    Program(ProgramCommands),

    /// Function operations
    #[command(subcommand, alias = "fn", alias = "func", alias = "functions")]
    Function(FunctionCommands),

    /// String operations
    #[command(subcommand, alias = "string", alias = "str")]
    Strings(StringsCommands),

    /// Symbol operations
    #[command(subcommand, alias = "sym", alias = "symbols")]
    Symbol(SymbolCommands),

    /// Memory operations
    #[command(subcommand, alias = "mem")]
    Memory(MemoryCommands),

    /// Cross-reference operations
    #[command(
        subcommand,
        alias = "xrefs",
        alias = "xref",
        alias = "crossref",
        alias = "crossrefs"
    )]
    XRef(XRefCommands),

    /// Type operations
    #[command(subcommand, alias = "types")]
    Type(TypeCommands),

    /// Equate (named scalar value) operations
    #[command(subcommand, alias = "equates", alias = "eq")]
    Equate(EquateCommands),

    /// Defined data (labeled globals/tables) operations
    #[command(name = "data", subcommand)]
    DataCmd(DataCommands),

    /// Comment operations
    #[command(subcommand, alias = "comments")]
    Comment(CommentCommands),

    /// Search operations
    #[command(subcommand, alias = "search")]
    Find(FindCommands),

    /// Graph operations
    #[command(subcommand, alias = "callgraph", alias = "cg")]
    Graph(GraphCommands),

    /// Decompile function
    #[command(alias = "decomp", alias = "dec")]
    Decompile(DecompileArgs),

    /// Decompile many functions in one bridge round-trip
    ///
    /// Selectors (combine freely; results are deduped by entry point):
    ///   --filter <substr>     : function-name substring match
    ///   --name <name>         : explicit name (repeatable)
    ///   --address <addr>      : explicit entry-point address (repeatable)
    /// With no selector, decompiles every function in the program.
    #[command(alias = "decomp-bulk", alias = "dec-bulk")]
    DecompileBulk(DecompileBulkArgs),

    /// Disassemble code
    #[command(alias = "disassemble", alias = "dis")]
    Disasm(DisasmArgs),

    /// Diff operations
    #[command(subcommand)]
    Diff(DiffCommands),

    /// Dump/export data
    #[command(subcommand, alias = "export")]
    Dump(DumpCommands),

    /// Patch binary
    #[command(subcommand)]
    Patch(PatchCommands),

    /// Script execution
    #[command(subcommand, alias = "scripts")]
    Script(ScriptCommands),

    /// Batch operations
    Batch(BatchArgs),

    /// Configuration management
    #[command(subcommand)]
    Config(ConfigCommands),

    /// Set default values
    SetDefault(SetDefaultArgs),

    /// Program summary
    #[command(alias = "info")]
    Summary(SummaryArgs),

    /// Program statistics
    Stats(StatsArgs),

    /// Show version information
    Version,

    /// Check Ghidra installation
    Doctor,

    /// Initialize configuration
    Init,

    /// Import a binary into a project
    Import(ImportArgs),

    /// Analyze a program
    #[command(alias = "analysis")]
    Analyze(AnalyzeArgs),

    /// Start the bridge
    Start {
        /// Project path
        #[arg(long)]
        project: Option<String>,
        /// Program name to load
        #[arg(long)]
        program: Option<String>,
    },

    /// Stop the bridge
    Stop {
        /// Project path
        #[arg(long)]
        project: Option<String>,
    },

    /// Restart the bridge
    Restart {
        /// Project path
        #[arg(long)]
        project: Option<String>,
        /// Program name to load
        #[arg(long)]
        program: Option<String>,
    },

    /// Show bridge status
    Status {
        /// Project path
        #[arg(long)]
        project: Option<String>,
    },

    /// Ping the bridge
    Ping {
        /// Project path
        #[arg(long)]
        project: Option<String>,
    },

    /// Download and setup Ghidra automatically
    Setup(SetupArgs),

    /// Rename a symbol (shortcut for `symbol rename`)
    #[command(alias = "mv")]
    Rename(RenameArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct QueryArgs {
    /// Data type to query (functions, strings, imports, etc.)
    pub data_type: String,

    /// Target program
    #[arg(long, env = "GHIDRA_DEFAULT_PROGRAM")]
    pub program: Option<String>,

    /// Project name
    #[arg(long, env = "GHIDRA_DEFAULT_PROJECT")]
    pub project: Option<String>,

    /// Filter expression
    #[arg(short, long)]
    pub filter: Option<String>,

    /// Field selection (comma-separated)
    #[arg(long)]
    pub fields: Option<String>,

    /// Output format
    #[arg(long, short = 'o')]
    pub format: Option<String>,

    /// Maximum number of results
    #[arg(long)]
    pub limit: Option<usize>,

    /// Skip first N results
    #[arg(long)]
    pub offset: Option<usize>,

    /// Sort by field(s) (comma-separated, prefix with - for descending)
    #[arg(long, allow_hyphen_values = true)]
    pub sort: Option<String>,

    /// Only return count
    #[arg(long)]
    pub count: bool,

    /// Output as JSON (shorthand for --format=json)
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct ProjectArgs {
    #[command(subcommand)]
    pub command: ProjectCommands,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum ProjectCommands {
    /// Create a new project
    Create { name: String },
    /// List all projects
    List,
    /// Delete a project
    Delete { name: String },
    /// Show project information
    Info { name: Option<String> },
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum ProgramCommands {
    /// List all programs in the project
    #[command(alias = "ls")]
    List(ProgramTargetArgs),
    /// Open/switch to a program
    Open(ProgramTargetArgs),
    /// Close a program
    Close(ProgramTargetArgs),
    /// Delete a program
    Delete(ProgramTargetArgs),
    /// Show program information
    Info(ProgramTargetArgs),
    /// Export program
    Export(ExportArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct ProgramTargetArgs {
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct ExportArgs {
    /// Export format (xml, json, asm, c)
    pub format: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
    /// Output file
    #[arg(short, long)]
    pub output: Option<String>,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum FunctionCommands {
    /// List all functions
    #[command(alias = "ls")]
    List(QueryOptions),
    /// Get function details
    #[command(alias = "show", alias = "detail")]
    Get(FunctionGetArgs),
    /// Decompile function
    #[command(alias = "decomp")]
    Decompile(FunctionDecompileArgs),
    /// Disassemble function
    #[command(alias = "disassemble", alias = "dis")]
    Disasm(FunctionGetArgs),
    /// Get function calls
    Calls(FunctionGetArgs),
    /// Get cross-references to function
    #[command(alias = "xrefs", alias = "crossrefs", alias = "references")]
    XRefs(FunctionGetArgs),
    /// Rename function
    Rename(RenameArgs),
    /// Create function
    Create(CreateFunctionArgs),
    /// Delete function
    Delete(FunctionGetArgs),
    /// Set function signature from C-style string
    SetSignature(SetSignatureArgs),
    /// Set function return type
    SetReturnType(SetReturnTypeArgs),
    /// Set function calling convention
    SetCallingConvention(SetCallingConventionArgs),
    /// Set variable type in a function
    SetVarType(SetVarTypeArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct FunctionGetArgs {
    /// Function target (name/address/FUN_...)
    #[arg(value_name = "TARGET", required_unless_present = "target")]
    pub positional_target: Option<String>,
    /// Function target (name | 0xaddr | FUN_<hex>)
    #[arg(long = "target", value_name = "TARGET")]
    pub target: Option<String>,
    #[command(flatten)]
    pub options: QueryOptions,
}

impl FunctionGetArgs {
    pub fn resolved_target(&self) -> &str {
        self.target
            .as_deref()
            .or(self.positional_target.as_deref())
            .expect("clap should ensure target is provided")
    }
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct RenameArgs {
    pub old_name: String,
    pub new_name: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct CreateFunctionArgs {
    pub address: String,
    pub name: Option<String>,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct FunctionDecompileArgs {
    /// Function target (name/address/FUN_...)
    #[arg(value_name = "TARGET", required_unless_present = "target")]
    pub positional_target: Option<String>,
    /// Function target (name | 0xaddr | FUN_<hex>)
    #[arg(long = "target", value_name = "TARGET")]
    pub target: Option<String>,
    /// Include local variable details (name, type, storage)
    #[arg(long)]
    pub with_vars: bool,
    /// Include parameter details (name, type, storage)
    #[arg(long)]
    pub with_params: bool,
    #[command(flatten)]
    pub options: QueryOptions,
}

impl FunctionDecompileArgs {
    pub fn resolved_target(&self) -> &str {
        self.target
            .as_deref()
            .or(self.positional_target.as_deref())
            .expect("clap should ensure target is provided")
    }
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct SetSignatureArgs {
    /// Function target (name | 0xaddr | FUN_<hex>)
    #[arg(value_name = "TARGET", required_unless_present = "target")]
    pub positional_target: Option<String>,
    /// Function target (name | 0xaddr | FUN_<hex>)
    #[arg(long = "target", value_name = "TARGET")]
    pub target: Option<String>,
    /// C-style signature string, e.g. "int main(int argc, char** argv)"
    #[arg(long)]
    pub signature: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

impl SetSignatureArgs {
    pub fn resolved_target(&self) -> &str {
        self.target
            .as_deref()
            .or(self.positional_target.as_deref())
            .expect("clap should ensure target is provided")
    }
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct SetReturnTypeArgs {
    /// Function target (name | 0xaddr | FUN_<hex>)
    #[arg(value_name = "TARGET", required_unless_present = "target")]
    pub positional_target: Option<String>,
    /// Function target (name | 0xaddr | FUN_<hex>)
    #[arg(long = "target", value_name = "TARGET")]
    pub target: Option<String>,
    /// Return type name
    #[arg(long = "type")]
    pub return_type: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

impl SetReturnTypeArgs {
    pub fn resolved_target(&self) -> &str {
        self.target
            .as_deref()
            .or(self.positional_target.as_deref())
            .expect("clap should ensure target is provided")
    }
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct SetCallingConventionArgs {
    /// Function target (name | 0xaddr | FUN_<hex>)
    #[arg(value_name = "TARGET", required_unless_present = "target")]
    pub positional_target: Option<String>,
    /// Function target (name | 0xaddr | FUN_<hex>)
    #[arg(long = "target", value_name = "TARGET")]
    pub target: Option<String>,
    /// Calling convention name (e.g., "__cdecl", "__stdcall", "__fastcall")
    #[arg(long)]
    pub convention: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

impl SetCallingConventionArgs {
    pub fn resolved_target(&self) -> &str {
        self.target
            .as_deref()
            .or(self.positional_target.as_deref())
            .expect("clap should ensure target is provided")
    }
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct SetVarTypeArgs {
    /// Function target (name | 0xaddr | FUN_<hex>)
    #[arg(value_name = "TARGET", required_unless_present = "target")]
    pub positional_target: Option<String>,
    /// Function target (name | 0xaddr | FUN_<hex>)
    #[arg(long = "target", value_name = "TARGET")]
    pub target: Option<String>,
    /// Variable name to retype
    #[arg(long = "var")]
    pub var_name: String,
    /// New type name (e.g., "int", "char *", "MyStruct")
    #[arg(long = "type")]
    pub type_name: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

impl SetVarTypeArgs {
    pub fn resolved_target(&self) -> &str {
        self.target
            .as_deref()
            .or(self.positional_target.as_deref())
            .expect("clap should ensure target is provided")
    }
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum StringsCommands {
    /// List all strings
    #[command(alias = "ls")]
    List(QueryOptions),
    /// Get references to a string
    #[command(alias = "references", alias = "xrefs")]
    Refs(StringRefsArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct StringRefsArgs {
    pub string: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum SymbolCommands {
    /// List all symbols
    #[command(alias = "ls")]
    List(QueryOptions),
    /// Get symbol details
    Get(SymbolGetArgs),
    /// Create symbol
    Create(CreateSymbolArgs),
    /// Delete symbol
    Delete(SymbolGetArgs),
    /// Rename symbol
    Rename(RenameArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct SymbolGetArgs {
    pub name: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct CreateSymbolArgs {
    pub address: String,
    pub name: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum EquateCommands {
    /// List all equates (named scalar values applied to operands)
    #[command(alias = "ls")]
    List(QueryOptions),
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum DataCommands {
    /// List defined data items (labeled globals, tables, constants)
    ///
    /// By default only items with a user-assigned name AND a non-default
    /// data type are returned — i.e. things you intentionally typed in
    /// Ghidra. Use --include-default / --include-unnamed to widen.
    #[command(alias = "ls")]
    List(DataListArgs),
    /// Read the structured value of a data item (expands structs/arrays)
    Read(DataReadArgs),
    /// Set the data type of a global/label at an address
    SetType(DataSetTypeArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct DataListArgs {
    /// Include items whose data type is undefined / default
    #[arg(long)]
    pub include_default: bool,

    /// Include items with auto-generated names (DAT_*, LAB_*) or no symbol
    #[arg(long)]
    pub include_unnamed: bool,

    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct DataReadArgs {
    /// Name or address of the data item
    pub target: String,

    /// Max recursion depth for nested structs/arrays (default 4)
    #[arg(long, default_value_t = 4)]
    pub max_depth: usize,

    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct DataSetTypeArgs {
    /// Name or address of the data item
    pub target: String,

    /// Type to apply (e.g. "MapUvCornerTable", "ushort[64]", "int")
    #[arg(long = "type")]
    pub type_name: String,

    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum MemoryCommands {
    /// Show memory map
    Map(QueryOptions),
    /// Read memory
    Read(MemReadArgs),
    /// Write memory
    Write(MemWriteArgs),
    /// Search memory
    Search(MemSearchArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct MemReadArgs {
    pub address: String,
    pub size: usize,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct MemWriteArgs {
    pub address: String,
    pub bytes: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct MemSearchArgs {
    pub pattern: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum XRefCommands {
    /// Get cross-references to address
    To(XRefArgs),
    /// Get cross-references from address
    From(XRefArgs),
    /// List all cross-references
    List(XRefArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct XRefArgs {
    /// XRef target (name | 0xaddr | FUN_<hex>)
    #[arg(value_name = "TARGET", required_unless_present = "target")]
    pub positional_target: Option<String>,
    /// XRef target (name | 0xaddr | FUN_<hex>)
    #[arg(long = "target", value_name = "TARGET")]
    pub target: Option<String>,
    #[command(flatten)]
    pub options: QueryOptions,
}

impl XRefArgs {
    pub fn resolved_target(&self) -> &str {
        self.target
            .as_deref()
            .or(self.positional_target.as_deref())
            .expect("clap should ensure target is provided")
    }
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum TypeCommands {
    /// List data types
    #[command(alias = "ls")]
    List(QueryOptions),
    /// Get type definition
    Get(TypeGetArgs),
    /// Create type
    Create(CreateTypeArgs),
    /// Apply type to address
    Apply(ApplyTypeArgs),
    /// Delete a data type
    #[command(alias = "rm")]
    Delete(TypeDeleteArgs),
    /// Rename a data type
    #[command(alias = "mv")]
    Rename(TypeRenameArgs),
    /// Create an enum type
    CreateEnum(CreateEnumArgs),
    /// Create a typedef (type alias)
    Typedef(TypedefArgs),
    /// Add a field to a struct type
    AddField(TypeAddFieldArgs),
    /// Remove a field from a struct type
    DelField(TypeDelFieldArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TypeGetArgs {
    pub name: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct CreateTypeArgs {
    pub definition: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct ApplyTypeArgs {
    pub address: String,
    pub type_name: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TypeDeleteArgs {
    /// Name or path of the type to delete
    pub name: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TypeRenameArgs {
    /// Current name of the type
    pub old_name: String,
    /// New name for the type
    pub new_name: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct CreateEnumArgs {
    /// Enum type name
    pub name: String,
    /// Comma-separated KEY=VALUE pairs, e.g. "RED=0,GREEN=1,BLUE=2"
    #[arg(long)]
    pub values: String,
    /// Size in bytes (1, 2, 4, or 8)
    #[arg(long, default_value = "4")]
    pub size: i32,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TypedefArgs {
    /// Name for the new typedef
    pub name: String,
    /// Base type to alias (e.g., "int", "dword", "MyStruct")
    pub base_type: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TypeAddFieldArgs {
    /// Name of the struct type to modify
    pub type_name: String,
    /// Field name
    #[arg(long)]
    pub name: String,
    /// Field type (e.g., "int", "byte", "pointer", a custom struct name)
    #[arg(long = "type")]
    pub field_type: String,
    /// Offset within the struct (decimal, 0x-hex, 0b-binary, or 0o-octal; if
    /// omitted, appends at end)
    #[arg(long, value_parser = parse_i32_with_radix)]
    pub offset: Option<i32>,
    /// Field size override (decimal, 0x-hex, 0b-binary, or 0o-octal)
    #[arg(long, value_parser = parse_i32_with_radix)]
    pub size: Option<i32>,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TypeDelFieldArgs {
    /// Name of the struct type to modify
    pub type_name: String,
    /// Field name to remove
    #[arg(long)]
    pub name: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum CommentCommands {
    /// List all comments
    #[command(alias = "ls")]
    List(QueryOptions),
    /// Get comment at address
    Get(CommentGetArgs),
    /// Set comment
    Set(CommentSetArgs),
    /// Delete comment
    Delete(CommentGetArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct CommentGetArgs {
    pub address: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct CommentSetArgs {
    pub address: String,
    pub text: String,
    #[arg(long)]
    pub comment_type: Option<String>,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum FindCommands {
    /// Find strings
    #[command(alias = "str", alias = "strings")]
    String(FindStringArgs),
    /// Find byte patterns
    Bytes(FindBytesArgs),
    /// Find functions
    #[command(alias = "func", alias = "fn", alias = "functions")]
    Function(FindFunctionArgs),
    /// Find calls to function
    Calls(FindCallsArgs),
    /// Find crypto constants
    #[command(alias = "encryption")]
    Crypto(QueryOptions),
    /// Find interesting functions
    #[command(alias = "suspicious", alias = "notable")]
    Interesting(QueryOptions),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct FindStringArgs {
    pub pattern: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct FindBytesArgs {
    pub hex: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct FindFunctionArgs {
    pub pattern: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct FindCallsArgs {
    /// Function target (name | 0xaddr | FUN_<hex>)
    #[arg(value_name = "TARGET", required_unless_present = "target")]
    pub positional_target: Option<String>,
    /// Function target (name | 0xaddr | FUN_<hex>)
    #[arg(long = "target", value_name = "TARGET")]
    pub target: Option<String>,
    #[command(flatten)]
    pub options: QueryOptions,
}

impl FindCallsArgs {
    pub fn resolved_target(&self) -> &str {
        self.target
            .as_deref()
            .or(self.positional_target.as_deref())
            .expect("clap should ensure target is provided")
    }
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum GraphCommands {
    /// Call graph
    Calls(QueryOptions),
    /// Get callers of function
    #[command(alias = "called-by", alias = "incoming")]
    Callers(GraphFunctionArgs),
    /// Get callees of function
    #[command(alias = "calls-to", alias = "outgoing")]
    Callees(GraphFunctionArgs),
    /// Export graph
    Export(GraphExportArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct GraphFunctionArgs {
    /// Function target (name | 0xaddr | FUN_<hex>)
    #[arg(value_name = "TARGET", required_unless_present = "target")]
    pub positional_target: Option<String>,
    /// Function target (name | 0xaddr | FUN_<hex>)
    #[arg(long = "target", value_name = "TARGET")]
    pub target: Option<String>,
    #[arg(long)]
    pub depth: Option<usize>,
    #[command(flatten)]
    pub options: QueryOptions,
}

impl GraphFunctionArgs {
    pub fn resolved_target(&self) -> &str {
        self.target
            .as_deref()
            .or(self.positional_target.as_deref())
            .expect("clap should ensure target is provided")
    }
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct GraphExportArgs {
    /// Export format (e.g., dot, json)
    #[arg(id = "export_format")]
    pub format: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct DecompileArgs {
    /// Function target (name | 0xaddr | FUN_<hex>)
    #[arg(value_name = "TARGET", required_unless_present = "target")]
    pub positional_target: Option<String>,
    /// Function target (name | 0xaddr | FUN_<hex>)
    #[arg(long = "target", value_name = "TARGET")]
    pub target: Option<String>,
    /// Include local variable details (name, type, storage)
    #[arg(long)]
    pub with_vars: bool,
    /// Include parameter details (name, type, storage)
    #[arg(long)]
    pub with_params: bool,
    #[command(flatten)]
    pub options: QueryOptions,
}

impl DecompileArgs {
    pub fn resolved_target(&self) -> &str {
        self.target
            .as_deref()
            .or(self.positional_target.as_deref())
            .expect("clap should ensure target is provided")
    }
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct DecompileBulkArgs {
    /// Explicit function name (repeatable)
    #[arg(long = "name", value_name = "NAME")]
    pub names: Vec<String>,

    /// Explicit entry-point address (repeatable, e.g. 0x00401000 or FUN_00401000)
    #[arg(long = "address", value_name = "ADDR")]
    pub addresses: Vec<String>,

    /// Per-function decompile timeout in seconds
    #[arg(long, default_value = "30")]
    pub timeout: usize,

    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct DisasmArgs {
    /// Disassembly target (name | 0xaddr | FUN_<hex>)
    #[arg(value_name = "TARGET", required_unless_present = "target")]
    pub positional_target: Option<String>,
    /// Disassembly target (name | 0xaddr | FUN_<hex>)
    #[arg(long = "target", value_name = "TARGET")]
    pub target: Option<String>,
    /// Number of instructions to disassemble
    #[arg(long = "instructions", short = 'n')]
    pub num_instructions: Option<usize>,
    #[command(flatten)]
    pub options: QueryOptions,
}

impl DisasmArgs {
    pub fn resolved_target(&self) -> &str {
        self.target
            .as_deref()
            .or(self.positional_target.as_deref())
            .expect("clap should ensure target is provided")
    }
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum DiffCommands {
    /// Compare two programs
    Programs(DiffProgramsArgs),
    /// Compare functions
    Functions(DiffFunctionsArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct DiffProgramsArgs {
    pub program1: String,
    pub program2: String,
    #[arg(long)]
    pub format: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct DiffFunctionsArgs {
    /// First function (name or address)
    pub func1: String,
    /// Second function (name or address)
    pub func2: String,
    #[arg(long)]
    pub format: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum DumpCommands {
    /// Dump imports
    Imports(QueryOptions),
    /// Dump exports
    Exports(QueryOptions),
    /// Dump functions
    Functions(QueryOptions),
    /// Dump strings
    Strings(QueryOptions),
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum PatchCommands {
    /// Patch bytes
    Bytes(PatchBytesArgs),
    /// NOP instructions
    Nop(PatchNopArgs),
    /// Export patched binary
    Export(PatchExportArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct PatchBytesArgs {
    pub address: String,
    pub hex: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct PatchNopArgs {
    pub address: String,
    #[arg(long)]
    pub count: Option<usize>,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct PatchExportArgs {
    #[arg(short, long)]
    pub output: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum ScriptCommands {
    /// Run a script file
    Run(ScriptRunArgs),
    /// Execute inline Python code
    Python(ScriptInlineArgs),
    /// Execute inline Java code
    Java(ScriptInlineArgs),
    /// List available scripts
    List,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct ScriptRunArgs {
    pub script_path: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
    /// Script arguments (after --)
    #[arg(last = true)]
    pub args: Vec<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct ScriptInlineArgs {
    pub code: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct BatchArgs {
    pub script_file: String,

    #[arg(long)]
    pub project: Option<String>,

    #[arg(long)]
    pub program: Option<String>,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum ConfigCommands {
    /// List all configuration
    List,
    /// Get configuration value
    Get { key: String },
    /// Set configuration value
    Set { key: String, value: String },
    /// Reset configuration
    Reset,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct SetDefaultArgs {
    pub kind: String,
    pub value: String,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct SummaryArgs {
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct StatsArgs {
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct ImportArgs {
    pub binary: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
    /// Return immediately, let bridge continue import in background
    #[arg(long, default_value = "false")]
    pub detach: bool,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct AnalyzeArgs {
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
    /// Return immediately, let bridge continue analysis in background
    #[arg(long, default_value = "false")]
    pub detach: bool,
}

/// Common query options used across commands
#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct QueryOptions {
    #[arg(long)]
    pub program: Option<String>,

    #[arg(long)]
    pub project: Option<String>,

    #[arg(short, long)]
    pub filter: Option<String>,

    #[arg(long)]
    pub fields: Option<String>,

    #[arg(long, short = 'o')]
    pub format: Option<String>,

    #[arg(long)]
    pub limit: Option<usize>,

    #[arg(long)]
    pub offset: Option<usize>,

    #[arg(long, allow_hyphen_values = true)]
    pub sort: Option<String>,

    #[arg(long)]
    pub count: bool,

    #[arg(long)]
    pub json: bool,
}

/// Arguments for the setup command
#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct SetupArgs {
    /// Specific Ghidra version to install (e.g., "11.0"). Defaults to latest.
    #[arg(long)]
    pub version: Option<String>,

    /// Installation directory. Defaults to standard data directory.
    #[arg(long, short = 'd')]
    pub dir: Option<String>,

    /// Skip Java check
    #[arg(long)]
    pub force: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_decompile_target_flag() {
        let cli = Cli::try_parse_from(["ghidra", "decompile", "--target", "FUN_00401000"])
            .expect("decompile --target should parse");
        match cli.command {
            Commands::Decompile(args) => assert_eq!(args.resolved_target(), "FUN_00401000"),
            _ => panic!("expected decompile command"),
        }
    }

    #[test]
    fn parses_function_get_positional_target() {
        let cli = Cli::try_parse_from(["ghidra", "function", "get", "main"])
            .expect("function get positional target should parse");
        match cli.command {
            Commands::Function(FunctionCommands::Get(args)) => {
                assert_eq!(args.resolved_target(), "main");
            }
            _ => panic!("expected function get command"),
        }
    }

    #[test]
    fn parse_i32_with_radix_accepts_decimal_and_hex() {
        assert_eq!(parse_i32_with_radix("16").unwrap(), 16);
        assert_eq!(parse_i32_with_radix("-4").unwrap(), -4);
        assert_eq!(parse_i32_with_radix("0x10").unwrap(), 16);
        assert_eq!(parse_i32_with_radix("0X10").unwrap(), 16);
        assert_eq!(parse_i32_with_radix("-0x10").unwrap(), -16);
        assert_eq!(parse_i32_with_radix("0b1010").unwrap(), 10);
        assert_eq!(parse_i32_with_radix("0o20").unwrap(), 16);
        assert!(parse_i32_with_radix("0xZZ").is_err());
        assert!(parse_i32_with_radix("").is_err());
    }

    #[test]
    fn type_add_field_accepts_hex_offset() {
        let cli = Cli::try_parse_from([
            "ghidra", "type", "add-field", "MyStruct",
            "--name", "x", "--type", "int", "--offset", "0x10",
        ])
        .expect("hex --offset should parse");
        match cli.command {
            Commands::Type(TypeCommands::AddField(args)) => {
                assert_eq!(args.offset, Some(16));
            }
            _ => panic!("expected type add-field command"),
        }
    }
}
