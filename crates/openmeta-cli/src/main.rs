mod commands;
mod demo;
mod output;
mod workspace;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "openmeta",
    version,
    about = "Publish, witness and verify signed package metadata"
)]
struct Cli {
    #[arg(
        long,
        global = true,
        default_value = "openmeta-data",
        env = "OPENMETA_DATA_DIR"
    )]
    data_dir: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(
        subcommand,
        about = "Manage Ed25519 identities for publishers, log operators and witnesses"
    )]
    Identity(IdentityCommand),
    #[command(subcommand, about = "Initialise and audit the publication log")]
    Log(LogCommand),
    #[command(about = "Sign package metadata and append it to the publication log")]
    Publish(PublishArgs),
    #[command(about = "Show records, optionally filtered by index or package URL")]
    Inspect {
        #[arg(long, conflicts_with = "purl")]
        index: Option<u64>,
        #[arg(long)]
        purl: Option<String>,
    },
    #[command(subcommand, about = "Create and inspect signed checkpoints")]
    Checkpoint(CheckpointCommand),
    #[command(about = "Export a record with its inclusion proof and checkpoint")]
    Prove {
        index: u64,
        #[arg(
            long,
            help = "Checkpoint size to prove against (defaults to the latest)"
        )]
        size: Option<u64>,
        #[arg(long, help = "Write the proof bundle to this file instead of stdout")]
        out: Option<PathBuf>,
    },
    #[command(subcommand, about = "Verify records, proof bundles and the whole log")]
    Verify(VerifyCommand),
    #[command(subcommand, about = "Run independent witnesses")]
    Witness(WitnessCommand),
    #[command(
        subcommand,
        about = "Anchor checkpoint commitments to the local ledger"
    )]
    Anchor(AnchorCommand),
    #[command(
        subcommand,
        about = "Simulate attacks against the current data directory"
    )]
    Simulate(SimulateCommand),
    #[command(about = "Run the complete deterministic demonstration scenario")]
    Demo {
        #[arg(long, default_value = "openmeta-demo")]
        dir: PathBuf,
    },
}

#[derive(Subcommand)]
enum IdentityCommand {
    New { name: String },
    List,
}

#[derive(Subcommand)]
enum LogCommand {
    Init {
        #[arg(long, help = "Identity that signs checkpoints")]
        operator: String,
    },
    #[command(about = "Replay every record and re-verify every stored checkpoint")]
    Verify,
}

#[derive(Args)]
struct PublishArgs {
    #[arg(long)]
    publisher: String,
    #[arg(long)]
    purl: String,
    #[arg(long)]
    repository: String,
    #[arg(long = "source-revision")]
    source_revision: String,
    #[arg(
        long,
        conflicts_with = "artifact",
        required_unless_present = "artifact"
    )]
    digest: Option<String>,
    #[arg(long, help = "File whose SHA-256 digest is recorded")]
    artifact: Option<PathBuf>,
    #[arg(long)]
    license: String,
    #[arg(long = "dependency", value_name = "PURL[=REQUIREMENT]")]
    dependencies: Vec<String>,
    #[arg(long = "vulnerability", value_name = "ID=STATUS")]
    vulnerabilities: Vec<String>,
    #[arg(long, help = "Unix timestamp (defaults to now)")]
    timestamp: Option<u64>,
}

#[derive(Subcommand)]
enum CheckpointCommand {
    Create {
        #[arg(long, help = "Unix timestamp (defaults to now)")]
        timestamp: Option<u64>,
    },
    Show {
        #[arg(long)]
        size: Option<u64>,
        #[arg(long, help = "Print the signed checkpoint as JSON")]
        json: bool,
    },
    List,
    #[command(about = "Compare two checkpoint files")]
    Compare {
        first: PathBuf,
        second: PathBuf,
    },
}

#[derive(Subcommand)]
enum VerifyCommand {
    #[command(about = "Verify a stored record and its inclusion in the latest checkpoint")]
    Record {
        index: u64,
        #[arg(long, help = "Require the record to be signed by this identity")]
        publisher: Option<String>,
    },
    #[command(about = "Verify an exported proof bundle against the trusted log key")]
    Proof {
        file: PathBuf,
        #[arg(long, help = "Expected publisher public key (hex)")]
        publisher_key: Option<String>,
    },
}

#[derive(Subcommand)]
enum WitnessCommand {
    New {
        name: String,
    },
    #[command(
        about = "Fetch the latest checkpoint, audit the log and record a cosigned observation"
    )]
    Observe {
        name: String,
        #[arg(
            long,
            help = "Only verify the consistency proof, skip replaying records"
        )]
        no_audit: bool,
    },
    Show {
        name: String,
    },
    Compare {
        first: String,
        second: String,
    },
}

#[derive(Subcommand)]
enum AnchorCommand {
    Submit {
        #[arg(long)]
        size: Option<u64>,
    },
    Verify {
        #[arg(long)]
        size: Option<u64>,
    },
    List,
}

#[derive(Subcommand)]
enum SimulateCommand {
    #[command(about = "Modify a copy of a record and show which checks catch it")]
    Tamper { index: u64 },
    #[command(
        about = "Have the log operator sign a conflicting checkpoint and present it to a witness"
    )]
    Equivocate {
        #[arg(long)]
        witness: String,
        #[arg(
            long,
            help = "Publisher whose latest record is replaced in the forked view"
        )]
        publisher: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Demo { dir } => demo::run(&dir),
        command => commands::run(&cli.data_dir, command),
    };
    match result {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}
