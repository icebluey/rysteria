use std::io;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand, ValueEnum};
use serde_json::{Map as JsonMap, Value as JsonValue};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::format::{FormatEvent, FormatFields, Writer};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;

use rysteria::app::cmd;
use rysteria::app::cmd::client::SpeedtestArgs;

#[derive(Debug, Parser)]
#[command(name = "rysteria")]
#[command(about = "A QUIC-based proxy")]
#[command(disable_help_subcommand = true)]
struct Cli {
    #[arg(
        short = 'c',
        long = "config",
        global = true,
        value_name = "FILE",
        help = "Config file path (default: auto-detect)"
    )]
    config: Option<PathBuf>,

    #[arg(
        short = 'l',
        long = "log-level",
        global = true,
        env = "RYSTERIA_LOG_LEVEL",
        default_value = "info",
        value_name = "LEVEL",
        help = "Log level: debug|info|warn|error|none"
    )]
    log_level: LogLevelArg,

    #[arg(
        short = 'f',
        long = "log-format",
        global = true,
        env = "RYSTERIA_LOG_FORMAT",
        default_value = "console",
        value_name = "FORMAT",
        help = "Log format: console|json"
    )]
    log_format: LogFormatArg,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    #[command(about = "Start proxy server (reads config file)")]
    Server,
    #[command(about = "Start proxy client (default if no subcommand given; reads config file)")]
    Client,
    #[command(about = "TCP ping to <addr> through the proxy server")]
    Ping { addr: String },
    #[command(about = "Speed test through the proxy server")]
    Speedtest {
        #[arg(
            long = "skip-download",
            default_value_t = false,
            help = "Skip download test (default: false)"
        )]
        skip_download: bool,
        #[arg(
            long = "skip-upload",
            default_value_t = false,
            help = "Skip upload test (default: false)"
        )]
        skip_upload: bool,
        #[arg(
            long = "duration",
            default_value_t = 10,
            value_name = "SECONDS",
            help = "Duration in seconds for each test direction, used in time-based mode (default: 10)"
        )]
        duration_secs: u64,
        #[arg(
            long = "data-size",
            value_name = "BYTES",
            help = "Data size for each test in bytes; if set, switches to size-based mode"
        )]
        data_size: Option<u32>,
        #[arg(
            long = "use-bytes",
            default_value_t = false,
            help = "Report speed in bytes/sec instead of bits/sec (default: false)"
        )]
        use_bytes: bool,
    },
    #[command(about = "Show version info (outputs version/build/platform details to stdout)")]
    Version,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum LogLevelArg {
    Debug,
    Info,
    Warn,
    Error,
    None,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum LogFormatArg {
    Console,
    Json,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    if let Err(err) = init_logger(cli.log_level, cli.log_format) {
        eprintln!("failed to initialize logger: {err}");
        std::process::exit(1);
    }

    let result = match cli.command {
        Some(Commands::Server) => cmd::server::run_server(cli.config).await,
        Some(Commands::Client) | None => cmd::client::run_client(cli.config).await,
        Some(Commands::Ping { addr }) => cmd::client::run_ping(cli.config, addr).await,
        Some(Commands::Speedtest {
            skip_download,
            skip_upload,
            duration_secs,
            data_size,
            use_bytes,
        }) => {
            cmd::client::run_speedtest(
                cli.config,
                SpeedtestArgs {
                    skip_download,
                    skip_upload,
                    duration: Duration::from_secs(duration_secs),
                    data_size,
                    use_bytes,
                },
            )
            .await
        }
        Some(Commands::Version) => {
            println!("{}", version_output());
            Ok(())
        }
    };

    if let Err(err) = result {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn init_logger(level: LogLevelArg, format: LogFormatArg) -> io::Result<()> {
    if matches!(level, LogLevelArg::None) {
        return Ok(());
    }
    let level = match level {
        LogLevelArg::Debug => "debug",
        LogLevelArg::Info => "info",
        LogLevelArg::Warn => "warn",
        LogLevelArg::Error => "error",
        LogLevelArg::None => unreachable!(),
    };
    let filter = EnvFilter::try_new(level)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;

    match format {
        LogFormatArg::Console => {
            tracing_subscriber::registry()
                .with(filter)
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_writer(std::io::stderr)
                        .with_target(false)
                        .event_format(ConsoleLogFormatter),
                )
                .init();
        }
        LogFormatArg::Json => {
            tracing_subscriber::registry()
                .with(filter)
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_writer(std::io::stderr)
                        .with_target(false)
                        .event_format(JsonLogFormatter),
                )
                .init();
        }
    }
    Ok(())
}

#[derive(Default)]
struct FieldCollector {
    fields: JsonMap<String, JsonValue>,
}

impl FieldCollector {
    fn strip_internal_log_fields(&mut self) {
        self.fields.remove("log.file");
        self.fields.remove("log.line");
        self.fields.remove("log.module_path");
        self.fields.remove("log.target");
    }

    fn take_message(&mut self) -> String {
        let msg = self
            .fields
            .remove("message")
            .unwrap_or_else(|| JsonValue::String(String::new()));
        match msg {
            JsonValue::String(s) => s,
            other => other.to_string(),
        }
    }
}

impl Visit for FieldCollector {
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.fields
            .insert(field.name().to_string(), JsonValue::from(value));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.fields
            .insert(field.name().to_string(), JsonValue::from(value));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.fields
            .insert(field.name().to_string(), JsonValue::from(value));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.fields
            .insert(field.name().to_string(), JsonValue::from(value));
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.fields
            .insert(field.name().to_string(), JsonValue::from(value.to_string()));
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.fields.insert(
            field.name().to_string(),
            JsonValue::from(format!("{value:?}")),
        );
    }
}

struct ConsoleLogFormatter;

impl<S, N> FormatEvent<S, N> for ConsoleLogFormatter
where
    S: Subscriber + for<'span> LookupSpan<'span>,
    N: for<'writer> FormatFields<'writer> + 'static,
{
    fn format_event(
        &self,
        _ctx: &tracing_subscriber::fmt::FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> std::fmt::Result {
        let mut collector = FieldCollector::default();
        event.record(&mut collector);
        collector.strip_internal_log_fields();
        let msg = collector.take_message();

        let time = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| "unknown".to_string());
        let level = color_level(event.metadata().level());

        if collector.fields.is_empty() {
            writeln!(writer, "{time}\t{level}\t{msg}")
        } else {
            let extra = JsonValue::Object(collector.fields).to_string();
            writeln!(writer, "{time}\t{level}\t{msg}\t{extra}")
        }
    }
}

struct JsonLogFormatter;

impl<S, N> FormatEvent<S, N> for JsonLogFormatter
where
    S: Subscriber + for<'span> LookupSpan<'span>,
    N: for<'writer> FormatFields<'writer> + 'static,
{
    fn format_event(
        &self,
        _ctx: &tracing_subscriber::fmt::FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> std::fmt::Result {
        let mut collector = FieldCollector::default();
        event.record(&mut collector);
        collector.strip_internal_log_fields();
        let msg = collector.take_message();

        let mut obj = JsonMap::new();
        obj.insert("time".to_string(), JsonValue::from(epoch_millis_now()));
        obj.insert(
            "level".to_string(),
            JsonValue::from(level_lower(event.metadata().level())),
        );
        obj.insert("msg".to_string(), JsonValue::from(msg));
        obj.extend(collector.fields);
        writeln!(writer, "{}", JsonValue::Object(obj))
    }
}

#[inline]
fn epoch_millis_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

#[inline]
fn level_lower(level: &Level) -> &'static str {
    match *level {
        Level::TRACE => "trace",
        Level::DEBUG => "debug",
        Level::INFO => "info",
        Level::WARN => "warn",
        Level::ERROR => "error",
    }
}

#[inline]
fn color_level(level: &Level) -> String {
    let text = match *level {
        Level::TRACE => "TRACE",
        Level::DEBUG => "DEBUG",
        Level::INFO => "INFO",
        Level::WARN => "WARN",
        Level::ERROR => "ERROR",
    };
    let color = match *level {
        Level::TRACE => "\x1b[35m",
        Level::DEBUG => "\x1b[36m",
        Level::INFO => "\x1b[32m",
        Level::WARN => "\x1b[33m",
        Level::ERROR => "\x1b[31m",
    };
    format!("{color}{text}\x1b[0m")
}

fn version_output() -> String {
    let build_type = env!("BUILD_PROFILE");
    let version = format!("v{}", env!("CARGO_PKG_VERSION"));
    let build_date = env!("BUILD_TIMESTAMP").trim();
    let platform = normalize_platform(env!("BUILD_PLATFORM"));
    let architecture = normalize_arch(env!("BUILD_ARCH"));
    let target_cpu = env!("BUILD_TARGET_CPU");
    let libraries = format!(
        "quinn = \"{}\", h3-quinn = \"{}\", h3 = \"{}\", tokio = \"{}\"",
        env!("BUILD_LIB_QUINN"),
        env!("BUILD_LIB_H3_QUINN"),
        env!("BUILD_LIB_H3"),
        env!("BUILD_LIB_TOKIO"),
    );

    format!(
        "Version:\t{}\nBuildDate:\t{}\nBuildType:\t{}\nToolchain:\t{}\nCommitHash:\t{}\nPlatform:\t{}\nArchitecture:\t{}\nTargetCPU:\t{}\nLibraries:\t{}",
        version,
        build_date,
        build_type,
        env!("BUILD_TOOLCHAIN"),
        env!("BUILD_GIT_HASH"),
        platform,
        architecture,
        target_cpu,
        libraries,
    )
}

fn normalize_platform(platform: &str) -> &str {
    match platform {
        "macos" => "darwin",
        other => other,
    }
}

fn normalize_arch(arch: &str) -> &str {
    arch
}
