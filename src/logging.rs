//! Helps instantiate a root slog logger

use crate::cli::Verbosity;
use slog::Drain;

/// Instantiate a root logger
pub fn root(verbosity: Verbosity) -> slog::Logger {
    let level = match verbosity {
        // log only up to info
        Verbosity::DefaultInfo => slog::Level::Info,
        // log everything; be advised that trace-messages are removed at compile time by default,
        // see https://docs.rs/slog/2.7.0/slog/#notable-details
        // but Debug messages will stay around.
        Verbosity::Debug => slog::Level::Trace,
    };
    lorri_logger(level)
}

/// Logger that can be used in tests
pub fn test_logger() -> slog::Logger {
    lorri_logger(slog::Level::Trace)
}

fn lorri_logger(level: slog::Level) -> slog::Logger {
    let decorator = slog_term::TermDecorator::new().stderr().build();
    let drain = slog_term::FullFormat::new(decorator)
        .build()
        .filter_level(level)
        .fuse();
    // This makes all logging go through a mutex. Should logging ever become a bottleneck, consider
    // using slog_async instead.
    let drain = std::sync::Mutex::new(drain).fuse();
    slog::Logger::root(drain, slog::o!())
}
