//! A `log` backend writing to a file: an injected DLL has no console.

use std::io::Write;
use std::sync::Mutex;
use std::time::Instant;

struct FileLogger {
    file: Mutex<std::fs::File>,
    start: Instant,
    level: log::LevelFilter,
}

impl log::Log for FileLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let t = self.start.elapsed();
        let mut f = self.file.lock().unwrap_or_else(|e| e.into_inner());
        let _ = writeln!(
            f,
            "{:>5}.{:03} {:<5} {}: {}",
            t.as_secs(),
            t.subsec_millis(),
            record.level(),
            record.target(),
            record.args()
        );
        let _ = f.flush();
    }

    fn flush(&self) {}
}

/// Logs to `path` (truncated) at `level` and above. Also routes panics
/// there. Returns an error if the file cannot be created or a logger is
/// already installed.
pub fn log_to_file(path: &std::path::Path, level: log::LevelFilter) -> Result<(), Box<dyn std::error::Error>> {
    let file = std::fs::File::create(path)?;
    log::set_boxed_logger(Box::new(FileLogger { file: Mutex::new(file), start: Instant::now(), level }))?;
    log::set_max_level(level);
    std::panic::set_hook(Box::new(|info| log::error!("{info}")));
    Ok(())
}
