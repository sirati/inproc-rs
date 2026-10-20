//! A `log` backend writing to a file: an injected DLL has no console.
//!
//! Any thread, the game's included, only formats its line and sends it;
//! one writer thread (`civ3r-log`) owns the file. Nobody waits for a file
//! write or for another thread's logging.

use std::io::Write;
use std::time::{Duration, Instant};

enum Line {
    Text(String),
    /// Written everything sent before: tell the sender.
    Flush(std::sync::mpsc::Sender<()>),
}

struct FileLogger {
    lines: tokio::sync::mpsc::UnboundedSender<Line>,
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
        let line = format!(
            "{:>5}.{:03} {:<5} {}: {}\n",
            t.as_secs(),
            t.subsec_millis(),
            record.level(),
            record.target(),
            record.args()
        );
        let _ = self.lines.send(Line::Text(line));
    }

    /// Waits (at most 200 ms) for the writer: only the panic hook calls
    /// it, so that the panic's line reaches the file before the process ends.
    fn flush(&self) {
        let (done, written) = std::sync::mpsc::channel();
        if self.lines.send(Line::Flush(done)).is_ok() {
            let _ = written.recv_timeout(Duration::from_millis(200));
        }
    }
}

/// The writer polls instead of parking in a receive: a sender (the game's
/// thread, logging from a hook) then never has a parked receiver to wake,
/// and its send stays a lock-free push.
const POLL: Duration = Duration::from_millis(10);

fn write_lines(mut file: std::fs::File, mut lines: tokio::sync::mpsc::UnboundedReceiver<Line>) {
    use tokio::sync::mpsc::error::TryRecvError;
    loop {
        match lines.try_recv() {
            Ok(Line::Text(text)) => {
                let _ = file.write_all(text.as_bytes());
                // Each line reaches the file at once: a crash keeps the log.
                let _ = file.flush();
            }
            Ok(Line::Flush(done)) => {
                let _ = done.send(());
            }
            Err(TryRecvError::Empty) => std::thread::sleep(POLL),
            Err(TryRecvError::Disconnected) => return,
        }
    }
}

/// Logs to `path` (truncated) at `level` and above. Also routes panics
/// there. Returns an error if the file cannot be created or a logger is
/// already installed.
pub fn log_to_file(path: &std::path::Path, level: log::LevelFilter) -> Result<(), Box<dyn std::error::Error>> {
    let file = std::fs::File::create(path)?;
    let (lines, receive) = tokio::sync::mpsc::unbounded_channel();
    log::set_boxed_logger(Box::new(FileLogger { lines, start: Instant::now(), level }))?;
    std::thread::Builder::new().name("civ3r-log".into()).spawn(move || write_lines(file, receive))?;
    log::set_max_level(level);
    std::panic::set_hook(Box::new(|info| {
        log::error!("{info}");
        log::logger().flush();
    }));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_from_many_threads_reach_the_file_in_each_threads_order() {
        let path = std::env::temp_dir().join(format!("inproc-log-test-{}.log", std::process::id()));
        let file = std::fs::File::create(&path).unwrap();
        let (lines, receive) = tokio::sync::mpsc::unbounded_channel();
        let logger = FileLogger { lines, start: Instant::now(), level: log::LevelFilter::Debug };
        let writer = std::thread::spawn(move || write_lines(file, receive));
        std::thread::scope(|s| {
            for t in 0..4 {
                let logger = &logger;
                s.spawn(move || {
                    for i in 0..100 {
                        log::Log::log(logger, &log::Record::builder().level(log::Level::Info).target("t").args(format_args!("{t} {i}")).build());
                    }
                });
            }
        });
        log::Log::flush(&logger);
        let text = std::fs::read_to_string(&path).unwrap();
        let mut last = [-1i32; 4];
        for line in text.lines() {
            let mut words = line.rsplit(' ');
            let i: i32 = words.next().unwrap().parse().unwrap();
            let t: usize = words.next().unwrap().parse().unwrap();
            assert!(i > last[t]);
            last[t] = i;
        }
        assert_eq!(last, [99; 4], "flush waits for every line sent before it");
        drop(logger);
        writer.join().unwrap();
        let _ = std::fs::remove_file(path);
    }
}
