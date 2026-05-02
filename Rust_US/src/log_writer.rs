use std::fmt;
use tokio::fs::OpenOptions;
use std::io;
use std::path::Path;
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::epbf::Event;

pub enum LogLevel {
    Debug,
    Warn,
    Error,
    Info,
}

pub enum LogEntry {
    Event(Event),
    Msg(String, LogLevel),
}

pub trait LogWritable: fmt::Display + Send {
    fn to_log_entry(self) -> LogEntry;
}

impl LogWritable for Event {
    fn to_log_entry(self) -> LogEntry {
        LogEntry::Event(self)
    }
}

impl fmt::Display for LogEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LogEntry::Event(event) => write!(f, "[EVENT] {}", event),
            LogEntry::Msg(msg_str, log_level) => {
                let label = match log_level {
                    LogLevel::Debug => "DEBUG",
                    LogLevel::Warn => "WARN",
                    LogLevel::Error => "ERROR",
                    LogLevel::Info => "INFO",
                };
                write!(f, "[{}] {}", label, msg_str)
            }
        }
    }
}

impl LogWritable for String {
    fn to_log_entry(self) -> LogEntry {
        LogEntry::Msg(self, LogLevel::Info)
    }
}

// Only the Sender needs to be cloned! No more Arc<Mutex>.
#[derive(Clone)]
pub struct LogSender {
    sender: mpsc::Sender<LogEntry>,
}

// The Worker stays in main() and handles the actual file writing.
pub struct LogWorker {
    task: JoinHandle<io::Result<()>>,
}

pub fn spawn_logger<P: AsRef<Path>>(path: P, buffer_size: usize) -> (LogSender, LogWorker) {
    let (sender, mut receiver) = mpsc::channel(buffer_size);
    let path = path.as_ref().to_path_buf();

    let task = tokio::spawn(async move {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await?;
        let mut writer = BufWriter::new(file);

        // This loop automatically ends when ALL LogSenders are dropped
        while let Some(event) = receiver.recv().await {
            // Added a newline character here so your logs don't print on a single continuous line
            let output = format!("{}\n", &event);
            writer.write_all(output.as_bytes()).await?;
        }

        writer.flush().await
    });

    (LogSender { sender }, LogWorker { task })
}

impl LogSender {
    pub fn try_write<T: LogWritable>(&self, msg: T) {
        let _ = self.sender.try_send(msg.to_log_entry());
    }

    pub async fn write<T: LogWritable>(&self, msg: T) {
        let _ = self.sender.send(msg.to_log_entry()).await;
    }
}

impl LogWorker {
    pub async fn shutdown(self) -> io::Result<()> {
        match self.task.await {
            Ok(result) => result,
            Err(err) => Err(io::Error::other(err)),
        }
    }
}
