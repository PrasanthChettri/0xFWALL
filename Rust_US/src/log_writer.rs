use std::fmt;
use tokio::fs::OpenOptions;
use std::io;
use std::path::Path;
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Duration;
use tokio::time ; 
use chrono::{DateTime, Local};

use crate::epbf::Event;

pub enum LogLevel {
    Debug,
    Warn,
    Error,
    Info
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
                    LogLevel::Info => "INFO"
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
        let mut ticker = time::interval(Duration::from_secs(3)) ; 

        // This loop automatically ends when ALL LogSenders are dropped
        loop{
            tokio::select!{
                maybe_event = receiver.recv() => {
                    match maybe_event {
                        Some(e) =>  { 
                            let now = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
                            let output = format!("[{}] {}\n", now, &e);
                            writer.write_all(output.as_bytes()).await?;
                        },
                        None => {
                            writer.flush().await ;
                            break;
                        } 
                    }
                } , 
                _ = ticker.tick() => {
                    writer.flush().await ; 
                } , 
            }

        }
        Ok(())
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
