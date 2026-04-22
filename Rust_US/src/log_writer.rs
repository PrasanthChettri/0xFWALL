use std::io;
use std::net::Ipv4Addr;
use std::path::Path;

use tokio::fs::OpenOptions;
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::xdp::BlockedIpEvent;

pub struct LogWriter {
    sender: mpsc::Sender<BlockedIpEvent>,
    task: JoinHandle<io::Result<()>>,
}

impl LogWriter {
    pub fn spawn<P: AsRef<Path>>(path: P, buffer_size: usize) -> Self {
        let (sender, mut receiver) = mpsc::channel(buffer_size);
        let path = path.as_ref().to_path_buf();

        let task = tokio::spawn(async move {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .await?;
            let mut writer = BufWriter::new(file);

            while let Some(event) = receiver.recv().await {
                writer.write_all(format_event(&event).as_bytes()).await?;
            }

            writer.flush().await
        });

        Self { sender, task }
    }

    pub fn try_write(&self, event: BlockedIpEvent) -> Result<(), mpsc::error::TrySendError<BlockedIpEvent>> {
        self.sender.try_send(event)
    }

    pub async fn shutdown(self) -> io::Result<()> {
        drop(self.sender);
        match self.task.await {
            Ok(result) => result,
            Err(err) => Err(io::Error::other(err)),
        }
    }
}

fn format_event(event: &BlockedIpEvent) -> String {
    format!(
        "id={} ts_ns={} src_ip={} dst_ip={} src_port={} dst_port={} proto={} reason={}\n",
        event.id,
        event.timestamp_ns,
        Ipv4Addr::from(u32::from_be(event.src_ip)),
        Ipv4Addr::from(u32::from_be(event.dst_ip)),
        event.src_port,
        event.dst_port,
        event.protocol,
        event.reason,
    )
}
