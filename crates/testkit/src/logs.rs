//! Log capture, for asserting what the service writes to its logs.

use std::{
    io,
    sync::{Arc, Mutex},
};

use tracing_subscriber::{EnvFilter, fmt::MakeWriter};

#[derive(Clone, Default)]
pub struct LogCapture {
    buffer: Arc<Mutex<Vec<u8>>>,
}

impl LogCapture {
    /// Record every event `filter` selects (`auth_api=trace,access=info`).
    ///
    /// Installs the process-wide subscriber, so it must run before anything
    /// logs; nextest runs each test in a process of its own.
    pub fn install(filter: &str) -> Self {
        let capture = Self::default();
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::new(filter))
            .with_writer(capture.clone())
            .with_ansi(false)
            .try_init()
            .expect("the log capture must be installed before any other subscriber");
        capture
    }

    pub fn contents(&self) -> String {
        String::from_utf8_lossy(&self.buffer.lock().unwrap()).into_owned()
    }
}

pub struct Writer(Arc<Mutex<Vec<u8>>>);

impl io::Write for Writer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for LogCapture {
    type Writer = Writer;

    fn make_writer(&'a self) -> Self::Writer {
        Writer(self.buffer.clone())
    }
}
