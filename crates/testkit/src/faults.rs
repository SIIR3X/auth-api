//! Fault injection between the application and a dependency.
//!
//! A [`FaultProxy`] listens on loopback and relays every connection to the
//! real PostgreSQL, Redis or NATS. Switching its [`Fault`] affects open
//! connections immediately, which is what a pool sees during an incident.

use std::{net::SocketAddr, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        TcpListener, TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::watch,
    task::JoinHandle,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// Relay traffic untouched.
    None,
    /// Delay every chunk of data, in both directions.
    Latency(Duration),
    /// Accept connections and hold every byte: the dependency hangs.
    Blackhole,
    /// Close open connections and every new one: the dependency is down.
    Refuse,
}

pub struct FaultProxy {
    addr: SocketAddr,
    fault: watch::Sender<Fault>,
    accept: JoinHandle<()>,
}

impl FaultProxy {
    /// Relay to `upstream` (`host:port`).
    pub async fn start(upstream: impl Into<String>) -> Self {
        let upstream = upstream.into();
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fault proxy");
        let addr = listener.local_addr().expect("fault proxy address");
        let (fault, watcher) = watch::channel(Fault::None);
        let accept = tokio::spawn(accept_loop(listener, upstream, watcher));
        Self {
            addr,
            fault,
            accept,
        }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn set(&self, fault: Fault) {
        self.fault.send_replace(fault);
    }

    pub fn current(&self) -> Fault {
        *self.fault.borrow()
    }
}

impl Drop for FaultProxy {
    fn drop(&mut self) {
        self.accept.abort();
        // Open relays notice the closed channel and shut their connections.
    }
}

async fn accept_loop(listener: TcpListener, upstream: String, watcher: watch::Receiver<Fault>) {
    loop {
        let Ok((client, _)) = listener.accept().await else {
            continue;
        };
        if *watcher.borrow() == Fault::Refuse {
            drop(client);
            continue;
        }
        tokio::spawn(relay(client, upstream.clone(), watcher.clone()));
    }
}

async fn relay(client: TcpStream, upstream: String, watcher: watch::Receiver<Fault>) {
    let Ok(server) = TcpStream::connect(&upstream).await else {
        return;
    };
    let _ = client.set_nodelay(true);
    let _ = server.set_nodelay(true);
    let (client_read, client_write) = client.into_split();
    let (server_read, server_write) = server.into_split();

    tokio::select! {
        _ = pump(client_read, server_write, watcher.clone()) => {}
        _ = pump(server_read, client_write, watcher.clone()) => {}
        _ = refused(watcher) => {}
    }
}

async fn pump(
    mut from: OwnedReadHalf,
    mut to: OwnedWriteHalf,
    mut watcher: watch::Receiver<Fault>,
) -> std::io::Result<()> {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = from.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        loop {
            let fault = *watcher.borrow_and_update();
            match fault {
                Fault::Blackhole => {
                    if watcher.changed().await.is_err() {
                        return Ok(());
                    }
                }
                Fault::Latency(delay) => {
                    tokio::time::sleep(delay).await;
                    break;
                }
                Fault::None | Fault::Refuse => break,
            }
        }
        to.write_all(&buf[..n]).await?;
    }
}

/// Resolves once the proxy refuses traffic or is dropped.
async fn refused(mut watcher: watch::Receiver<Fault>) {
    loop {
        if *watcher.borrow_and_update() == Fault::Refuse {
            return;
        }
        if watcher.changed().await.is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn echo_server() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    while let Ok(n) = socket.read(&mut buf).await {
                        if n == 0 || socket.write_all(&buf[..n]).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        addr
    }

    async fn round_trip(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
        stream.write_all(b"ping").await?;
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await?;
        Ok(buf.to_vec())
    }

    #[tokio::test]
    async fn relays_until_told_otherwise() {
        let proxy = FaultProxy::start(echo_server().await.to_string()).await;
        let mut stream = TcpStream::connect(proxy.addr()).await.unwrap();
        assert_eq!(round_trip(&mut stream).await.unwrap(), b"ping");
    }

    #[tokio::test]
    async fn latency_delays_traffic() {
        let proxy = FaultProxy::start(echo_server().await.to_string()).await;
        proxy.set(Fault::Latency(Duration::from_millis(100)));
        let mut stream = TcpStream::connect(proxy.addr()).await.unwrap();

        let started = std::time::Instant::now();
        round_trip(&mut stream).await.unwrap();
        // One delay each way.
        assert!(started.elapsed() >= Duration::from_millis(200));
    }

    #[tokio::test]
    async fn blackhole_hangs_until_lifted() {
        let proxy = FaultProxy::start(echo_server().await.to_string()).await;
        let mut stream = TcpStream::connect(proxy.addr()).await.unwrap();
        proxy.set(Fault::Blackhole);

        let hung = tokio::time::timeout(Duration::from_millis(200), round_trip(&mut stream)).await;
        assert!(hung.is_err(), "traffic passed a blackhole");

        proxy.set(Fault::None);
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
    }

    #[tokio::test]
    async fn refuse_closes_open_and_new_connections() {
        let proxy = FaultProxy::start(echo_server().await.to_string()).await;
        let mut open = TcpStream::connect(proxy.addr()).await.unwrap();
        round_trip(&mut open).await.unwrap();

        proxy.set(Fault::Refuse);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(round_trip(&mut open).await.is_err());

        let mut fresh = TcpStream::connect(proxy.addr()).await.unwrap();
        assert!(round_trip(&mut fresh).await.is_err());
    }
}
