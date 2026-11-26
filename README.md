# nbdwire

An async server for the [NBD protocol](https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md)
(Network Block Device), in Rust on tokio.

- Serves on any `AsyncRead + AsyncWrite` stream: a Unix socket, TCP, or
  anything else that carries bytes.
- Speaks TLS through rustls (`NBD_OPT_STARTTLS`). With TLS configured, every
  client must use it; your `rustls::ServerConfig` decides whether clients need
  certificates.
- Exports are `Backend`s, a small trait. `FileBackend` serves a regular file
  and reports its holes, so `nbdcopy` and `qemu-img` copy sparse images
  without reading or writing the holes.

```rust,no_run
use std::sync::Arc;

use nbdwire::{Access, FileBackend, Server};

# async fn run() -> std::io::Result<()> {
let disk = FileBackend::open("disk.img", Access::ReadOnly)?;
let server = Arc::new(Server::new().export("disk", Arc::new(disk)));
let listener = tokio::net::UnixListener::bind("/run/disk.sock")?;
loop {
    let (stream, _) = listener.accept().await?;
    let server = server.clone();
    tokio::spawn(async move { server.serve(stream).await });
}
# }
```

```console
$ nbdinfo --map 'nbd+unix:///disk?socket=/run/disk.sock'
         0     1048576    0  data
   1048576     3145728    3  hole,zero
```

## Protocol support

| | |
|---|---|
| Handshake | fixed newstyle, `NO_ZEROES` |
| Options | `EXPORT_NAME`, `ABORT`, `LIST`, `STARTTLS`, `INFO` and `GO` (with block sizes), `STRUCTURED_REPLY`, `LIST_META_CONTEXT`, `SET_META_CONTEXT` |
| Commands | `READ` (`DF`), `WRITE`, `FLUSH`, `TRIM`, `WRITE_ZEROES` (`NO_HOLE`), `BLOCK_STATUS` (`REQ_ONE`), `DISC`, with `FUA` on writes |
| Metadata contexts | `base:allocation` |

Not yet: extended headers (64-bit lengths), `CACHE`, `RESIZE`, `FAST_ZERO`,
and more than one request in flight per connection. Exports allow several
connections at once (`NBD_FLAG_CAN_MULTI_CONN`), which clients such as
`nbdcopy` use to work in parallel.

## Tests

`cargo test` runs the server against clients it shares no code with: libnbd's
`nbdinfo` and `nbdcopy`, and QEMU's `qemu-img` and `qemu-io`. Install them
first; on Debian and Ubuntu that is `apt install libnbd-bin qemu-utils`.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT), at your option.
