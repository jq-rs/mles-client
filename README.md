# Mles Client

[![Crates.io](https://img.shields.io/crates/v/mles-client.svg)](https://crates.io/crates/mles-client)
[![License: MPL 2.0](https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg)](https://opensource.org/licenses/MPL-2.0)

A prototype implementation of the [Mles v2 protocol](https://github.com/jq-rs/mles-rs). This client serves as an example implementation and proof-of-concept for the protocol, demonstrating WebSocket-based messaging with end-to-end encryption using XChaCha20-Poly1305.

**⚠️ Important Note:** This is a prototype implementation intended for demonstration and learning purposes. It should not be used in production environments or for any critical applications.

## About Mles Protocol

This client implements the [Mles v2 protocol](https://github.com/jq-rs/mles-rs) (Modern Lightweight channEl Service), a client-server data distribution protocol designed for lightweight and reliable distributed publish-subscribe data service. For production implementations and more detailed protocol specifications, please visit https://mles.io.

## Client Features

- End-to-end encryption using XChaCha20-Poly1305
- Real-time messaging with colorized usernames
- Message deduplication
- Proxy mode for connecting two Mles servers
- Local timestamp conversion
- Secure key derivation using Scrypt and Blake2b
- Support for shared keys via environment variables

## Usage

### Direct Mode

```bash
# Connect to default server (wss://mles.io)
mles-client

# Connect to specific server
mles-client -s wss://example.com

# Connect with predefined channel and user ID
mles-client -c mychannel -u myuser
```

### Proxy Mode

```bash
# Connect two servers
mles-client -s wss://server1.com --proxy-server wss://server2.com -c channel -u proxy-user
```

## Command Line Arguments

- `-s, --server`: WebSocket server URL (default: wss://mles.io)
- `-c, --channel`: Channel name
- `-u, --uid`: User ID
- `--proxy-server`: Second server URL for proxy mode

## Environment Variables

- `MLES_KEY`: Optional shared key for authentication

## Implementation Notes

This implementation includes:
- Basic protocol compliance with Mles v2
- Example encryption using XChaCha20-Poly1305
- Prototype proxy functionality
- Simple terminal-based UI

While functional, this implementation prioritizes demonstrating protocol concepts over production-ready features and security hardening.

## Features in Detail

### Security
- Secure message encryption using XChaCha20-Poly1305
- Key derivation using Scrypt with Blake2b hash
- Authentication using SipHash

### UI Features
- Colorized usernames for better readability
- Local time conversion for timestamps
- Dynamic terminal resizing support
- Message deduplication to prevent doubles

### Proxy Mode
- Bidirectional message forwarding between servers
- Live statistics showing message counts
- Auto-reconnect capabilities
- Clean shutdown handling

## Building

```bash
cargo build --release
```

## Dependencies

- tokio: Async runtime
- tokio-tungstenite: WebSocket implementation
- chacha20poly1305: Encryption
- blake2: Hashing
- scrypt: Key derivation
- clap: Command line argument parsing
- crossterm: Terminal UI
- serde_json: JSON handling

## Acknowledgments

- [Zed](https://zed.dev) - An outstanding text processor that greatly facilitated the development of this project
- [Claude 3.5 Sonnet](https://www.anthropic.com/claude) - AI assistant that provided valuable help with code suggestions and documentation

## License

This project is licensed under the Mozilla Public License Version 2.0 - see the [LICENSE](LICENSE) file for details.
