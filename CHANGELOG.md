# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/); before 1.0.0 a minor version may change
the wire protocol or module parameters.

## [0.1.0] - 2026-10-02

First release.

### Added
- Virtual fbdev framebuffer (16 bpp RGB565 or 32 bpp XRGB8888, up to 8192x8192) with
  deferred I/O and per-row damage tracking for `write()`, `mmap()` and fbcon drawing.
- In-kernel HTTP/1.1 and WebSocket (RFC 6455) server; one thread per connection.
- Pixel messages carry only changed rows and are LZ4-compressed when that is smaller.
- Web UI embedded in the module: live view, scaling, pause, screenshot, recording,
  command palette, statistics (rate, round-trip time, compression ratio), light and
  dark themes, phone layout.
- Optional keyboard input through a virtual input device (`keyboard=1`), with
  layout-independent typing, macOS Cmd/Option/Caps Lock handling, clipboard typing,
  a Ctrl+Alt+Del / console-switch menu and on-screen keyboard support.
- Access control: loopback-only by default, mandatory token for other addresses,
  constant-time token check, `Origin` check, request size and time limits, connection
  limit.
- Tests: QEMU end-to-end suite (`test/e2e.py`), real-browser checks
  (`test/browser.py`, `test/browser_keys.py`).

### Known limitations
- No mouse input, no TLS, IPv4 and the initial network namespace only.
- Tested on Linux 6.12 (arm64, QEMU); compiles against 6.17 and 6.19. x86 has not been
  built or run.
- The KASAN and lockdep run covers the code up to the LZ4 change; the `sk_data_ready`
  wake-up and `ping` were tested on a non-debug kernel only. No kmemleak run.

[0.1.0]: https://github.com/DatanoiseTV/netfb/releases/tag/v0.1.0
