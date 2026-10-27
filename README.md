# rustdesk-tunnel

A minimal, campus-aware **RustDesk protocol tunnel client**: when you are off
campus, it pulls a service port on your lab machine (e.g. an intranet proxy)
to `127.0.0.1` through your own self-hosted RustDesk `hbbs`/`hbbr`. When you
are on campus, it does **nothing** — your device already reaches everything
directly, so the app stays idle.

Multi-platform (Windows / Linux / macOS), Rust core + GUI & tray.

> Not affiliated with or endorsed by RustDesk. "RustDesk" is a trademark of
> its owner; this is an independent client speaking the open protocol of the
> [RustDesk](https://github.com/rustdesk/rustdesk) / [rustdesk-server](https://github.com/rustdesk/rustdesk-server)
> codebases (GPL-3.0 / AGPL-3.0 respectively — hence this project's license).

## Behavior

```
On campus  (probe OK):    app idle. Your programs access campus resources
                          directly; no tunnel, no listener, no VPS traffic.
Off campus (probe fails): app dials hbbs over TCP (PunchHoleRequest), gets the
                          peer's address, falls back to the hbbr relay, does the
                          end-to-end encrypted handshake (server key as trust
                          anchor), logs in with ConnType=PortForward
                          (multiplexed), and serves the remote port on
                          127.0.0.1:<local port>.
```

Path selection is just connectivity: a ~1s TCP probe against a
campus-only-reachable endpoint, re-run in the background and on network
changes. The relay path is end-to-end encrypted; `hbbr` only ever sees
ciphertext. On-campus state involves no tunneling at all.

## Roadmap

- [ ] P0 — Rust core (CLI): rendezvous over TCP → relay → secure handshake →
      port-forward login → multiplexed channels; local listener; auto path
      selection; reconnect.
- [ ] P1 — Tauri v2 shell: window + system tray, config editor, status/path
      indicator, traffic stats (React + shadcn/Tailwind UI).
- [ ] P2 — Release builds for Windows/Linux/macOS via CI.

## Configuration (draft)

```toml
[rustdesk]
server   = "hbbs.example.com:21116"
key      = "<id_ed25519.pub contents>"
device_id = "123456789"        # the machine that runs the service
password  = "<its permanent password>"

[service]                      # what to pull
remote_addr = "127.0.0.1:8443" # as seen from the device above

[local]
listen = "127.0.0.1:17897"     # what your programs use when off campus

[campus]
probe = "10.0.0.1:22"          # reachable only from campus; idle when it is
```

## License

AGPL-3.0 — protocol definitions and the multiplexing/flow-control design are
adapted from the RustDesk codebase (GPL-3.0 client, AGPL-3.0 server); the
GPLv3 permits conveying under AGPL-3.0, which keeps the whole tree consistent.
