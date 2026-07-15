# gp-client-mac

A native macOS GUI client for GlobalProtect VPN, built on top of [openconnect](https://www.infradead.org/openconnect/) and SwiftUI.

Inspired by [yuezk/GlobalProtect-openconnect](https://github.com/yuezk/GlobalProtect-openconnect) (Linux only). This is an independent, drop-in alternative for Mac users — written in pure Swift, no Tauri / GTK / WebKit dependencies.

## Features

- Native SwiftUI window, looks and feels like a real Mac app
- Username + password authentication (GlobalProtect protocol)
- Self-signed server certificate support with trust-on-first-use
- Password storage in macOS Keychain
- One-time setup of passwordless `sudo` rule — no admin prompts on every connect
- Automatic reconnection state detection across app restarts
- Apple Silicon native (arm64)

## Requirements

- macOS 13 or later
- [Homebrew](https://brew.sh)
- `openconnect` (the app will tell you to install it on first run if missing):
  ```sh
  brew install openconnect
  ```

## Install

1. Download `GlobalProtect.dmg` from the [latest release](../../releases/latest)
2. Open the DMG and drag **GlobalProtect** to **Applications**
3. Launch the app from Spotlight or Launchpad
4. The first time, macOS Gatekeeper will block the app because it is unsigned. Right-click the app → **Open** → confirm. (Only needed once.)
5. The app will offer a **one-time setup** to install a `sudoers` rule. Click *Set Up* and enter your Mac password — this is the last time you'll be asked for it.

## Usage

1. Enter the VPN portal address (e.g. `vpn.example.com`)
2. Click **Connect** — enter your VPN credentials
3. Optionally enable **Remember password in Keychain**
4. Click **Disconnect** when done

If your VPN server uses a self-signed certificate, the app will prompt you to confirm the fingerprint on first connection (SSH-style trust on first use).

## Build from source

```sh
git clone https://github.com/xellDart/gp-client-mac.git
cd gp-client-mac
make build       # compiles GlobalProtect.app into ./build/
make dmg         # creates GlobalProtect.dmg
make install     # installs the app to /Applications
```

Requires Xcode Command Line Tools (`xcode-select --install`).

## How it works

- The Swift app launches `openconnect` via `sudo -n` (no password prompt) thanks to a sudoers drop-in installed on first run
- A pid file at `/tmp/gpclient.pid` tracks the daemon
- A timer monitors the process every 3s using `ps` and updates the UI accordingly
- Disconnect sends `SIGINT` (`pkill -INT -F /tmp/gpclient.pid`) so openconnect runs the vpnc-script cleanup and restores the system DNS and routes; it escalates to `SIGTERM`/`SIGKILL` only if the daemon does not exit
- While connected, the UI shows the IPv4 address assigned by the gateway (read from the `utun` tunnel interface)

The sudoers rules installed by the app are restricted to specific commands:

```
$USER ALL=(root) NOPASSWD: /opt/homebrew/bin/openconnect *
$USER ALL=(root) NOPASSWD: /usr/bin/pkill -INT -F /tmp/gpclient.pid
$USER ALL=(root) NOPASSWD: /usr/bin/pkill -F /tmp/gpclient.pid
$USER ALL=(root) NOPASSWD: /usr/bin/pkill -KILL -F /tmp/gpclient.pid
$USER ALL=(root) NOPASSWD: /usr/bin/pkill -TERM -F /tmp/gpclient.pid
$USER ALL=(root) NOPASSWD: /usr/bin/true gpclient-sudoers-v2
```

The last line is a version marker: running `sudo -n /usr/bin/true gpclient-sudoers-v2` succeeds only when the current rules are installed, which is how the app detects outdated installs and offers to update them (`sudo -l` cannot distinguish passwordless rules from admin-with-password ones).

To uninstall the sudoers rule:
```sh
sudo rm /etc/sudoers.d/gpclient
```

## Limitations

- Only username + password auth is supported. SAML / SSO portals are not yet handled.
- HIP report submission (Host Information Profile) is not implemented. Some corporate gateways may limit access without it.
- Routes are managed by the default vpnc-script shipped with openconnect; some `route: writing to routing socket` warnings on macOS are harmless.

## License

MIT — see [LICENSE](LICENSE).
