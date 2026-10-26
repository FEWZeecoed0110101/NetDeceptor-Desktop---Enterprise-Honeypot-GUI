<p align="center">
  <img src="assets/logo.png" alt="NetDeceptor Desktop Logo" width="180">
</p>

<h1 align="center">NetDeceptor Desktop</h1>
<p align="center"><b>Enterprise Honeypot & Threat Inspector</b></p>
# NetDeceptor

NetDeceptor can run either as a desktop dashboard or as a foreground headless
honeypot process. The headless mode does not require PyQt6.

## Project layout

- `app.py` is the backward-compatible launcher.
- `netdeceptor/config.py` loads and validates application settings.
- `netdeceptor/database.py` stores events and verifies the hash chain.
- `netdeceptor/services.py` contains classification, notifications, rate limiting,
  geolocation, and firewall-defense helpers.
- `netdeceptor/engine.py` runs the asyncio honeypot and traffic simulator.
- `netdeceptor/reports.py` exports CSV, JSON, and optional PDF reports.
- `netdeceptor/dashboard.py` contains the desktop UI and its Python/JavaScript bridge.
- `netdeceptor/cli.py` selects desktop or headless startup.
- `netdeceptor/compat.py` provides shared paths, standard-library imports, and
  optional PyQt compatibility for headless installs.

## Headless mode

Run from the project directory:

```powershell
python app.py --headless
```

The process listens on the enabled ports in `netdeceptor_config.json`, writes
events to `netdeceptor.db`, and exits cleanly when it receives Ctrl+C or a
termination signal. Paths can be overridden:

```powershell
python app.py --headless --config C:\NetDeceptor\config.json --db C:\NetDeceptor\events.db
```

On Linux, run the same foreground command under a supervisor such as systemd.
On Windows, use an approved service wrapper or supervisor; this script does not
install itself as a Windows Service.

The default bind address is `127.0.0.1`. Only change it to a network interface
address in an isolated, authorized test environment, and restrict inbound and
outbound traffic with host and network firewalls. Ports below 1024 may require
elevated privileges or may already be in use. Firewall blocking remains in
dry-run mode by default.

Use `python app.py --help` to see command-line options. Omitting `--headless`
continues to launch the desktop application.
