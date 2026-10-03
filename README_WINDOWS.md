# PRISM on Windows 11

PRISM includes a native Tkinter desktop interface, so the Windows GUI does not require a separate GUI framework.

## Run from source

Install Python 3.11+ from python.org and make sure `py` is available:

```powershell
py -m pip install -r requirements.txt
py -m prism
```

Or double-click `run_prism.bat`.

Put your API keys in `.env` next to the project:

```env
VIRUSTOTAL_API_KEY=...
URLSCAN_API_KEY=...
ABUSEIPDB_API_KEY=...
URLQUERY_API_KEY=...
```

## Build a Windows executable

On Windows 11:

```powershell
build_windows.bat
```

The executable is created at:

```text
dist\PRISM.exe
```

Copy/edit `dist\.env` with your provider keys. The application will read `.env` from the executable directory.

## CLI is still available

```powershell
py -m prism.cli lookup google.com
py -m prism.cli lookup 8.8.8.8 --json
```

The GUI runs investigations in a background thread so URLQuery submissions/polling do not freeze the window.

## What the desktop window provides

- Polished light/dark Windows-friendly interface with a matching tab-bar/ttk theme
- Single IOC input field
- Automatic IOC type detection
- Background provider execution so the UI stays responsive
- Stop button to cancel the current investigation from the UI and immediately search another IOC
- Results from an old/stopped search are ignored so they cannot overwrite a newer search
- Separate result cards for VirusTotal, URLScan, URLQuery and AbuseIPDB
- Provider status and errors
- Copy complete investigation JSON to clipboard
- Enter = investigate
- Escape = stop while investigating, otherwise clear
- Footer attribution: Created by Sahil

## Windows 11 notes

The GUI uses Python's built-in Tkinter toolkit, so there is no Electron runtime or browser wrapper. This keeps the application lightweight and avoids Linux-only dependencies.


### Live parallel provider results

PRISM runs applicable providers concurrently. The desktop UI renders each provider result immediately when that provider finishes; it does not wait for slower providers such as URLQuery before showing faster results. URLQuery sandbox submissions are polled for up to 180 seconds by default. If the scan is still processing after that, PRISM marks it as `PROCESSING` rather than incorrectly showing `SUCCESS`. Configure `PRISM_URLQUERY_POLL_TIMEOUT` in `.env` when a longer wait is desired.

## Live provider progress

The Windows GUI runs applicable providers in parallel. Each provider gets a live skeleton card immediately after an investigation starts. The skeleton animates while that provider is working and is replaced in-place with the provider's result as soon as it finishes. A slow URLQuery sandbox scan therefore never blocks faster providers such as VirusTotal or URLScan from displaying their results.

The toolbar also shows `completed/total` provider progress while the investigation is running.
