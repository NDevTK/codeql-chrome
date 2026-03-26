# CodeQL Chrome

Runtime JavaScript security analysis. Launches Chrome with CDP, captures every script as it executes, and runs CodeQL to find vulnerabilities with full dataflow traces.

Unlike static scanners that analyze source files on disk, this tool captures JavaScript **as the browser sees it** — including dynamically fetched scripts, inline scripts, `eval`'d code, and scripts injected at runtime. Each execution context (page, iframe) gets its own CodeQL database so cross-file analysis is accurate and findings don't cross-contaminate between unrelated pages.

## Quick Start

```bash
pip install PySide6 websocket-client

# GUI — launches Chrome, analyzes as you browse
python main.py

# CLI — analyze specific URLs
python main.py https://example.com

# Spider — crawl and analyze an entire site
python main.py --spider https://example.com
```

CodeQL is downloaded automatically on first run (~620MB).

## How It Works

1. **Chrome launches** with a persistent profile and CDP enabled on port 9222
2. **CDP captures all JavaScript** via `Debugger.scriptParsed` — external files, inline scripts, `eval`'d code, dynamically imported modules
3. **Execution contexts are tracked** via `Runtime.executionContextCreated` — each page and each cross-origin iframe is isolated
4. **Debounce** fires 3 seconds after the last script arrives in a context
5. **CodeQL daemon** (5 parallel workers) creates a database per context, runs 24 client-side security queries
6. **Findings with full traces** are persisted to `findings.json`, source files to `sources/`
7. **System notification** fires when new findings are detected

GUI and CLI share the same Chrome instance, the same findings store, and the same persistent profile. Run the CLI while the GUI is open — findings appear in both.

## CLI

```
python main.py [OPTIONS] URL [URL...]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--spider` | off | Crawl links from each URL using the live DOM |
| `--depth N` | 3 | Spider crawl depth |
| `--max-pages N` | 50 | Spider max pages |
| `--scope` | `same-origin` | `same-origin`, `same-domain`, `prefix`, `regex` |
| `--scope-pattern` | | Pattern for `prefix`/`regex` scope |
| `--wait N` | 5 | Seconds to wait per page for scripts |
| `--output FILE` | | Write merged SARIF to file |
| `--json` | | Print findings as JSON |
| `--clear` | | Clear persisted findings before running |
| `--port N` | 9222 | CDP port |
| `--chrome PATH` | auto | Chrome executable path |
| `--codeql PATH` | auto | CodeQL CLI path |

### Examples

```bash
# Analyze a single page
python main.py https://example.com

# Spider a site
python main.py --spider --max-pages 30 https://example.com

# Output SARIF for CI
python main.py --output results.sarif https://example.com

# Clear old findings and rescan
python main.py --clear --spider https://example.com
```

## GUI

```bash
python main.py
```

On startup the GUI automatically launches Chrome (or connects to an existing instance on port 9222), starts capturing scripts, and loads any persisted findings from previous sessions.

**Toolbar:** Spider | Stop Spider | Clear Findings | Settings

**Panels:**
- **Findings** (left) — sortable, filterable table: severity, rule, message, script URL, page context, file, line
- **Trace** (top right) — dataflow trace from source to sink, click a step to navigate
- **Source** (bottom right) — full JavaScript source with syntax highlighting and line numbers

Browse any page in Chrome — scripts are captured and analyzed automatically. Findings appear as they're found with a system notification.

## Shared State

Everything is shared between GUI and CLI:

| What | Where | Shared how |
|------|-------|------------|
| Chrome instance | Port 9222 | Both connect to the same CDP port |
| Chrome profile | `chrome-profile/` | Persistent — cookies, logins, history survive restarts |
| Findings | `findings.json` | GUI watches for changes, updates live |
| Source files | `sources/{hash}/` | Full JS files kept for any context with findings |
| CodeQL | `codeql/` | Auto-downloaded bundle, shared |

## Execution Context Isolation

Each CodeQL database contains only the scripts from one execution context:

- **Same page**: `app.js` and `lib.js` loaded by the same page share a `window` — analyzed together
- **Cross-origin iframe**: `https://ads.net` in `https://example.com` gets a separate database — no false positives
- **Navigation**: page A → page B creates new contexts — scripts never mix

The isolation key is Chrome's `context.uniqueId` from `Runtime.executionContextCreated`.

## CodeQL

| Detail | Value |
|--------|-------|
| Queries | 24 client-side only (no Node.js server-side rules) |
| Workers | 5 parallel (auto-scaled to CPU cores) |
| Per worker | 4 threads, ~5GB RAM (on 20-core/32GB) |
| Cache | Compiled queries reused across all databases |
| Sources | Full JS files persisted by content hash when findings exist |

Queries cover: DOM XSS, code injection (`eval`), client-side URL redirect, client-side request forgery, `postMessage` issues, prototype pollution, insecure randomness, incomplete sanitization, untrusted script sources.

## Spider

The spider drives Chrome through the live DOM using `Runtime.evaluate` to extract links from rendered `<a>`, `<area>`, and `<form>` elements. It handles SPAs, JS-rendered navigation, and dynamically injected links.

Each page visited triggers the capture → debounce → analysis pipeline automatically.

## Architecture

```
main.py                  Entry point — routes to GUI or CLI
cli.py                   CLI with spider and CodeQL daemon

app/
  cdp_client.py          CDP WebSocket client (context tracking, auto-attach iframes)
  chrome_launcher.py     Chrome lifecycle (launch or reuse existing, persistent profile)
  spider.py              BFS crawler via live DOM
  codeql_daemon.py       Parallel analysis (5-worker thread pool)
  codeql_runner.py       CodeQL subprocess wrapper
  codeql_setup.py        Auto-downloads CodeQL bundle
  config.py              24 client-side queries, path detection
  findings_store.py      Persistent findings (JSON, dedup, SARIF/JSON export)
  sarif_parser.py        SARIF v2.1.0 parser
  script_store.py        Saves captured JS, reverse lookup
  workers.py             Qt thread workers (capture, spider, setup)
  cleanup.py             Startup cleanup of stale temp dirs

gui/
  main_window.py         Main window, auto-analysis, context lifecycle
  toolbar.py             Spider / Stop / Clear / Settings
  findings_panel.py      Findings table
  trace_panel.py         Dataflow trace tree
  source_panel.py        Code editor with JS highlighting
```

## Requirements

- Python 3.11+
- PySide6
- websocket-client
- Chrome (detected automatically)
- CodeQL (downloaded automatically)
