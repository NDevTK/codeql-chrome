# CodeQL Chrome

Runtime JavaScript security analysis. Launches Chrome with CDP, captures every script as it executes, and runs CodeQL to find vulnerabilities with full dataflow traces.

Unlike static scanners that analyze source files on disk, this tool captures JavaScript **as the browser sees it** -- including dynamically fetched scripts, inline scripts, `eval`'d code, and scripts injected at runtime. Each execution context (page, iframe) gets its own CodeQL database so cross-file analysis is accurate and findings don't cross-contaminate between unrelated pages.

## Quick Start

```bash
pip install PySide6 websocket-client

# GUI -- launches Chrome automatically, analyzes as you browse
python main.py

# CLI -- headless analysis of specific URLs
python main.py https://example.com

# Spider -- crawl and analyze an entire site
python main.py --spider https://example.com
```

CodeQL is downloaded automatically on first run (~620MB).

## How It Works

```
Chrome (CDP)          Capture           CodeQL Daemon          Findings
+-----------+     +------------+     +------------------+     +----------+
| Debugger. |---->| Group by   |---->| 5 parallel       |---->| Persist  |
| script    |     | execution  |     | workers          |     | to disk  |
| Parsed    |     | context    |     |                  |     |          |
|           |     |            |     | 1 DB per context |     | Dedup    |
| Runtime.  |     | Debounce   |     | 24 client-side   |     |          |
| execution |     | (3s after  |     | queries only     |     | Notify   |
| Context   |     | last       |     |                  |     |          |
| Created   |     | script)    |     | Full traces      |     | SARIF    |
+-----------+     +------------+     +------------------+     +----------+
```

1. **Chrome launches** with an isolated profile and CDP enabled
2. **CDP captures all JavaScript** via `Debugger.scriptParsed` -- external files, inline scripts, `eval`'d code, dynamically imported modules
3. **Execution contexts are tracked** via `Runtime.executionContextCreated` with Chrome's `uniqueId` -- each page and each cross-origin iframe gets its own context
4. **Scripts are grouped by context** -- only scripts that share a global scope are analyzed together
5. **Debounce timer** fires 3 seconds after the last script arrives in a context
6. **Content hash** of all script sources in the context is checked -- skip if already analyzed
7. **CodeQL daemon** picks up the work -- creates a database, runs 24 client-side security queries, parses SARIF output
8. **Findings with full traces** are persisted to `findings.json` and source files to `sources/`
9. **System notification** fires when new findings are detected

## CLI

```
python main.py [OPTIONS] URL [URL...]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--spider` | off | Crawl links from each URL using the live DOM |
| `--depth N` | 3 | Spider crawl depth |
| `--max-pages N` | 50 | Spider max pages |
| `--scope` | `same-origin` | Spider scope: `same-origin`, `same-domain`, `prefix`, `regex` |
| `--scope-pattern` | | Pattern for `prefix`/`regex` scope |
| `--wait N` | 5 | Seconds to wait per page for scripts to load |
| `--output FILE` | | Write merged SARIF to file |
| `--json` | | Print findings as JSON |
| `--no-headless` | headless | Show the browser window |
| `--clear` | | Clear persisted findings before running |
| `--port N` | 9222 | CDP port |
| `--chrome PATH` | auto | Chrome executable path |
| `--codeql PATH` | auto | CodeQL CLI path |

### Examples

```bash
# Analyze a single page
python main.py https://example.com

# Spider a site, same-origin scope, max 30 pages
python main.py --spider --max-pages 30 https://example.com

# Spider with visible browser
python main.py --spider --no-headless https://example.com

# Output SARIF for CI integration
python main.py --output results.sarif https://example.com

# Clear old findings and rescan
python main.py --clear --spider https://example.com
```

## GUI

```bash
python main.py
```

On startup the GUI:
1. Downloads CodeQL if not present
2. Launches Chrome with an isolated profile
3. Starts capturing scripts automatically
4. Loads any persisted findings from previous sessions

**Toolbar:**
- **Launch Chrome** -- start a new CDP-enabled browser
- **Capture Scripts** -- begin capturing (automatic on startup)
- **Stop Capture** -- pause script capture
- **Spider** -- crawl links from the current page (same-origin, depth 3)
- **Stop Spider** -- halt the crawl
- **Clear Findings** -- wipe all persisted findings and source files
- **Settings** -- configure Chrome/CodeQL paths and CDP port

**Panels:**
- **Findings** (left) -- sortable, filterable table with severity, rule, message, script URL, page context, file, line
- **Trace** (top right) -- dataflow trace from source to sink, click a step to navigate
- **Source** (bottom right) -- full JavaScript source with syntax highlighting, line numbers, highlighted trace lines

Findings persist across sessions in `findings.json`. Source files are kept in `sources/` by content hash.

## Architecture

```
main.py                  Entry point -- routes to GUI or CLI
cli.py                   CLI with spider, daemon, event-driven pipeline

app/
  cdp_client.py          CDP WebSocket client
                         - CDPPageClient: per-target connection
                         - CDPClient: multi-target aggregator
                         - Tracks execution contexts (uniqueId)
                         - Auto-attaches to iframes (Target.setAutoAttach)
                         - navigate() / evaluate() for spider
  chrome_launcher.py     Chrome process management (headless + visible)
  spider.py              BFS crawler using live DOM link extraction
  codeql_daemon.py       Parallel analysis daemon (thread pool)
  codeql_runner.py       CodeQL subprocess wrapper
  codeql_setup.py        Auto-downloads CodeQL bundle from GitHub
  config.py              24 client-side security queries, path detection
  findings_store.py      Persistent findings (JSON on disk, dedup, SARIF export)
  sarif_parser.py        SARIF v2.1.0 parser (Finding, TraceStep)
  script_store.py        Saves captured JS to disk, reverse lookup
  workers.py             Qt thread workers (capture, spider, setup)
  cleanup.py             Startup cleanup of stale temp dirs

gui/
  main_window.py         Main window, auto-analysis pipeline, context lifecycle
  toolbar.py             Action toolbar with state management
  findings_panel.py      Findings table (QTreeView)
  trace_panel.py         Dataflow trace tree (QTreeWidget)
  source_panel.py        Code editor with JS highlighting + line numbers
```

## Execution Context Isolation

Each CodeQL database contains only the scripts from one execution context. This matters because:

- **Same page, same global scope**: `app.js` and `lib.js` loaded by the same page share a `window` object. A taint flow from `lib.js` into `app.js` is real. They belong in the same database.
- **Cross-origin iframe**: An iframe from `https://ads.net` embedded in `https://example.com` has its own `window`. CodeQL can't model cross-frame access, so analyzing them together would produce false positives. They get separate databases.
- **Navigation**: When the user navigates from page A to page B, page A's execution contexts are destroyed and new ones are created. The scripts from page A and page B never mix.

The isolation key is Chrome's `Runtime.executionContextCreated` event with `context.uniqueId` -- globally unique per document lifecycle.

## CodeQL Performance

| Optimization | Impact |
|-------------|--------|
| 24 client-side queries (not 104) | Skips all Node.js server-side rules |
| Parallel daemon (5 workers) | 5 contexts analyzed simultaneously |
| Resources divided per worker | 4 threads + 5GB RAM each (on 20-core/32GB) |
| Content hash dedup | Same script set = skip re-analysis |
| Compiled query cache | Queries compiled once, reused across all databases |
| Source persistence by hash | Full JS files kept only when findings exist |

## Spider

The spider drives Chrome through the live DOM -- not HTML parsing. It uses `Runtime.evaluate` to extract links from rendered `<a>`, `<area>`, and `<form>` elements, so it handles:

- JavaScript-rendered navigation (SPAs, React Router, etc.)
- Links injected by scripts after page load
- `pushState` / `replaceState` URL changes

Each page the spider visits automatically triggers the capture + debounce + analysis pipeline. Findings accumulate in the persistent store.

## Findings Persistence

- `findings.json` -- all findings with full metadata (rule, severity, message, traces, source root, page context)
- `sources/{content_hash}/` -- full JavaScript source files for any context that produced findings
- Findings survive app restarts, Chrome crashes, and browser close
- CLI and GUI share the same store -- run the CLI, see results in the GUI
- User explicitly clears with "Clear Findings" button or `--clear` flag

## Requirements

- Python 3.11+
- PySide6
- websocket-client
- Chrome (detected automatically)
- CodeQL (downloaded automatically, ~620MB)
