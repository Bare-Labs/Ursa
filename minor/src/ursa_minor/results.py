"""
Ursa Minor — Scan Result Persistence & Export
==============================================
Auto-saves scan results as JSON. Exports to JSON, CSV, or HTML.

Results are stored in ~/.ursa/results/ (configurable via ursa.yaml).
"""

import csv
import io
import json
import os
import time
from datetime import datetime
from pathlib import Path


DEFAULT_RESULTS_DIR = Path.home() / ".ursa" / "results"


def _get_results_dir() -> Path:
    """Get results directory, creating it if needed."""
    try:
        from major.config import get_config
        cfg = get_config()
        results_dir = Path(cfg.get("minor.results_dir", str(DEFAULT_RESULTS_DIR)))
    except ImportError:
        results_dir = DEFAULT_RESULTS_DIR

    # Expand ~ in path
    results_dir = results_dir.expanduser()
    results_dir.mkdir(parents=True, exist_ok=True)
    return results_dir


def save_result(tool_name: str, result_data: str, metadata: dict | None = None) -> str:
    """Save a scan result to disk.

    Args:
        tool_name: Name of the MCP tool (e.g. "scan_ports")
        result_data: The raw text output from the tool
        metadata: Optional dict with extra info (target, args, etc.)

    Returns:
        Result ID (filename stem) for later retrieval.
    """
    results_dir = _get_results_dir()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    result_id = f"{tool_name}_{ts}"
    filepath = results_dir / f"{result_id}.json"

    record = {
        "id": result_id,
        "tool": tool_name,
        "timestamp": time.time(),
        "timestamp_str": datetime.now().isoformat(),
        "metadata": metadata or {},
        "result": result_data,
    }

    with open(filepath, "w") as f:
        json.dump(record, f, indent=2)

    return result_id


def list_results(tool_filter: str | None = None, limit: int = 50) -> list[dict]:
    """List saved scan results.

    Args:
        tool_filter: Filter by tool name (substring match).
        limit: Max results to return.

    Returns:
        List of result metadata dicts (without full result data).
    """
    results_dir = _get_results_dir()
    results = []

    json_files = sorted(results_dir.glob("*.json"), key=os.path.getmtime, reverse=True)

    for filepath in json_files[:limit * 2]:  # read extra in case of filter
        try:
            with open(filepath) as f:
                record = json.load(f)
            if tool_filter and tool_filter.lower() not in record.get("tool", "").lower():
                continue
            results.append({
                "id": record.get("id", filepath.stem),
                "tool": record.get("tool", "unknown"),
                "timestamp": record.get("timestamp_str", ""),
                "metadata": record.get("metadata", {}),
            })
            if len(results) >= limit:
                break
        except (json.JSONDecodeError, KeyError):
            continue

    return results


def get_result(result_id: str) -> dict | None:
    """Retrieve a specific scan result by ID.

    Returns:
        Full result record including data, or None if not found.
    """
    results_dir = _get_results_dir()
    filepath = results_dir / f"{result_id}.json"

    if not filepath.exists():
        return None

    with open(filepath) as f:
        return json.load(f)


def export_json(result_id: str) -> str:
    """Export a result as formatted JSON."""
    record = get_result(result_id)
    if not record:
        return f"Result {result_id} not found."
    return json.dumps(record, indent=2)


def export_csv(result_id: str) -> str:
    """Export a result as CSV. Best-effort tabular conversion."""
    record = get_result(result_id)
    if not record:
        return f"Result {result_id} not found."

    result_text = record.get("result", "")
    output = io.StringIO()
    writer = csv.writer(output)

    # Write header row with metadata
    writer.writerow(["tool", "timestamp", "result_id"])
    writer.writerow([record.get("tool", ""), record.get("timestamp_str", ""), result_id])
    writer.writerow([])

    # Try to parse result as structured data, else dump as text rows
    lines = result_text.strip().split("\n")
    for line in lines:
        writer.writerow([line])

    return output.getvalue()


def export_html(result_id: str) -> str:
    """Export a result as a self-contained HTML report."""
    record = get_result(result_id)
    if not record:
        return f"Result {result_id} not found."

    tool = record.get("tool", "unknown")
    timestamp = record.get("timestamp_str", "")
    metadata = record.get("metadata", {})
    result_text = record.get("result", "")

    # Escape HTML
    import html
    result_html = html.escape(result_text)

    meta_rows = ""
    for k, v in metadata.items():
        meta_rows += f"<tr><td>{html.escape(str(k))}</td><td>{html.escape(str(v))}</td></tr>\n"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Ursa Minor — {html.escape(tool)} Report</title>
<style>
  :root {{
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #e6edf3; --text-muted: #8b949e; --accent: #58a6ff;
    --green: #3fb950; --yellow: #d29922; --red: #f85149;
  }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    background: var(--bg); color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
    padding: 2rem; line-height: 1.5;
  }}
  h1 {{ color: var(--accent); margin-bottom: 0.5rem; font-size: 1.5rem; }}
  .meta {{ color: var(--text-muted); margin-bottom: 1.5rem; font-size: 0.9rem; }}
  table {{
    width: 100%; border-collapse: collapse; margin-bottom: 1.5rem;
    background: var(--surface); border-radius: 6px; overflow: hidden;
  }}
  th, td {{
    padding: 0.6rem 1rem; text-align: left; border-bottom: 1px solid var(--border);
  }}
  th {{ background: var(--border); color: var(--text-muted); font-weight: 600; font-size: 0.85rem; }}
  pre {{
    background: var(--surface); border: 1px solid var(--border); border-radius: 6px;
    padding: 1rem; overflow-x: auto; font-family: 'SF Mono', Monaco, monospace;
    font-size: 0.85rem; line-height: 1.6; white-space: pre-wrap; word-wrap: break-word;
  }}
  .footer {{ color: var(--text-muted); font-size: 0.8rem; margin-top: 2rem; text-align: center; }}
</style>
</head>
<body>
  <h1>Ursa Minor — {html.escape(tool)}</h1>
  <p class="meta">Generated: {html.escape(timestamp)} | ID: {html.escape(result_id)}</p>

  {"<h2 style='font-size:1.1rem;margin-bottom:0.5rem;'>Metadata</h2><table><tr><th>Key</th><th>Value</th></tr>" + meta_rows + "</table>" if meta_rows else ""}

  <h2 style="font-size:1.1rem;margin-bottom:0.5rem;">Output</h2>
  <pre>{result_html}</pre>

  <p class="footer">Ursa Minor Recon Toolkit — Bare Labs</p>
</body>
</html>"""
