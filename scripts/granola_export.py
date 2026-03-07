#!/usr/bin/env python3
"""
Granola Notes Exporter
Extracts all notes from the Granola app and saves them as text/markdown files.

Usage:
    python granola_export.py                    # Export to ~/granola-notes/
    python granola_export.py --output ~/Notes   # Export to custom folder
    python granola_export.py --format txt       # Save as .txt instead of .md
    python granola_export.py --include-transcript  # Also save full transcripts
"""

import argparse
import json
import logging
import os
import re
import sys
from datetime import datetime
from pathlib import Path

import requests

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    handlers=[logging.StreamHandler()],
)
log = logging.getLogger(__name__)


# ── Auth ──────────────────────────────────────────────────────────────────────
def load_token() -> str:
    """Read the Granola access token from the local credentials file."""
    if sys.platform == "win32":
        creds_path = Path(os.environ["APPDATA"]) / "Granola" / "supabase.json"
    else:
        creds_path = Path.home() / "Library" / "Application Support" / "Granola" / "supabase.json"

    if not creds_path.exists():
        log.error(f"Credentials file not found: {creds_path}")
        log.error("Make sure Granola is installed and you are logged in.")
        sys.exit(1)

    with open(creds_path) as f:
        data = json.load(f)

    # Granola stores tokens as a JSON-encoded string inside the JSON file
    raw_tokens = data.get("workos_tokens") or data.get("tokens") or ""
    if isinstance(raw_tokens, str):
        tokens = json.loads(raw_tokens)
    else:
        tokens = raw_tokens

    token = tokens.get("access_token")
    if not token:
        log.error("No access_token found in credentials file. Try re-logging into Granola.")
        sys.exit(1)

    log.info("Loaded Granola credentials ✓")
    return token


# ── API ───────────────────────────────────────────────────────────────────────
GRANOLA_API = "https://api.granola.ai/v2"
HEADERS_BASE = {
    "Content-Type": "application/json",
    "Accept": "*/*",
    "User-Agent": "Granola/5.354.0",
    "X-Client-Version": "5.354.0",
}


def fetch_documents(token: str) -> list[dict]:
    """Fetch all documents (notes) from the Granola API."""
    headers = {**HEADERS_BASE, "Authorization": f"Bearer {token}"}

    all_docs: list[dict] = []
    offset = 0
    page = 1

    while True:
        payload = {
            "limit": 100,
            "offset": offset,
            "include_last_viewed_panel": True,
        }

        log.info(f"Fetching page {page} (offset {offset})…")
        resp = requests.post(
            f"{GRANOLA_API}/get-documents",
            headers=headers,
            json=payload,
            timeout=30,
        )

        if resp.status_code == 401:
            log.error("Authentication failed. Re-open Granola and try again (your token may have expired).")
            sys.exit(1)

        resp.raise_for_status()
        data = resp.json()

        docs = data.get("docs", [])
        all_docs.extend(docs)
        log.info(f"  → got {len(docs)} notes (total so far: {len(all_docs)})")

        # Stop when we get fewer results than the page size
        if len(docs) < 100:
            break
        offset += len(docs)
        page += 1

    return all_docs


# ── Content extraction ────────────────────────────────────────────────────────
def prosemirror_to_text(node: dict, indent: int = 0) -> str:
    """Recursively convert a ProseMirror document node to plain text."""
    if not node:
        return ""

    node_type = node.get("type", "")
    content = node.get("content", [])
    text_val = node.get("text", "")

    # Leaf text node
    if node_type == "text":
        marks = {m["type"] for m in node.get("marks", [])}
        out = text_val
        if "bold" in marks:
            out = f"**{out}**"
        if "italic" in marks:
            out = f"*{out}*"
        if "code" in marks:
            out = f"`{out}`"
        return out

    children = "".join(prosemirror_to_text(c, indent) for c in content)

    if node_type == "doc":
        return children
    if node_type == "paragraph":
        return children.strip() + "\n\n"
    if node_type in ("heading",):
        level = node.get("attrs", {}).get("level", 1)
        return f"{'#' * level} {children.strip()}\n\n"
    if node_type == "bulletList":
        return children
    if node_type == "orderedList":
        return children
    if node_type == "listItem":
        lines = children.strip().splitlines()
        bullet = f"{'  ' * indent}- {lines[0]}" if lines else ""
        rest = "\n".join(f"{'  ' * (indent + 1)}{l}" for l in lines[1:])
        return bullet + ("\n" + rest if rest else "") + "\n"
    if node_type == "blockquote":
        lines = children.strip().splitlines()
        return "\n".join(f"> {l}" for l in lines) + "\n\n"
    if node_type == "codeBlock":
        lang = node.get("attrs", {}).get("language", "")
        return f"```{lang}\n{children.strip()}\n```\n\n"
    if node_type == "horizontalRule":
        return "---\n\n"
    if node_type == "hardBreak":
        return "\n"
    if node_type == "taskList":
        return children
    if node_type == "taskItem":
        checked = node.get("attrs", {}).get("checked", False)
        box = "[x]" if checked else "[ ]"
        return f"- {box} {children.strip()}\n"

    # Fallback: just return children text
    return children


def extract_note_content(doc: dict) -> str:
    """Pull the AI-summarised note content out of a Granola document object."""
    # Try the panel content first (what you see in the app)
    panel = doc.get("last_viewed_panel") or {}
    pm_doc = None

    if isinstance(panel, dict):
        inner = panel.get("content", {})
        if isinstance(inner, dict) and inner.get("type") == "doc":
            pm_doc = inner

    # Fall back to top-level notes field
    if not pm_doc:
        notes = doc.get("notes") or doc.get("content") or {}
        if isinstance(notes, dict) and notes.get("type") == "doc":
            pm_doc = notes

    if pm_doc:
        return prosemirror_to_text(pm_doc).strip()

    # Last resort: plain text field
    return doc.get("summary") or doc.get("plain_text") or ""


def extract_transcript(doc: dict) -> str:
    """Extract the raw transcript, if present."""
    transcript = doc.get("transcript") or []
    if not transcript:
        return ""

    lines = []
    for segment in transcript:
        speaker = segment.get("speaker") or segment.get("name") or "Unknown"
        text = segment.get("text") or segment.get("content") or ""
        if text:
            lines.append(f"**{speaker}:** {text}")

    return "\n\n".join(lines)


# ── File helpers ──────────────────────────────────────────────────────────────
def safe_filename(title: str, max_len: int = 80) -> str:
    """Turn a note title into a safe filename."""
    name = re.sub(r'[\\/:*?"<>|]', "-", title)
    name = re.sub(r"\s+", " ", name).strip()
    return name[:max_len] if name else "Untitled"


def format_date(iso: str) -> str:
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M")
    except Exception:
        return iso


# ── Main export ───────────────────────────────────────────────────────────────
def export_notes(
    docs: list[dict],
    output_dir: Path,
    ext: str = "md",
    include_transcript: bool = False,
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    saved = 0
    skipped = 0

    for doc in docs:
        title = doc.get("title") or "Untitled"
        created = doc.get("created_at") or doc.get("createdAt") or ""
        updated = doc.get("updated_at") or doc.get("updatedAt") or ""

        content = extract_note_content(doc)
        if not content:
            log.debug(f"Skipping '{title}' — no content found")
            skipped += 1
            continue

        # Build markdown/text body
        date_str = format_date(created) if created else ""
        header_lines = [f"# {title}", ""]
        if date_str:
            header_lines += [f"**Date:** {date_str}", ""]
        if updated and updated != created:
            header_lines += [f"**Last updated:** {format_date(updated)}", ""]

        attendees = doc.get("people") or doc.get("attendees") or []
        if attendees:
            names = ", ".join(
                p.get("name") or p.get("email") or str(p)
                for p in attendees
                if isinstance(p, dict)
            )
            if names:
                header_lines += [f"**Attendees:** {names}", ""]

        body = "\n".join(header_lines) + "\n" + content

        if include_transcript:
            transcript = extract_transcript(doc)
            if transcript:
                body += "\n\n---\n\n## Full Transcript\n\n" + transcript

        # Write file
        base_name = safe_filename(title)
        if date_str:
            date_prefix = date_str[:10]  # YYYY-MM-DD
            filename = f"{date_prefix} {base_name}.{ext}"
        else:
            filename = f"{base_name}.{ext}"

        filepath = output_dir / filename

        if filepath.exists():
            log.debug(f"  –  already exists, skipping: {filepath.name}")
            skipped += 1
            continue

        filepath.write_text(body, encoding="utf-8")
        log.info(f"  ✓  {filepath.name}")
        saved += 1

    already_exists = sum(1 for doc in docs if doc.get("_skipped_exists"))
    print(f"\n{'─'*50}")
    print(f"  Saved:   {saved} new notes  →  {output_dir}")
    if skipped:
        print(f"  Skipped: {skipped} (already exist or no content)")
    print(f"{'─'*50}\n")


# ── CLI ───────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Export all Granola meeting notes to text/markdown files."
    )
    parser.add_argument(
        "--output", "-o",
        default=str(Path.home() / "granola-notes"),
        help="Folder to save notes into (default: ~/granola-notes)",
    )
    parser.add_argument(
        "--format", "-f",
        choices=["md", "txt"],
        default="md",
        help="File extension / format (default: md)",
    )
    parser.add_argument(
        "--include-transcript",
        action="store_true",
        help="Append the full meeting transcript to each note",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show debug output",
    )
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    output_dir = Path(args.output).expanduser().resolve()

    print("\n🌿  Granola Notes Exporter")
    print(f"   Output folder : {output_dir}")
    print(f"   File format   : .{args.format}")
    print(f"   Transcripts   : {'yes' if args.include_transcript else 'no'}\n")

    token = load_token()
    docs = fetch_documents(token)

    if not docs:
        print("No notes found in your Granola account.")
        sys.exit(0)

    print(f"\nFound {len(docs)} notes. Exporting…\n")
    export_notes(docs, output_dir, ext=args.format, include_transcript=args.include_transcript)


if __name__ == "__main__":
    main()
