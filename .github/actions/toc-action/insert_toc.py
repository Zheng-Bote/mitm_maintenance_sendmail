#!/usr/bin/env python3
"""
Insert or update a Table of Contents between markers:
  <!-- START doctoc generated TOC please keep comment here to allow auto update -->
  <!-- END doctoc generated TOC please keep comment here to allow auto update -->

Features:
- Parses headings level >= 2 (## ... ######)
- Generates GitHub-compatible anchors (slugger behavior)
- Ensures unique anchors with -1, -2 suffixes
- Skips files containing <!-- DOCTOC SKIP -->
- Accepts comma-separated files or globs
"""
from pathlib import Path
from glob import glob
import argparse
import re
import unicodedata
from collections import defaultdict

MARKER_START = "<!-- START doctoc generated TOC please keep comment here to allow auto update -->"
MARKER_END = "<!-- END doctoc generated TOC please keep comment here to allow auto update -->"
SKIP_FLAG = "<!-- DOCTOC SKIP -->"

def github_slugger(text, seen):
    # Normalize
    s = unicodedata.normalize("NFKD", text)
    # Remove combining marks
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    s = s.strip().lower()

    # Remove most punctuation but keep letters, numbers, spaces and hyphens
    s = re.sub(r"[^\w\s-]", "", s, flags=re.UNICODE)

    # Replace whitespace with hyphens
    s = re.sub(r"\s+", "-", s)

    # Collapse multiple hyphens
    s = re.sub(r"-{2,}", "-", s)

    # IMPORTANT: do NOT strip leading hyphens here.
    # GitHub preserves a leading hyphen if the original text started with a non-word
    # character followed by a space (e.g. "📜 License" -> "-license").
    # Only handle the empty case:
    if s == "" or all(ch == "-" for ch in s):
        s = "-"  # fallback to single hyphen if nothing meaningful left

    # Ensure uniqueness
    base = s
    count = seen[base]
    seen[base] += 1
    return base if count == 0 else f"{base}-{count}"

def build_toc(headings, collapsed):
    if not headings:
        return ""
    seen = defaultdict(int)
    lines = []
    for level, text in headings:
        indent = "  " * max(0, level - 2)
        anchor = github_slugger(text, seen)
        lines.append(f"{indent}- [{text}](#{anchor})")
    toc_body = "\n".join(lines)
    if collapsed:
        return f"<details>\n<summary>Table of Contents</summary>\n\n{toc_body}\n\n</details>"
    return toc_body

def collect_headings(text):
    headings = []
    # Match headings at line start: ## Heading text
    for m in re.finditer(r'^(#{2,6})\s+(.*)$', text, flags=re.MULTILINE):
        lvl = len(m.group(1))
        txt = m.group(2).strip()
        # Remove trailing '#' characters that some authors add: "## Title ##"
        txt = re.sub(r'\s+#+\s*$', '', txt)
        headings.append((lvl, txt))
    return headings

def process_file(path: Path, collapsed: bool):
    txt = path.read_text(encoding="utf-8")
    if SKIP_FLAG in txt:
        print(f"Skipping {path} (DOCTOC SKIP present)")
        return False
    if MARKER_START not in txt or MARKER_END not in txt:
        print(f"Skipping {path}: TOC markers not found")
        return False

    headings = collect_headings(txt)
    toc = build_toc(headings, collapsed)

    # Replace content between markers (keep markers)
    before, rest = txt.split(MARKER_START, 1)
    _, after = rest.split(MARKER_END, 1)
    new_txt = before + MARKER_START + "\n\n" + toc + "\n\n" + MARKER_END + after

    if new_txt != txt:
        path.write_text(new_txt, encoding="utf-8")
        print(f"Updated TOC in {path}")
        return True
    print(f"No changes for {path}")
    return False

def expand_patterns(patterns):
    out = []
    for p in patterns:
        p = p.strip()
        if any(ch in p for ch in "*?[]"):
            out.extend(glob(p, recursive=True))
        else:
            out.append(p)
    # Remove duplicates while preserving order
    seen = set()
    res = []
    for x in out:
        if x not in seen:
            seen.add(x)
            res.append(x)
    return [Path(x) for x in res]

def main():
    ap = argparse.ArgumentParser(description="Insert TOC into Markdown files")
    ap.add_argument("--files", default="./README.md",
                    help="Comma-separated files or globs (default: ./README.md)")
    ap.add_argument("--collapsed", default="true",
                    help="true/false: wrap TOC in <details> (default: true)")
    args = ap.parse_args()

    patterns = [p for p in args.files.split(",") if p.strip()]
    collapsed = str(args.collapsed).lower() in ("1", "true", "yes")
    paths = expand_patterns(patterns)

    if not paths:
        print("No files matched.")
        return

    changed_any = False
    for p in paths:
        if not p.exists():
            print(f"Not found: {p}")
            continue
        try:
            changed = process_file(p, collapsed)
            changed_any = changed_any or changed
        except Exception as e:
            print(f"Error processing {p}: {e}")

    # exit code 0 always (workflow decides whether to commit)
    return

if __name__ == "__main__":
    main()
