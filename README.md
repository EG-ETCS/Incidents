# Incidents — Weekly Cybersecurity Incident Knowledge Base

A living, week-by-week catalogue of cybersecurity incidents, vulnerabilities, malware campaigns and threat-actor activity, published as a searchable static site built with [MkDocs](https://www.mkdocs.org/) and the [Material for MkDocs](https://squidfunk.github.io/mkdocs-material/) theme.

Every entry is a standalone briefing: what happened, which products are affected, how the attack works, what the impact is, and what to do about it. Entries are grouped into week folders so the archive doubles as a timeline of the threat landscape.

---

## What's inside

Topics span the full spectrum of the field: CVEs in enterprise software and network appliances (Cisco, Fortinet, VMware, Oracle, SonicWall), ICS/OT and critical-infrastructure attacks (water utilities, SCADA, building management), nation-state APT campaigns, Android and iOS malware, supply-chain compromises in npm and browser extensions, ransomware and data breaches, and emerging AI-related attack surfaces such as prompt injection.

## Repository layout

```
.
├── mkdocs.yml                  # Site config: theme, plugins, markdown extensions, full nav tree
├── TEMPLATE.md                 # Canonical structure for a new incident page (+ input formats)
├── serve_docs.bat              # Windows one-click: launch editor, serve site, open browser
├── run_command_api.py          # Local-only Flask helper (see security note below)
├── .github/
│   └── copilot-instructions.md # Conventions for AI assistants working in this repo
└── docs/
    ├── index.md                # "Today's Incidents" card grid
    ├── This-Week.md            # Current week's card grid
    ├── Last-Week.md            # Previous week's card grid
    ├── default.md              # Placeholder shown when no incident is selected
    ├── stylesheets/extra.css   # Custom theme: dark-red header, CVE chips, card grid effects
    ├── alarm.png / alarm.ico   # Site logo and favicon
    ├── 2025/
    │   ├── Week44/ … Week53/
    │   │   ├── <incident-slug>.md
    │   │   └── images/<incident-slug>.png
    └── 2026/
        └── Week1/ … Week30/
            ├── <incident-slug>.md
            └── images/<incident-slug>.png
```

## Anatomy of an incident page

Pages follow the structure defined in [`TEMPLATE.md`](TEMPLATE.md). Keeping to it is what makes the archive skimmable and comparable across hundreds of entries:

1. **Title** — the incident or vulnerability name as an `h1`.
2. **Hero image** — a screenshot, logo, or diagram from the sibling `images/` folder.
3. **Chip tags** — bolded labels suffixed with `{.cve-chip}`, rendering as red pills (CVE IDs, attack class, affected sector).
4. **Overview** — a few paragraphs of narrative context.
5. **Technical Specifications** — a two-column markdown table (CVE ID, CVSS, attack vector, authentication, complexity, affected versions).
6. **Affected Products** — vendors, models, firmware ranges, end-of-life status.
7. **Attack Scenario** — the exploitation chain as a numbered sequence.
8. **Impact Assessment** — tabbed blocks (`=== "Integrity"` / `"Confidentiality"` / `"Availability"`) powered by `pymdownx.tabbed`.
9. **Mitigation Strategies** — immediate actions, short-term measures, monitoring and detection, long-term fixes.
10. **Resources and References** — source links inside an `!!! info` admonition.
11. **Footer** — a horizontal rule and `*Last Updated: Month DD, YYYY*`.

## Getting started

### Prerequisites

- Python 3.8 or newer
- `pip`

### Install dependencies

```powershell
python -m pip install mkdocs mkdocs-material pymdown-extensions mkdocs-video mkdocs-pdf-export-plugin mkdocs-pdf
python -m mkdocs --version
```

### Preview locally

```powershell
python -m mkdocs serve
```

The site is served at <http://127.0.0.1:8000/> with live reload on save.

On Windows you can instead run [`serve_docs.bat`](serve_docs.bat), which opens the folder in VS Code, starts the dev server, waits for it to return `200 OK`, and then launches Edge. Note that the script hard-codes local VS Code and Edge install paths, so adjust them for your machine before use.

### Build and deploy

```powershell
python -m mkdocs build          # render to ./site (git-ignored) — use this as a pre-commit sanity check
python -m mkdocs gh-deploy --clean   # publish to the gh-pages branch
```

Never hand-edit anything under `site/`; it is generated output.

## Adding a new incident

1. **Pick the target week folder.** Create `docs/<year>/Week<nn>/` and its `images/` subfolder if this is a new week. Folder names are capitalised, e.g. `Week30`.
2. **Add the artwork.** Drop the hero image in `docs/<year>/Week<nn>/images/` using the same slug as the page (`Minnesota.png` for `Minnesota.md`). Extra shots take a numeric suffix: `Minnesota1.png`, `Minnesota2.png`.
3. **Write the page.** Copy the skeleton from [`TEMPLATE.md`](TEMPLATE.md) into `docs/<year>/Week<nn>/<slug>.md` and fill in every section. Preserve the headings, tables, tab blocks, and admonitions verbatim — the layout depends on them.
4. **Register it in the navigation.** The `nav` tree in [`mkdocs.yml`](mkdocs.yml) is maintained by hand. Add an entry under the correct year → month → week, using a descriptive human-readable title. Quote titles containing colons or commas; use single quotes when the title itself contains double quotes. **A page not listed in `nav` will not appear on the site.**
5. **Surface it on the landing pages.** Add a matching card to `docs/This-Week.md` (and `docs/index.md` if it is a same-day item), and move the previous week's cards to `docs/Last-Week.md`.
6. **Verify.** Run `python -m mkdocs build` and watch for warnings about broken links or missing files, then check the rendering with `mkdocs serve`.


