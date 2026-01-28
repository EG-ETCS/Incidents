# AI Coding Guidelines for Incidents Repo

- **Purpose**: MkDocs + Material site for weekly incident write-ups; content lives in [docs/](docs) and is organized by year/week folders, surfaced via cards in [docs/This-Week.md](docs/This-Week.md) and [docs/Last-Week.md](docs/Last-Week.md).
- **Navigation is manual**: Update [mkdocs.yml](mkdocs.yml) when adding new weeks or pages; months/weeks are nested under the `nav` tree (2025/2026). Keep titles human-readable and paths pointing to markdown files in docs.
- **Serve locally**: `python -m mkdocs serve` from repo root, or run [serve_docs.bat](serve_docs.bat) on Windows (launches VS Code, starts mkdocs, opens Edge once server returns 200).
- **Deploy**: Repo expects `mkdocs gh-deploy --clean` (see [README.md](README.md)).
- **Dependencies**: mkdocs-material with extras (pymdown extensions, mkdocs-video, mkdocs-pdf). Ensure `python -m pip install mkdocs mkdocs-material pymdown-extensions mkdocs-video mkdocs-pdf-export-plugin mkdocs-pdf` before serving.
- **Styling hooks**: Chips use the `.cve-chip` class and emoji/Material icons enabled in [mkdocs.yml](mkdocs.yml); extra styles live in [stylesheets/extra.css](stylesheets/extra.css).
- **Incident authoring pattern**: Use the structure in [TEMPLATE.md](TEMPLATE.md) (title, chip tags, Overview, Technical Specifications table, Affected Products, Attack Scenario, Impact tabs, Mitigation sections, Resources). Preserve headings and tab blocks to keep layout consistent.
- **File placement**: New incidents go under `docs/<year>/Week<nn>/`. Match filenames to incident slugs (e.g., `abb-fbxi.md`) and add any images to the sibling `images/` directory; reference images with relative paths used by cards (see [docs/2025/Week44/aski-energy-als-mini.md](docs/2025/Week44/aski-energy-als-mini.md)).
- **Card layout for weekly pages**: The weekly landing pages hide nav/toc via front matter and use a `grid cards` block with image, bold title, chip tags, summary, and a “Read more” link. Mirror this pattern when adding new cards to [docs/This-Week.md](docs/This-Week.md) or [docs/Last-Week.md](docs/Last-Week.md).
- **Front matter**: Keep the YAML `hide: [navigation, toc]` block at the top of card pages (see [docs/This-Week.md](docs/This-Week.md)). Incident detail pages typically omit front matter.
- **Chips and icons**: Use `{.cve-chip}` after bolded tags/CVEs for consistent pill styling. Icons in headings (e.g., `:material-network-off:`) are supported by Material icons configured in [mkdocs.yml](mkdocs.yml).
- **Tables and admonitions**: Technical specs and resource lists rely on Markdown tables and `!!!` admonitions; keep them intact to avoid layout regression.
- **Math/mermaid**: Arithmatex and mermaid fences are preconfigured in [mkdocs.yml](mkdocs.yml); use fenced `mermaid` blocks or math if needed—no extra setup.
- **Video/PDF**: mkdocs-video plugin is enabled (`is_video`, `video_controls` in [mkdocs.yml](mkdocs.yml)), so you can embed videos with the plugin syntax; mkdocs-pdf provides PDF generation.
- **Images**: Use descriptive alt text; prefer relative paths like `![title](2026/Week4/images/gmail.png)` to keep links working in the built site.
- **Naming**: Week folders are capitalized `Week##`; months are grouped in `nav` under 2025/2026. Keep new files consistent to avoid broken nav items.
- **Security note**: [run_command_api.py](run_command_api.py) is a debug helper that shells commands; avoid exposing it beyond local use.
- **Lint/tests**: No automated tests; primary check is mkdocs render. Run `python -m mkdocs build` to validate before commit if you need a quick sanity check.
- **Site output**: Built site lives in [site/](site); do not hand-edit generated files.
- **PR review hotspots**: Confirm new pages are linked in `nav`, card grids updated, images added to correct week folder, and chip/tag styling preserved.

If any section is unclear or missing project-specific details you need, tell me and I will refine this file.