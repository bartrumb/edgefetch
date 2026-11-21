# Browser Extensions (`extensions`)

## Overview

Groups first-party browser extension packages that integrate desktop Chromium-based browsers with an EdgeFetch Hub for interactive DOM tab clipping and opt-in residential outbound fetch execution. This directory contains zero top-level source files and delegates all runtime behavior to its child extension package(s).

## Subdirectories & Boundaries

- [browser-clipper](./browser-clipper/EGM.md) - Chrome/Edge Manifest V3 extension (`manifest.json` `v2.5.3`, `service-worker.js`, `offscreen.js`, `popup.js`) providing active-tab HTML ingestion (`POST /v1/ingest-tab`) and an SSRF-guarded offscreen WebSocket worker node (`ws(s)://<hub>/agent/ws` -> `POST /agent/reply`) enforcing HTTPS-only public host validation, manual 5-hop redirect checks, and a 4 MiB response stream cap.
