# GenAI & Knowledge Archive Providers (`hub/src/extractors/providers/genai`)

## Overview

Provides built-in keyless `SiteAdapter` definitions for generative AI model/dataset hubs and public knowledge archives (`huggingface.co`, `archive.org`, and `openrouter.ai`). Each adapter resolves incoming web URLs into declarative `SiteExtractorTwin` descriptors (`resolveTwin`) that upgrade page fetches to raw Markdown/code blobs or official public JSON metadata endpoints and format responses into structured Markdown.

## Interface

- `[huggingface.ts:default]` — `SiteAdapter` (`id: 'huggingface'`, `category: 'genai'`, `domains: ['huggingface.co', 'www.huggingface.co']`) implementing `resolveTwin` for twin `'huggingface-card'` (`kind: 'text'`, `fetchUrl: 'https://huggingface.co/${repoPrefix}/raw/${encodeURIComponent(rev)}/README.md'`) and twin `'huggingface-blob'` (`kind: 'text'`, `fetchUrl: 'https://huggingface.co/${repoPrefix}/raw/${encodeURIComponent(rev)}/${filePath}'`).
- `[internet-archive.ts:default]` — `SiteAdapter` (`id: 'internet-archive'`, `category: 'genai'`, `domains: ['archive.org', 'www.archive.org']`) implementing `resolveTwin` for twin `'internet-archive'` (`kind: 'json'`, `fetchUrl: 'https://archive.org/metadata/${encodeURIComponent(identifier)}'`).
- `[openrouter.ts:default]` — `SiteAdapter` (`id: 'openrouter'`, `category: 'genai'`, `domains: ['openrouter.ai']`) implementing `resolveTwin` for twin `'openrouter'` (`kind: 'json'`, `fetchUrl: 'https://openrouter.ai/api/v1/models'`).

## Invariants

- `[huggingface.ts:resolveTwin]` — Matches either typed repositories (`(parts[0] === 'datasets' || parts[0] === 'spaces') && parts.length >= 3`) or untyped model repositories (`parts.length >= 2` where `parts[0].toLowerCase()` is excluded from reserved root `Set` `{'models','datasets','spaces','docs','blog','papers','posts','tasks','organizations','settings','login','join','pricing'}`); returns `null` unless trailing segments match root/`tree/<rev>` (`'huggingface-card'`, defaulting empty `rev` to `'main'`) or `blob/<rev>/<filePath>` (`'huggingface-blob'`).
- `[huggingface.ts:formatTwin]` — Rejects empty responses or HTML error documents matching `/^\s*<!doctype\s+html|^\s*<html/i` by returning `null`; delegates Markdown blobs (`detectFenceLang(filePath).isMarkdown`) to `formatYamlFrontmatterCard` and wraps non-Markdown source blobs via `safeFence(rawBody, lang)`.
- `[internet-archive.ts:resolveTwin]` — Requires `parts[0] === 'details' && parts.length === 2` where decoded `identifier` satisfies `/^[A-Za-z0-9._-]{2,120}$/` and does not start with `'@'`; otherwise returns `null`.
- `[internet-archive.ts:formatTwin]` — Returns `null` when `parseJsonObject(rawBody)?.metadata` is missing or non-object; caps `meta.collection` at `.slice(0, 6)`, filters `data.files` to exclude `'_meta.xml'` / `'_files.xml'` suffixes capped at `.slice(0, 15)`, strips inline HTML via `stripTagsInline`, and truncates `description` to `260` characters.
- `[openrouter.ts:resolveTwin]` — Accepts `/models/<org>/<slug>` (`parts.length === 3`) or `/<org>/<slug>` (`parts.length === 2` when `parts[0].toLowerCase()` is outside reserved `Set` `{'docs','rankings','chat','activity','settings','keys','credits','privacy','terms','about','blog','pricing','providers'}`) and enforces `/^[A-Za-z0-9._-]+\/[A-Za-z0-9._:-]+$/` on `modelId`; otherwise returns `null`.
- `[openrouter.ts:formatTwin]` — Matches `modelId` case-insensitively against `data` entries from `/api/v1/models` (returning `null` if absent), omits negative or non-finite pricing in `perMillion`, caps `supported_parameters` at `.slice(0, 14)`, and truncates `description` to `260` characters.
- `[huggingface.ts:default]`, `[internet-archive.ts:default]`, `[openrouter.ts:default]` — Pure declarative adapter contract: adapters never invoke network I/O directly and only return `SiteExtractorTwin` descriptors or `null`.

## Side Effects

- None (`[huggingface.ts:default]`, `[internet-archive.ts:default]`, `[openrouter.ts:default]` perform pure URL matching and string/JSON formatting without network, disk, or state mutations).

## Verification

- Run: `npm --prefix hub test`
