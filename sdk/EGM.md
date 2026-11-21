# sdk

## Overview

`sdk` groups official language client libraries for the EdgeFetch Hub HTTP v1 API, providing Bearer-authenticated JSON request wrappers, typed/structured error handling (`EdgeFetchError`), and multi-gateway failover across `baseUrls`.

## Subdirectories & Boundaries

- `py`: [./py/EGM.md](./py/EGM.md) - Zero-dependency Python standard-library client (`EdgeFetchClient`, `EdgeFetchError`) covering `/v1/*` Hub endpoints with multi-URL gateway failover and cross-origin redirect `Authorization` header stripping.
- `ts`: [./ts/EGM.md](./ts/EGM.md) - TypeScript/ESM client (`EdgeFetchClient`, `EdgeFetchError`, and `/v1/*` parameter types) using `fetch` with multi-URL gateway failover (`502`/`503`/`504` and network errors).
