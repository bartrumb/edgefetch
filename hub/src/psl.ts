/**
 * Mozilla Public Suffix List (PSL) Bridge (`hub/src/psl.ts`) — delegates to Go `internal/extract/psl.go` via `edgefetch-core.wasm`.
 */

import { wasmLookupPsl } from './wasm-bridge';

export function getRegistrableDomain(host: string): string | null {
  return wasmLookupPsl(host).registrableDomain;
}

export function isPublicOrPrivateSuffix(host: string): boolean {
  return wasmLookupPsl(host).isSuffix;
}

export function hasPrivateSharedHostingSuffix(host: string): boolean {
  return wasmLookupPsl(host).isPrivateShared;
}
