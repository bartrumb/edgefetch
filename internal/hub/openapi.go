package hub

import (
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/bartrumb/edgefetch/v2/internal/agent"
)

const defaultGoOpenAPIOrigin = "https://edgefetch.dev"

var reStrictOpenAPIHost = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*|\[::1\])(?::[1-9]\d{0,4})?$`)

func sanitizeGoOpenAPIOrigin(r *http.Request) string {
	rawHost := strings.ToLower(strings.TrimSpace(r.Host))
	if rawHost == "" && r.URL != nil {
		rawHost = strings.ToLower(strings.TrimSpace(r.URL.Host))
	}
	if rawHost == "" || !reStrictOpenAPIHost.MatchString(rawHost) {
		return defaultGoOpenAPIOrigin
	}
	hostPart, _, splitErr := net.SplitHostPort(rawHost)
	if splitErr != nil {
		hostPart = rawHost
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	} else if !isLoopbackHostnameOnly(hostPart) {
		return defaultGoOpenAPIOrigin
	}
	u, err := url.Parse(scheme + "://" + rawHost)
	if err != nil || u.Host == "" || u.User != nil {
		return defaultGoOpenAPIOrigin
	}
	return u.Scheme + "://" + u.Host
}

func resolveGoOpenAPIContentType(acceptHeader string) string {
	accept := strings.ToLower(acceptHeader)
	oaIdx := strings.Index(accept, "application/openapi+json")
	if oaIdx >= 0 {
		jsonIdx := strings.Index(accept, "application/json")
		if jsonIdx < 0 || oaIdx < jsonIdx {
			return "application/openapi+json; charset=utf-8"
		}
	}
	return "application/json; charset=utf-8"
}

func buildGoHubOpenAPISpec(origin string) map[string]any {
	bearerSec := []map[string]any{{"bearerAuth": []string{}}}
	jsonSchema := func(ref string) map[string]any {
		return map[string]any{
			"application/json": map[string]any{
				"schema": map[string]any{"$ref": "#/components/schemas/" + ref},
			},
		}
	}

	return map[string]any{
		"openapi":           "3.1.0",
		"jsonSchemaDialect": "https://spec.openapis.org/oas/3.1/dialect/base",
		"info": map[string]any{
			"title":       "EdgeFetch Go Hub API",
			"summary":     "Self-hosted single-binary Go Hub coordinator and MCP server for AI agents.",
			"version":     agent.Version,
			"description": "Self-hosted Go Hub (`edgefetch --mode=hub`) coordinating outbound Go worker nodes over `/agent/ws` with zero cloud dependencies, strict RFC 9309 `robots.txt` compliance, declarative site adapters, and Streamable HTTP MCP (`/mcp`).",
			"license": map[string]any{
				"name": "FSL-1.1-MIT (Hub) / MIT (Worker, SDKs & Adapters)",
				"url":  "https://github.com/bartrumb/edgefetch/blob/main/README.md#license--trademarks",
			},
		},
		"servers": []map[string]any{
			{
				"url":         origin,
				"description": "EdgeFetch Go Hub Instance",
			},
		},
		"tags": []map[string]any{
			{"name": "Discovery", "description": "Health, OpenAPI 3.1.0 schema, and RFC 9421 Web Bot Auth transparency endpoints."},
			{"name": "System", "description": "Capabilities, declarative site extractors, and connected worker fleet."},
			{"name": "Scraping & Extraction", "description": "Polite URL-to-Markdown scraping and site URL discovery."},
			{"name": "Coordinator & MCP", "description": "Low-level coordinator batch fetch (`POST /fetch`) and Streamable HTTP MCP (`POST /mcp`)."},
			{"name": "Compatibility", "description": "Drop-in Firecrawl v2 (`/v2/*`) compatibility endpoints."},
		},
		"paths": map[string]any{
			"/health": map[string]any{
				"get": map[string]any{
					"tags":        []string{"Discovery"},
					"operationId": "getHealth",
					"summary":     "Check Go Hub liveness and connected worker count",
					"security":    []any{},
					"responses": map[string]any{
						"200": map[string]any{"description": "Hub is healthy.", "content": jsonSchema("HealthResponse")},
					},
				},
			},
			"/openapi.json": map[string]any{
				"get": map[string]any{
					"tags":        []string{"Discovery"},
					"operationId": "getOpenApiSpec",
					"summary":     "Fetch OpenAPI 3.1.0 specification",
					"security":    []any{},
					"responses": map[string]any{
						"200": map[string]any{
							"description": "OpenAPI 3.1.0 JSON document.",
							"content": map[string]any{
								"application/json":         map[string]any{"schema": map[string]any{"type": "object"}},
								"application/openapi+json": map[string]any{"schema": map[string]any{"type": "object"}},
							},
						},
					},
				},
			},
			"/.well-known/edgefetch-bot.json": map[string]any{
				"get": map[string]any{
					"tags":        []string{"Discovery"},
					"operationId": "getBotManifest",
					"summary":     "Get machine-readable bot transparency manifest",
					"security":    []any{},
					"responses": map[string]any{
						"200": map[string]any{"description": "Bot transparency manifest.", "content": jsonSchema("GenericObject")},
					},
				},
			},
			"/.well-known/http-message-signatures-directory": map[string]any{
				"get": map[string]any{
					"tags":        []string{"Discovery"},
					"operationId": "getBotSignaturesDirectory",
					"summary":     "Get RFC 9421 Web Bot Auth Ed25519 JWKS directory",
					"security":    []any{},
					"responses": map[string]any{
						"200": map[string]any{
							"description": "RFC 9421 HTTP Message Signatures JWKS directory.",
							"content": map[string]any{
								"application/http-message-signatures-directory+json": map[string]any{
									"schema": map[string]any{"$ref": "#/components/schemas/GenericObject"},
								},
							},
						},
					},
				},
			},
			"/agents": map[string]any{
				"get": map[string]any{
					"tags":        []string{"System"},
					"operationId": "listAgents",
					"summary":     "List connected Go worker nodes",
					"security":    bearerSec,
					"responses": map[string]any{
						"200": map[string]any{"description": "Connected worker fleet.", "content": jsonSchema("GenericObject")},
					},
				},
			},
			"/v1/capabilities": map[string]any{
				"get": map[string]any{
					"tags":        []string{"System"},
					"operationId": "getCapabilities",
					"summary":     "Inspect Go Hub runtime capabilities",
					"security":    bearerSec,
					"responses": map[string]any{
						"200": map[string]any{"description": "Go Hub capability summary.", "content": jsonSchema("GenericObject")},
					},
				},
			},
			"/v1/extractors": map[string]any{
				"get": map[string]any{
					"tags":        []string{"System"},
					"operationId": "listExtractors",
					"summary":     "List declarative keyless site adapters",
					"security":    bearerSec,
					"parameters": []map[string]any{
						{"name": "query", "in": "query", "schema": map[string]any{"type": "string"}},
						{"name": "category", "in": "query", "schema": map[string]any{"type": "string"}},
						{"name": "limit", "in": "query", "schema": map[string]any{"type": "integer", "minimum": 1, "maximum": 50}},
					},
					"responses": map[string]any{
						"200": map[string]any{"description": "Registered declarative adapters.", "content": jsonSchema("GenericObject")},
					},
				},
			},
			"/v1/scrape": map[string]any{
				"post": map[string]any{
					"tags":        []string{"Scraping & Extraction"},
					"operationId": "scrapeUrl",
					"summary":     "Scrape a public HTTPS URL to clean Markdown",
					"security":    bearerSec,
					"requestBody": map[string]any{"required": true, "content": jsonSchema("ScrapeRequest")},
					"responses": map[string]any{
						"200": map[string]any{"description": "Scrape output.", "content": jsonSchema("GenericObject")},
					},
				},
			},
			"/v1/map": map[string]any{
				"post": map[string]any{
					"tags":        []string{"Scraping & Extraction"},
					"operationId": "mapSiteUrls",
					"summary":     "Discover URLs on a site via sitemaps, /llms.txt, and links",
					"security":    bearerSec,
					"requestBody": map[string]any{"required": true, "content": jsonSchema("MapRequest")},
					"responses": map[string]any{
						"200": map[string]any{"description": "Discovered URL list.", "content": jsonSchema("GenericObject")},
					},
				},
			},
			"/fetch": map[string]any{
				"post": map[string]any{
					"tags":        []string{"Coordinator & MCP"},
					"operationId": "dispatchFetch",
					"summary":     "Dispatch a coordinated multi-URL fetch call",
					"security":    bearerSec,
					"requestBody": map[string]any{"required": true, "content": jsonSchema("GenericObject")},
					"responses": map[string]any{
						"200": map[string]any{"description": "Coordinator fetch reply.", "content": jsonSchema("GenericObject")},
					},
				},
			},
			"/mcp": map[string]any{
				"post": map[string]any{
					"tags":        []string{"Coordinator & MCP"},
					"operationId": "handleMcpJsonRpc",
					"summary":     "Streamable HTTP Model Context Protocol (MCP) JSON-RPC endpoint",
					"security":    bearerSec,
					"requestBody": map[string]any{"required": true, "content": jsonSchema("GenericObject")},
					"responses": map[string]any{
						"200": map[string]any{"description": "JSON-RPC 2.0 response.", "content": jsonSchema("GenericObject")},
					},
				},
			},
			"/v2/scrape": map[string]any{
				"post": map[string]any{
					"tags":        []string{"Compatibility"},
					"operationId": "compatV2Scrape",
					"summary":     "Firecrawl v2 compatible single-URL scrape",
					"security":    bearerSec,
					"requestBody": map[string]any{"required": true, "content": jsonSchema("ScrapeRequest")},
					"responses": map[string]any{
						"200": map[string]any{"description": "Firecrawl v2 envelope.", "content": jsonSchema("GenericObject")},
					},
				},
			},
			"/v2/map": map[string]any{
				"post": map[string]any{
					"tags":        []string{"Compatibility"},
					"operationId": "compatV2Map",
					"summary":     "Firecrawl v2 compatible site URL map",
					"security":    bearerSec,
					"requestBody": map[string]any{"required": true, "content": jsonSchema("MapRequest")},
					"responses": map[string]any{
						"200": map[string]any{"description": "Firecrawl v2 envelope.", "content": jsonSchema("GenericObject")},
					},
				},
			},
		},
		"components": map[string]any{
			"securitySchemes": map[string]any{
				"bearerAuth": map[string]any{
					"type":        "http",
					"scheme":      "bearer",
					"description": "Pass `Authorization: Bearer <EDGEFETCH_CALLER_TOKEN>` (or `X-API-Key: <token>`).",
				},
			},
			"schemas": map[string]any{
				"HealthResponse": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"ok":              map[string]any{"type": "boolean"},
						"mode":            map[string]any{"type": "string"},
						"version":         map[string]any{"type": "string"},
						"connectedAgents": map[string]any{"type": "integer"},
					},
					"required": []string{"ok"},
				},
				"ScrapeRequest": map[string]any{
					"type":     "object",
					"required": []string{"url"},
					"properties": map[string]any{
						"url":             map[string]any{"type": "string", "description": "Public https:// URL to scrape."},
						"formats":         map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "default": []string{"markdown"}},
						"renderMode":      map[string]any{"type": "string", "enum": []string{"off", "auto", "always", "browser"}, "default": "auto"},
						"onlyMainContent": map[string]any{"type": "boolean", "default": true},
						"query":           map[string]any{"type": "string"},
						"maxChars":        map[string]any{"type": "integer", "minimum": 500, "maximum": 500000},
						"target":          map[string]any{"type": "string", "enum": []string{"auto", "agent", "container"}, "default": "auto"},
						"site":            map[string]any{"type": "string"},
					},
				},
				"MapRequest": map[string]any{
					"type":     "object",
					"required": []string{"url"},
					"properties": map[string]any{
						"url":    map[string]any{"type": "string", "description": "Root public https:// URL."},
						"search": map[string]any{"type": "string"},
						"limit":  map[string]any{"type": "integer", "minimum": 1, "maximum": 500, "default": 100},
						"target": map[string]any{"type": "string", "enum": []string{"auto", "agent", "container"}, "default": "auto"},
						"site":   map[string]any{"type": "string"},
					},
				},
				"GenericObject": map[string]any{
					"type":                 "object",
					"additionalProperties": true,
				},
			},
		},
	}
}

func (s *Server) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Authorization, Content-Type, X-API-Key")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	if r.Method == http.MethodOptions {
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD, OPTIONS")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}

	origin := sanitizeGoOpenAPIOrigin(r)
	spec := buildGoHubOpenAPISpec(origin)
	body, _ := json.MarshalIndent(spec, "", "  ")
	body = append(body, '\n')

	w.Header().Set("Content-Type", resolveGoOpenAPIContentType(r.Header.Get("Accept")))
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("Vary", "Accept")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}
