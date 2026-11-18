module github.com/bartrumb/edgefetch

// 100% Go standard library: zero external dependencies (no go.sum required).
// Targets Go 1.22+ for standard-library structured logging (`log/slog`), enhanced `for`-loop variable scoping,
// and modern `net/http` routing; Dockerfiles compile with Go 1.25 for automatic cgroup `GOMAXPROCS` awareness.
go 1.22
