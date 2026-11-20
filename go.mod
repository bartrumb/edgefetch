module github.com/bartrumb/edgefetch/v2

// One Go dependency (github.com/coder/websocket), with no transitive dependencies.
// Targets go 1.26.0+ so Go 1.25+ container cgroup GOMAXPROCS awareness (containermaxprocs / updatemaxprocs) is enabled.
go 1.26.0

require github.com/coder/websocket v1.8.15
