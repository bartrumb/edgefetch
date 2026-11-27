package main

import (
	"encoding/json"
	"time"

	"github.com/bartrumb/edgefetch/v2/internal/jobs"
)

func init() {
	phase2SalaryRPC = handleSalaryRPC
}

// handleSalaryRPC serves the salary aggregation ops. All normalization and statistics live in
// internal/jobs/salary.go; the Worker only persists observations (one per posting URL) and calls these.
func handleSalaryRPC(op string, payload json.RawMessage) (any, bool, error) {
	switch op {
	case "salary_observations":
		var p struct {
			Jobs     []jobs.StructuredJobRecord `json:"jobs"`
			SeenAtMs int64                      `json:"seenAtMs"`
		}
		if len(payload) > 0 {
			if err := json.Unmarshal(payload, &p); err != nil {
				return nil, true, err
			}
		}
		if p.SeenAtMs <= 0 {
			p.SeenAtMs = time.Now().UnixMilli()
		}
		obs, rejected := jobs.SalaryObservationsFromJobs(p.Jobs, p.SeenAtMs)
		return map[string]any{"observations": obs, "rejected": rejected}, true, nil

	case "salary_match_query":
		var p struct {
			Title    string `json:"title"`
			Location string `json:"location"`
		}
		if len(payload) > 0 {
			if err := json.Unmarshal(payload, &p); err != nil {
				return nil, true, err
			}
		}
		family, seniority := jobs.MatchTitleQuery(p.Title)
		return map[string]any{
			"titleFamily":    family,
			"seniority":      seniority,
			"locationBucket": jobs.NormalizeLocationQuery(p.Location),
		}, true, nil

	case "salary_aggregate":
		var p struct {
			Observations []jobs.SalaryObservation `json:"observations"`
			Query        jobs.SalaryQuery         `json:"query"`
		}
		if len(payload) > 0 {
			if err := json.Unmarshal(payload, &p); err != nil {
				return nil, true, err
			}
		}
		return jobs.AggregateSalaries(p.Observations, p.Query), true, nil
	}
	return nil, false, nil
}
