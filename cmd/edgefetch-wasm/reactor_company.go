package main

import (
	"encoding/json"

	"github.com/bartrumb/edgefetch/v2/internal/company"
)

func init() {
	phase2CompanyRPC = handleCompanyRPC
}

// handleCompanyRPC exposes internal/company to the Worker. The hub only orchestrates fetches:
// company_plan -> fetch -> company_followups -> fetch entities -> company_pick_wikidata ->
// (company_entity_followups) -> fetch SEC / labels -> company_places_query (optional Maps search) ->
// company_merge.
func handleCompanyRPC(op string, payload json.RawMessage) (any, bool, error) {
	switch op {
	case "company_plan":
		var p company.PlanInput
		if err := unmarshalCompanyPayload(payload, &p); err != nil {
			return nil, true, err
		}
		out, err := company.Plan(p)
		if err != nil {
			return nil, true, err
		}
		return out, true, nil

	case "company_followups":
		var p company.FollowupsInput
		if err := unmarshalCompanyPayload(payload, &p); err != nil {
			return nil, true, err
		}
		return company.Followups(p), true, nil

	case "company_pick_wikidata":
		var p company.PickInput
		if err := unmarshalCompanyPayload(payload, &p); err != nil {
			return nil, true, err
		}
		return company.PickWikidataEntity(p), true, nil

	case "company_entity_followups", "company_sec_urls":
		var p company.EntityFollowupsInput
		if err := unmarshalCompanyPayload(payload, &p); err != nil {
			return nil, true, err
		}
		return company.EntityFollowupsFor(p), true, nil

	case "company_places_query":
		var p company.PlacesQueryInput
		if err := unmarshalCompanyPayload(payload, &p); err != nil {
			return nil, true, err
		}
		return map[string]any{"query": company.PlacesQuery(p)}, true, nil

	case "company_merge":
		var p company.MergeInput
		if err := unmarshalCompanyPayload(payload, &p); err != nil {
			return nil, true, err
		}
		return company.Merge(p), true, nil
	}
	return nil, false, nil
}

func unmarshalCompanyPayload(payload json.RawMessage, v any) error {
	if len(payload) == 0 {
		return nil
	}
	return json.Unmarshal(payload, v)
}
