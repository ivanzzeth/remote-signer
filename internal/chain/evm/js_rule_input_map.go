package evm

import "encoding/json"

func ruleInputToMap(input *RuleInput) (map[string]interface{}, error) {
	if input == nil { return nil, nil }
	data, err := json.Marshal(input)
	if err != nil { return nil, err }
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil { return nil, err }
	return m, nil
}
