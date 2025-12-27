package policy

import (
	"encoding/json"
	"fmt"
	"os"
)

type Policy struct {
	Name        string
	Description string
}

func Load(path string) (*Policy, error) {

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var p Policy
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}

	fmt.Println("[policy] Loaded policy:", p.Name)

	return &p, nil
}
