package cert

import (
	"encoding/json"
	"fmt"
)

type identifier string

func (id *identifier) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*id = ""
		return nil
	}
	if len(data) == 0 {
		return fmt.Errorf("empty certificate identifier")
	}
	if data[0] == '"' {
		var value string
		if err := json.Unmarshal(data, &value); err != nil {
			return err
		}
		*id = identifier(value)
		return nil
	}
	var value json.Number
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*id = identifier(value.String())
	return nil
}

func (id identifier) String() string { return string(id) }
