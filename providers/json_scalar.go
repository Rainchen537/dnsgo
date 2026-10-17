package providers

import (
	"encoding/json"
	"fmt"
)

// jsonScalar accepts the string and numeric identifiers that some vendor
// APIs interchange, while preserving an opaque value for outgoing requests.
type jsonScalar string

func (s *jsonScalar) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*s = ""
		return nil
	}
	if len(data) == 0 {
		return fmt.Errorf("empty JSON scalar")
	}
	if data[0] == '"' {
		var value string
		if err := json.Unmarshal(data, &value); err != nil {
			return err
		}
		*s = jsonScalar(value)
		return nil
	}
	var number json.Number
	if err := json.Unmarshal(data, &number); err != nil {
		return err
	}
	*s = jsonScalar(number.String())
	return nil
}

func (s jsonScalar) String() string { return string(s) }
