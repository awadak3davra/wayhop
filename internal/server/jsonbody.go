package server

import (
	"encoding/json"
	"errors"
	"io"
)

// errTrailingJSON is a body that holds more than one JSON value.
var errTrailingJSON = errors.New("unexpected data after the JSON value")

// decodeJSONBody reads exactly one JSON value from a request body into v. A second value or trailing
// junk is an error: the write endpoints used to save the first document and drop the rest, answering 200
// to a body nobody meant (`{"name":"a"} {"name":"b"}` saved "a"). An empty body is io.EOF, as before.
func decodeJSONBody(body io.Reader, v any) error {
	dec := json.NewDecoder(body)
	if err := dec.Decode(v); err != nil {
		return err
	}
	var rest json.RawMessage
	if err := dec.Decode(&rest); !errors.Is(err, io.EOF) {
		return errTrailingJSON
	}
	return nil
}
