// Package types — json_bytes.go defines a Gorm-friendly raw-JSON
// column type. json.RawMessage gets the JSON shape right but its
// sql.Scan implementation rejects driver.Value strings, which is
// exactly what SQLite hands back for TEXT-stored jsonb columns —
// surfaces as
//
//   unsupported Scan, storing driver.Value type string into type *json.RawMessage
//
// JSONBytes scans from both []byte and string and serialises through
// Marshal/Unmarshal as the raw JSON content (not as a quoted base64
// string the way []byte would), so a model field of type JSONBytes
// round-trips identically to json.RawMessage at the JSON layer while
// surviving SQLite TEXT reads at the SQL layer.

package types

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
)

// JSONBytes is a raw JSON payload usable as a Gorm column type
// across SQLite and Postgres. Drop-in replacement for json.RawMessage
// in storage models.
type JSONBytes []byte

// Scan implements sql.Scanner — accepts both []byte (Postgres bytea /
// jsonb) and string (SQLite TEXT). Empty / nil input becomes a nil
// JSONBytes so callers can distinguish "column present but JSON
// null" from "column absent".
func (b *JSONBytes) Scan(src any) error {
	if src == nil {
		*b = nil
		return nil
	}
	switch v := src.(type) {
	case []byte:
		buf := make([]byte, len(v))
		copy(buf, v)
		*b = buf
		return nil
	case string:
		*b = []byte(v)
		return nil
	default:
		return fmt.Errorf("JSONBytes.Scan: unsupported source type %T", src)
	}
}

// Value implements driver.Valuer — writes through as the raw bytes
// so the column stores valid JSON whether the backing type is TEXT,
// bytea, or jsonb.
func (b JSONBytes) Value() (driver.Value, error) {
	if b == nil {
		return nil, nil
	}
	return []byte(b), nil
}

// MarshalJSON serialises the stored payload verbatim — the contract
// is "this field IS the JSON", not "this field is bytes encoded as
// JSON". Empty payload becomes JSON null so the wire format stays
// consistent.
func (b JSONBytes) MarshalJSON() ([]byte, error) {
	if len(b) == 0 {
		return []byte("null"), nil
	}
	return b, nil
}

// UnmarshalJSON keeps a verbatim copy. Like json.RawMessage, we
// don't validate parseability — that's the caller's job at consume
// time, since we may be holding partial fragments mid-decode.
func (b *JSONBytes) UnmarshalJSON(data []byte) error {
	if b == nil {
		return errors.New("JSONBytes.UnmarshalJSON: nil receiver")
	}
	*b = append((*b)[:0], data...)
	return nil
}

// String returns the JSON payload as a string. Exists primarily so
// log statements + tests don't print byte-array notation.
func (b JSONBytes) String() string { return string(b) }

// Compile-time guards.
var (
	_ json.Marshaler   = JSONBytes(nil)
	_ json.Unmarshaler = (*JSONBytes)(nil)
	_ driver.Valuer    = JSONBytes(nil)
)
