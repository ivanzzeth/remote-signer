package evm

import (
	"encoding/json"
	"testing"
)

// FuzzSignRequestParsing fuzzes the JSON deserialization of sign requests.
// Goal: ensure malformed JSON never causes panics in request parsing.
func FuzzSignRequestParsing(f *testing.F) {
	// Seed corpus
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"chain_id":"1","signer_address":"0xabc","sign_type":"transaction","payload":{}}`))
	f.Add([]byte(`{"chain_id":"","signer_address":"","sign_type":"","payload":null}`))
	f.Add([]byte(`{"chain_id":1}`))                                                     // wrong type
	f.Add([]byte(`{"payload":"not-an-object"}`))                                         // payload as string
	f.Add([]byte(`{"payload":12345}`))                                                   // payload as number
	f.Add([]byte(`{"chain_id":"1","signer_address":"0x` + string(make([]byte, 10000)) + `"}`)) // oversized address
	f.Add([]byte("null"))
	f.Add([]byte("[]"))
	f.Add([]byte(""))
	f.Add([]byte(`{"sign_type":"unknown_type","payload":{"data":"0xdeadbeef"}}`))
	f.Add([]byte(`{"chain_id":"999999999999999","payload":{}}`))
	f.Add([]byte(`{"\x00":"\x00"}`)) // null bytes in keys

	f.Fuzz(func(t *testing.T, data []byte) {
		var req SignRequest
		// json.Unmarshal must never panic
		_ = json.Unmarshal(data, &req)

		// If parsing succeeds, validate that fields are accessible without panic
		_ = req.ChainID
		_ = req.SignerAddress
		_ = req.SignType
		_ = len(req.Payload)
	})
}

// FuzzSignRequestPayload fuzzes the payload field specifically with valid outer structure.
// Goal: test that the handler gracefully handles any payload content.
func FuzzSignRequestPayload(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"to":"0x5B38Da6a701c568545dCfcB03FcB875f56beddC4","value":"0x0","data":"0x"}`))
	f.Add([]byte(`{"message":"Hello World"}`))
	f.Add([]byte(`{"types":{"EIP712Domain":[]},"primaryType":"Permit","domain":{},"message":{}}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`"just a string"`))
	f.Add([]byte(`12345`))

	f.Fuzz(func(t *testing.T, payload []byte) {
		req := SignRequest{
			ChainID:       "1",
			SignerAddress: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
			SignType:      "transaction",
			Payload:       json.RawMessage(payload),
		}

		// Marshal/unmarshal round-trip must not panic
		data, err := json.Marshal(req)
		if err != nil {
			return // marshal failure is acceptable for weird payloads
		}

		var req2 SignRequest
		_ = json.Unmarshal(data, &req2)

		// Field access must not panic
		_ = req2.ChainID
		_ = req2.SignerAddress
		_ = req2.SignType
		_ = len(req2.Payload)
	})
}
