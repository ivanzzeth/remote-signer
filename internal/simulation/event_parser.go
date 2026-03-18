package simulation

import (
	"math/big"
	"strings"
)

// Well-known event topic0 hashes.
const (
	// ERC20 Transfer / ERC721 Transfer (same topic0, distinguished by topic count)
	transferTopic0 = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

	// ERC1155 TransferSingle
	transferSingleTopic0 = "0xc3d58168c5ae7397731d063d5bbf3d657706970af1fbf4d87d8d6f7c7cc0a0fa"

	// ERC1155 TransferBatch
	transferBatchTopic0 = "0x4a39dc06d4c0dbc64b70af90fd698a233a518aa5d07e595d9738d51b3ff80634"

	// WETH Deposit
	depositTopic0 = "0xe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c"

	// WETH Withdrawal
	withdrawalTopic0 = "0x7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65"

	// ERC20/ERC721 Approval
	approvalTopic0 = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"

	// ERC721 ApprovalForAll
	approvalForAllTopic0 = "0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31"
)

// Well-known calldata selectors for approval detection.
const (
	approveSelector            = "0x095ea7b3"
	setApprovalForAllSelector  = "0xa22cb465"
	increaseAllowanceSelector  = "0x39509351"
)

// ParseEvents parses token standard events from transaction receipt logs.
func ParseEvents(logs []txLog) []SimEvent {
	events := make([]SimEvent, 0, len(logs))

	for _, log := range logs {
		if len(log.Topics) == 0 {
			continue
		}

		topic0 := strings.ToLower(log.Topics[0])

		switch topic0 {
		case transferTopic0:
			event := parseTransferEvent(log)
			if event != nil {
				events = append(events, *event)
			}

		case transferSingleTopic0:
			event := parseTransferSingleEvent(log)
			if event != nil {
				events = append(events, *event)
			}

		case transferBatchTopic0:
			event := parseTransferBatchEvent(log)
			events = append(events, event...)

		case depositTopic0:
			event := parseDepositEvent(log)
			if event != nil {
				events = append(events, *event)
			}

		case withdrawalTopic0:
			event := parseWithdrawalEvent(log)
			if event != nil {
				events = append(events, *event)
			}

		case approvalTopic0:
			event := parseApprovalEvent(log)
			if event != nil {
				events = append(events, *event)
			}

		case approvalForAllTopic0:
			event := parseApprovalForAllEvent(log)
			if event != nil {
				events = append(events, *event)
			}
		}
	}

	return events
}

// parseTransferEvent parses ERC20 or ERC721 Transfer events.
// ERC20: 3 topics (topic0, from, to) + 32-byte data (value)
// ERC721: 4 topics (topic0, from, to, tokenId) + empty data
func parseTransferEvent(log txLog) *SimEvent {
	if len(log.Topics) == 3 {
		// ERC20 Transfer
		from := topicToAddress(log.Topics[1])
		to := topicToAddress(log.Topics[2])
		value := dataToHexValue(log.Data, 0)

		return &SimEvent{
			Address:  strings.ToLower(log.Address),
			Event:    "Transfer",
			Standard: "erc20",
			Args: map[string]string{
				"from":  from,
				"to":    to,
				"value": value,
			},
		}
	}

	if len(log.Topics) == 4 {
		// ERC721 Transfer
		from := topicToAddress(log.Topics[1])
		to := topicToAddress(log.Topics[2])
		tokenID := topicToUint256(log.Topics[3])

		return &SimEvent{
			Address:  strings.ToLower(log.Address),
			Event:    "Transfer",
			Standard: "erc721",
			Args: map[string]string{
				"from":    from,
				"to":      to,
				"tokenId": tokenID,
			},
		}
	}

	return nil
}

// parseTransferSingleEvent parses ERC1155 TransferSingle events.
// Topics: [topic0, operator (indexed), from (indexed), to (indexed)]
// Data: [id (uint256), value (uint256)]
func parseTransferSingleEvent(log txLog) *SimEvent {
	if len(log.Topics) < 4 {
		return nil
	}

	operator := topicToAddress(log.Topics[1])
	from := topicToAddress(log.Topics[2])
	to := topicToAddress(log.Topics[3])
	id := dataToHexValue(log.Data, 0)
	value := dataToHexValue(log.Data, 1)

	return &SimEvent{
		Address:  strings.ToLower(log.Address),
		Event:    "TransferSingle",
		Standard: "erc1155",
		Args: map[string]string{
			"operator": operator,
			"from":     from,
			"to":       to,
			"id":       id,
			"value":    value,
		},
	}
}

// parseTransferBatchEvent parses ERC1155 TransferBatch events.
// Topics: [topic0, operator (indexed), from (indexed), to (indexed)]
// Data: [ids (uint256[]), values (uint256[])]
func parseTransferBatchEvent(log txLog) []SimEvent {
	if len(log.Topics) < 4 {
		return nil
	}

	operator := topicToAddress(log.Topics[1])
	from := topicToAddress(log.Topics[2])
	to := topicToAddress(log.Topics[3])

	// Parse dynamic arrays from data
	data := trimHexPrefix(log.Data)
	ids, values := parseTransferBatchData(data)

	events := make([]SimEvent, 0, len(ids))
	for i := 0; i < len(ids) && i < len(values); i++ {
		events = append(events, SimEvent{
			Address:  strings.ToLower(log.Address),
			Event:    "TransferBatch",
			Standard: "erc1155",
			Args: map[string]string{
				"operator": operator,
				"from":     from,
				"to":       to,
				"id":       ids[i],
				"value":    values[i],
			},
		})
	}

	return events
}

// parseDepositEvent parses WETH Deposit events.
// Topics: [topic0, dst (indexed)]
// Data: [wad (uint256)]
func parseDepositEvent(log txLog) *SimEvent {
	if len(log.Topics) < 2 {
		return nil
	}

	dst := topicToAddress(log.Topics[1])
	wad := dataToHexValue(log.Data, 0)

	return &SimEvent{
		Address:  strings.ToLower(log.Address),
		Event:    "Deposit",
		Standard: "weth",
		Args: map[string]string{
			"dst": dst,
			"wad": wad,
		},
	}
}

// parseWithdrawalEvent parses WETH Withdrawal events.
// Topics: [topic0, src (indexed)]
// Data: [wad (uint256)]
func parseWithdrawalEvent(log txLog) *SimEvent {
	if len(log.Topics) < 2 {
		return nil
	}

	src := topicToAddress(log.Topics[1])
	wad := dataToHexValue(log.Data, 0)

	return &SimEvent{
		Address:  strings.ToLower(log.Address),
		Event:    "Withdrawal",
		Standard: "weth",
		Args: map[string]string{
			"src": src,
			"wad": wad,
		},
	}
}

// parseApprovalEvent parses ERC20/ERC721 Approval events.
func parseApprovalEvent(log txLog) *SimEvent {
	if len(log.Topics) < 3 {
		return nil
	}

	owner := topicToAddress(log.Topics[1])
	spender := topicToAddress(log.Topics[2])

	args := map[string]string{
		"owner":   owner,
		"spender": spender,
	}

	standard := "erc20"
	if len(log.Topics) == 4 {
		// ERC721 Approval has tokenId as 4th topic
		standard = "erc721"
		args["tokenId"] = topicToUint256(log.Topics[3])
	} else {
		args["value"] = dataToHexValue(log.Data, 0)
	}

	return &SimEvent{
		Address:  strings.ToLower(log.Address),
		Event:    "Approval",
		Standard: standard,
		Args:     args,
	}
}

// parseApprovalForAllEvent parses ERC721/ERC1155 ApprovalForAll events.
func parseApprovalForAllEvent(log txLog) *SimEvent {
	if len(log.Topics) < 3 {
		return nil
	}

	owner := topicToAddress(log.Topics[1])
	operator := topicToAddress(log.Topics[2])

	return &SimEvent{
		Address:  strings.ToLower(log.Address),
		Event:    "ApprovalForAll",
		Standard: "erc721",
		Args: map[string]string{
			"owner":    owner,
			"operator": operator,
		},
	}
}

// DetectApproval checks if the transaction or its events contain approvals.
func DetectApproval(events []SimEvent, calldata string) bool {
	// Check calldata selectors
	if len(calldata) >= 10 {
		selector := strings.ToLower(calldata[:10])
		if selector == approveSelector || selector == setApprovalForAllSelector || selector == increaseAllowanceSelector {
			return true
		}
	}

	// Check event logs for Approval / ApprovalForAll
	for _, event := range events {
		if event.Event == "Approval" || event.Event == "ApprovalForAll" {
			return true
		}
	}

	return false
}

// Helper functions for parsing hex data

// topicToAddress extracts an Ethereum address from a 32-byte topic (last 20 bytes).
func topicToAddress(topic string) string {
	topic = strings.ToLower(trimHexPrefix(topic))
	if len(topic) < 40 {
		return "0x" + topic
	}
	// Take last 40 hex chars (20 bytes)
	return "0x" + topic[len(topic)-40:]
}

// topicToUint256 converts a 32-byte topic to a decimal string.
func topicToUint256(topic string) string {
	hex := trimHexPrefix(topic)
	val := new(big.Int)
	val.SetString(hex, 16)
	return val.String()
}

// dataToHexValue extracts a uint256 value from ABI-encoded data at the given word index.
func dataToHexValue(data string, wordIndex int) string {
	hex := trimHexPrefix(data)
	start := wordIndex * 64
	if start+64 > len(hex) {
		return "0"
	}
	word := hex[start : start+64]
	val := new(big.Int)
	val.SetString(word, 16)
	return val.String()
}

// parseTransferBatchData parses the ids and values arrays from TransferBatch data.
func parseTransferBatchData(data string) (ids []string, values []string) {
	// ABI encoding: offset_ids(32) + offset_values(32) + len_ids(32) + ids... + len_values(32) + values...
	if len(data) < 128 { // minimum: 2 offsets
		return nil, nil
	}

	// Read offsets
	idsOffset := parseUint64FromHex(data[0:64])
	valuesOffset := parseUint64FromHex(data[64:128])

	ids = parseUint256Array(data, idsOffset*2)     // *2 because offsets are in bytes, data is hex chars
	values = parseUint256Array(data, valuesOffset*2)

	return ids, values
}

// parseUint256Array parses a dynamic uint256[] from ABI-encoded data at the given hex char offset.
func parseUint256Array(data string, hexOffset uint64) []string {
	if hexOffset+64 > uint64(len(data)) {
		return nil
	}

	length := parseUint64FromHex(data[hexOffset : hexOffset+64])
	result := make([]string, 0, length)

	for i := uint64(0); i < length; i++ {
		start := hexOffset + 64 + i*64
		if start+64 > uint64(len(data)) {
			break
		}
		val := new(big.Int)
		val.SetString(data[start:start+64], 16)
		result = append(result, val.String())
	}

	return result
}

// parseUint64FromHex parses a hex string as uint64.
func parseUint64FromHex(hex string) uint64 {
	val := new(big.Int)
	val.SetString(hex, 16)
	return val.Uint64()
}
