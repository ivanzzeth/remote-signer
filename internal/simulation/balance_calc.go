package simulation

import (
	"math/big"
	"strings"
)

// balanceKey uniquely identifies a token+tokenID combination.
type balanceKey struct {
	token   string // lowercase address or "native"
	tokenID string // decimal string, empty for fungibles
}

// ComputeBalanceChanges computes balance changes for a signer from parsed events and native value.
func ComputeBalanceChanges(events []SimEvent, from, to, value string) []BalanceChange {
	from = strings.ToLower(from)

	// Track changes per token
	changes := make(map[balanceKey]*big.Int)

	// Process native ETH transfer from tx.value
	if value != "" && value != "0x0" && value != "0x" && value != "0" {
		hexVal := trimHexPrefix(value)
		nativeAmount := new(big.Int)
		nativeAmount.SetString(hexVal, 16)
		if nativeAmount.Sign() > 0 {
			key := balanceKey{token: "native"}
			// From loses native value
			if _, ok := changes[key]; !ok {
				changes[key] = new(big.Int)
			}
			changes[key].Sub(changes[key], nativeAmount)
		}
	}

	// Process events
	for _, event := range events {
		switch event.Standard {
		case "erc20":
			processERC20Event(event, from, changes)
		case "erc721":
			processERC721Event(event, from, changes)
		case "erc1155":
			processERC1155Event(event, from, changes)
		case "weth":
			// WETH deposit/withdrawal is budget-neutral (ETH <-> WETH same value)
			// No balance change tracked
		}
	}

	// Convert to BalanceChange slice
	result := make([]BalanceChange, 0, len(changes))
	for key, amount := range changes {
		if amount.Sign() == 0 {
			continue // skip zero changes
		}

		direction := "inflow"
		if amount.Sign() < 0 {
			direction = "outflow"
		}

		bc := BalanceChange{
			Token:     key.token,
			Amount:    new(big.Int).Set(amount),
			Direction: direction,
		}

		// Set standard and tokenID
		if key.token == "native" {
			bc.Standard = "native"
		} else if key.tokenID != "" {
			// Could be ERC721 or ERC1155 - check events for the standard
			bc.Standard = findStandardForToken(events, key.token, key.tokenID)
			tokenID := new(big.Int)
			tokenID.SetString(key.tokenID, 10)
			bc.TokenID = tokenID
		} else {
			bc.Standard = "erc20"
		}

		result = append(result, bc)
	}

	return result
}

// processERC20Event processes an ERC20 Transfer event for balance changes.
func processERC20Event(event SimEvent, signerAddr string, changes map[balanceKey]*big.Int) {
	if event.Event != "Transfer" {
		return
	}

	eventFrom := strings.ToLower(event.Args["from"])
	eventTo := strings.ToLower(event.Args["to"])
	valueStr := event.Args["value"]

	amount := new(big.Int)
	amount.SetString(valueStr, 10)

	key := balanceKey{token: strings.ToLower(event.Address)}

	if eventFrom == signerAddr {
		if _, ok := changes[key]; !ok {
			changes[key] = new(big.Int)
		}
		changes[key].Sub(changes[key], amount)
	}

	if eventTo == signerAddr {
		if _, ok := changes[key]; !ok {
			changes[key] = new(big.Int)
		}
		changes[key].Add(changes[key], amount)
	}
}

// processERC721Event processes an ERC721 Transfer event for balance changes.
func processERC721Event(event SimEvent, signerAddr string, changes map[balanceKey]*big.Int) {
	if event.Event != "Transfer" {
		return
	}

	eventFrom := strings.ToLower(event.Args["from"])
	eventTo := strings.ToLower(event.Args["to"])
	tokenID := event.Args["tokenId"]

	key := balanceKey{token: strings.ToLower(event.Address), tokenID: tokenID}

	if eventFrom == signerAddr {
		if _, ok := changes[key]; !ok {
			changes[key] = new(big.Int)
		}
		changes[key].Sub(changes[key], big.NewInt(1))
	}

	if eventTo == signerAddr {
		if _, ok := changes[key]; !ok {
			changes[key] = new(big.Int)
		}
		changes[key].Add(changes[key], big.NewInt(1))
	}
}

// processERC1155Event processes an ERC1155 TransferSingle or TransferBatch event.
func processERC1155Event(event SimEvent, signerAddr string, changes map[balanceKey]*big.Int) {
	if event.Event != "TransferSingle" && event.Event != "TransferBatch" {
		return
	}

	eventFrom := strings.ToLower(event.Args["from"])
	eventTo := strings.ToLower(event.Args["to"])
	id := event.Args["id"]
	valueStr := event.Args["value"]

	amount := new(big.Int)
	amount.SetString(valueStr, 10)

	key := balanceKey{token: strings.ToLower(event.Address), tokenID: id}

	if eventFrom == signerAddr {
		if _, ok := changes[key]; !ok {
			changes[key] = new(big.Int)
		}
		changes[key].Sub(changes[key], amount)
	}

	if eventTo == signerAddr {
		if _, ok := changes[key]; !ok {
			changes[key] = new(big.Int)
		}
		changes[key].Add(changes[key], amount)
	}
}

// findStandardForToken finds the standard (erc721 or erc1155) for a non-fungible token.
func findStandardForToken(events []SimEvent, token, tokenID string) string {
	for _, e := range events {
		if strings.ToLower(e.Address) == token {
			if e.Args["tokenId"] == tokenID || e.Args["id"] == tokenID {
				return e.Standard
			}
		}
	}
	return "erc721" // default
}

// ComputeNetBalanceChanges aggregates balance changes across multiple simulation results for a signer.
func ComputeNetBalanceChanges(results []SimulationResult, signerAddr string) []BalanceChange {
	netChanges := make(map[balanceKey]*big.Int)

	for _, result := range results {
		for _, bc := range result.BalanceChanges {
			key := balanceKey{token: bc.Token}
			if bc.TokenID != nil {
				key.tokenID = bc.TokenID.String()
			}

			if _, ok := netChanges[key]; !ok {
				netChanges[key] = new(big.Int)
			}
			netChanges[key].Add(netChanges[key], bc.Amount)
		}
	}

	// Convert to slice
	result := make([]BalanceChange, 0, len(netChanges))
	for key, amount := range netChanges {
		if amount.Sign() == 0 {
			continue
		}

		direction := "inflow"
		if amount.Sign() < 0 {
			direction = "outflow"
		}

		bc := BalanceChange{
			Token:     key.token,
			Amount:    new(big.Int).Set(amount),
			Direction: direction,
		}

		if key.token == "native" {
			bc.Standard = "native"
		} else if key.tokenID != "" {
			bc.Standard = "erc1155" // default for non-fungible in aggregation
			tokenID := new(big.Int)
			tokenID.SetString(key.tokenID, 10)
			bc.TokenID = tokenID
		} else {
			bc.Standard = "erc20"
		}

		result = append(result, bc)
	}

	return result
}
