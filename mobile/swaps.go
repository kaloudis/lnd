//go:build mobile
// +build mobile

package lndmobile

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"

	"github.com/BoltzExchange/boltz-client/v2/pkg/boltz"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func leaf(script string) txscript.TapLeaf {
	decoded, _ := hex.DecodeString(script)
	return txscript.TapLeaf{
		LeafVersion: txscript.BaseLeafVersion,
		Script:      decoded,
	}
}

func CreateClaimTransaction(endpoint string, id string, claimLeaf string, refundLeaf string, privateKey string, servicePubKey string, transactionHash string, pubNonce string) error {
	swapTree := &boltz.SwapTree{
		ClaimLeaf:  leaf(claimLeaf),
		RefundLeaf: leaf(refundLeaf),
	}

	// Decode the hex string to bytes
	privKeyBytes, err := hex.DecodeString(privateKey)
	if err != nil {
		fmt.Printf("Failed to decode hex string: %v", err)
	}

	// Create the private key using btcec
	keys, _ := btcec.PrivKeyFromBytes(privKeyBytes)

	// Decode the hex string to bytes
	servicePubKeyBytes, err := hex.DecodeString(servicePubKey)
	if err != nil {
		return fmt.Errorf("Error decoding service public key hex: %s", err)
	}

	// Parse the public key
	servicePubKeyFormatted, err := secp256k1.ParsePubKey(servicePubKeyBytes)
	if err != nil {
		return fmt.Errorf("Error parsing service public key %s", err)
	}

	if err := swapTree.Init(boltz.CurrencyBtc, false, keys, servicePubKeyFormatted); err != nil {
		return fmt.Errorf("Error initializing swap tree %s", err)
	}

	session, err := boltz.NewSigningSession(swapTree)
	if err != nil {
		return fmt.Errorf("could not create signing session: %s", err)
	}
	partial, err := session.Sign([]byte(transactionHash), []byte(pubNonce))
	if err != nil {
		return fmt.Errorf("could not create partial signature: %s", err)
	}

	boltzApi := &boltz.Api{URL: endpoint}
	if err := boltzApi.SendSwapClaimSignature(id, partial); err != nil {
		return fmt.Errorf("could not send partial signature to Boltz: %s", err)
	}

	return nil
}

func CreateReverseClaimTransaction(endpoint string, id string, claimLeaf string, refundLeaf string, privateKey string, servicePubKey string, preimageHex string, transactionHex string, lockupAddress string, destinationAddress string, feeRate int32, minerFee int32, isTestnet bool) error {
	var toCurrency = boltz.CurrencyBtc
	var network *boltz.Network
	if isTestnet {
		network = boltz.TestNet
	} else {
		network = boltz.MainNet
	}

	boltzApi := &boltz.Api{URL: endpoint}

	// Decode the hex string to bytes
	privKeyBytes, err := hex.DecodeString(privateKey)
	if err != nil {
		fmt.Printf("Failed to decode hex string: %v", err)
	}

	// Create the private key using btcec
	keys, _ := btcec.PrivKeyFromBytes(privKeyBytes)

	// Decode the hex string to bytes
	servicePubKeyBytes, err := hex.DecodeString(servicePubKey)
	if err != nil {
		return fmt.Errorf("Error decoding service public key hex: %s", err)
	}

	// Parse the public key
	servicePubKeyFormatted, err := secp256k1.ParsePubKey(servicePubKeyBytes)
	if err != nil {
		return fmt.Errorf("Error parsing service public key %s", err)
	}

	swapTree := &boltz.SwapTree{
		ClaimLeaf:  leaf(claimLeaf),
		RefundLeaf: leaf(refundLeaf),
	}

	if err := swapTree.Init(boltz.CurrencyBtc, false, keys, servicePubKeyFormatted); err != nil {
		return fmt.Errorf("Error initializing swap tree %s", err)
	}

	lockupTransaction, err := boltz.NewTxFromHex(toCurrency, transactionHex, nil)
	if err != nil {
		return fmt.Errorf("Error constructing lockup tx %s", err)
	}

	vout, _, err := lockupTransaction.FindVout(network, lockupAddress)
	if err != nil {
		return fmt.Errorf("Error finding vout %s", err)
	}

	preimage, err := hex.DecodeString(preimageHex)
	if err != nil {
		return fmt.Errorf("Error decoding preimage hex string: %w", err)
	}

	var fee boltz.Fee
	if minerFee > 0 {
		sats := uint64(minerFee)
		fee = boltz.Fee{Sats: &sats}
	} else {
		satPerVbyte := float64(feeRate)
		fee = boltz.Fee{SatsPerVbyte: &satPerVbyte}
	}
	claimTransaction, _, err := boltz.ConstructTransaction(
		network,
		boltz.CurrencyBtc,
		[]boltz.OutputDetails{
			{
				SwapId:            id,
				SwapType:          boltz.ReverseSwap,
				Address:           destinationAddress,
				LockupTransaction: lockupTransaction,
				Vout:              vout,
				Preimage:          preimage,
				PrivateKey:        keys,
				SwapTree:          swapTree,
				Cooperative:       true,
			},
		},
		fee,
		boltzApi,
	)
	if err != nil {
		return fmt.Errorf("could not create claim transaction: %w", err)
	}

	txHex, err := claimTransaction.Serialize()
	if err != nil {
		return fmt.Errorf("could not serialize claim transaction: %w", err)
	}

	var broadcastUrl string
	if isTestnet {
		broadcastUrl = "https://mempool.space/testnet/api/tx"
	} else {
		broadcastUrl = "https://mempool.space/api/tx"
	}

	// Create HTTP request
	req, err := http.NewRequest("POST", broadcastUrl, bytes.NewBufferString(txHex))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Execute HTTP request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send HTTP request: %v", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("non-200 response: %d, body: %s", resp.StatusCode, string(body))
	}

	fmt.Printf("Transaction broadcasted successfully: %s\n", string(body))

	return nil
}

func CreateRefundTransaction(endpoint string, id string, claimLeaf string, refundLeaf string, transactionHex string, privateKey string, servicePubKey string, feeRate int32, timeoutBlockHeight int32, destinationAddress string, lockupAddress string, cooperative bool, isTestnet bool) (string, error) {
	var toCurrency = boltz.CurrencyBtc

	var network *boltz.Network
	if isTestnet {
		network = boltz.TestNet
	} else {
		network = boltz.MainNet
	}

	boltzApi := &boltz.Api{URL: endpoint}

	// Decode the hex string to bytes
	privKeyBytes, err := hex.DecodeString(privateKey)
	if err != nil {
		fmt.Printf("Failed to decode hex string: %v\n", err)
		return "", fmt.Errorf("failed to decode hex string: %v", err)
	}

	// Create the private key using btcec
	keys, _ := btcec.PrivKeyFromBytes(privKeyBytes)

	// Decode the hex string to bytes
	servicePubKeyBytes, err := hex.DecodeString(servicePubKey)
	if err != nil {
		return "", fmt.Errorf("error decoding service public key hex: %s", err)
	}

	// Parse the public key
	servicePubKeyFormatted, err := secp256k1.ParsePubKey(servicePubKeyBytes)
	if err != nil {
		return "", fmt.Errorf("error parsing service public key %s", err)
	}

	// Creating the swapTree
	swapTree := &boltz.SwapTree{
		ClaimLeaf:  leaf(claimLeaf),
		RefundLeaf: leaf(refundLeaf),
	}
	fmt.Println("SwapTree created successfully")

	if err := swapTree.Init(boltz.CurrencyBtc, false, keys, servicePubKeyFormatted); err != nil {
		return "", fmt.Errorf("error initializing swap tree %s", err)
	}

	satPerVbyte := float64(feeRate)

	lockupTransaction, err := boltz.NewTxFromHex(toCurrency, transactionHex, nil)
	if err != nil {
		return "", fmt.Errorf("error constructing lockup tx %v", err)
	}
	fmt.Println("Lockup transaction constructed successfully")

	vout, _, err := lockupTransaction.FindVout(network, lockupAddress)
	if err != nil {
		return "", fmt.Errorf("error finding vout %s", err)
	}

	refundTransaction, _, err := boltz.ConstructTransaction(
		network,
		boltz.CurrencyBtc,
		[]boltz.OutputDetails{
			{
				SwapId:             id,
				SwapType:           boltz.NormalSwap,
				Address:            destinationAddress,
				LockupTransaction:  lockupTransaction,
				Vout:               vout,
				Preimage:           []byte{},
				PrivateKey:         keys,
				TimeoutBlockHeight: uint32(timeoutBlockHeight),
				SwapTree:           swapTree,
				Cooperative:        cooperative,
			},
		},
		boltz.Fee{SatsPerVbyte: &satPerVbyte},
		boltzApi,
	)

	if err != nil {
		return "", fmt.Errorf("could not create refund transaction: %w", err)
	}
	fmt.Println("Refund transaction constructed successfully")

	txHex, err := refundTransaction.Serialize()
	if err != nil {
		return "", fmt.Errorf("could not serialize refund transaction: %w", err)
	}
	fmt.Println("Refund transaction serialized successfully")

	var broadcastUrl string
	if isTestnet {
		broadcastUrl = "https://mempool.space/testnet/api/tx"
	} else {
		broadcastUrl = "https://mempool.space/api/tx"
	}

	// Create HTTP request
	req, err := http.NewRequest("POST", broadcastUrl, bytes.NewBufferString(txHex))
	if err != nil {
		return "", fmt.Errorf("failed to create HTTP request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Execute HTTP request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send HTTP request: %v", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("non-200 response: %d, body: %s", resp.StatusCode, string(body))
	}

	txid := string(body)
	fmt.Printf("Transaction broadcasted successfully: %s\n", txid)
	fmt.Println("Transaction broadcasted successfully")

	return txid, nil
}
