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

// swapNetwork maps a network name to boltz-client's parameters. Signet and
// testnet4 share testnet3's address encoding, which is all the claim and
// refund builders use the network for.
func swapNetwork(network string) (*boltz.Network, error) {
	switch network {
	case "mainnet", "bitcoin":
		return boltz.MainNet, nil
	case "testnet", "testnet3", "testnet4", "signet":
		return boltz.TestNet, nil
	case "regtest":
		return boltz.Regtest, nil
	default:
		return nil, fmt.Errorf("unsupported network %q", network)
	}
}

func legacyNetworkName(isTestnet bool) string {
	if isTestnet {
		return "testnet"
	}
	return "mainnet"
}

// swapKeysAndTree parses our private key and the service's public key and
// initializes the swap tree with them.
func swapKeysAndTree(claimLeaf string, refundLeaf string, privateKey string,
	servicePubKey string) (*btcec.PrivateKey, *boltz.SwapTree, error) {

	privKeyBytes, err := hex.DecodeString(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding private key hex: %w", err)
	}
	keys, _ := btcec.PrivKeyFromBytes(privKeyBytes)

	servicePubKeyBytes, err := hex.DecodeString(servicePubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding service public key hex: %w", err)
	}
	servicePubKeyFormatted, err := secp256k1.ParsePubKey(servicePubKeyBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing service public key: %w", err)
	}

	swapTree := &boltz.SwapTree{
		ClaimLeaf:  leaf(claimLeaf),
		RefundLeaf: leaf(refundLeaf),
	}
	if err := swapTree.Init(boltz.CurrencyBtc, false, keys, servicePubKeyFormatted); err != nil {
		return nil, nil, fmt.Errorf("error initializing swap tree: %w", err)
	}

	return keys, swapTree, nil
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
	transactionHashBytes, err := hex.DecodeString(transactionHash)
	if err != nil {
		return fmt.Errorf("Error decoding transaction hash hex: %s", err)
	}

	pubNonceBytes, err := hex.DecodeString(pubNonce)
	if err != nil {
		return fmt.Errorf("Error decoding pub nonce hex: %s", err)
	}

	partial, err := session.Sign(transactionHashBytes, pubNonceBytes)
	if err != nil {
		return fmt.Errorf("could not create partial signature: %s", err)
	}

	boltzApi := &boltz.Api{URL: endpoint}
	if err := boltzApi.SendSwapClaimSignature(id, partial); err != nil {
		return fmt.Errorf("could not send partial signature to Boltz: %s", err)
	}

	return nil
}

// BuildReverseClaimTransaction builds and signs the claim of a reverse swap's
// lockup and returns it as hex without broadcasting it. A cooperative claim
// sends the preimage to the swap host while building, so the caller must keep
// the returned transaction and keep broadcasting it until it confirms.
func BuildReverseClaimTransaction(endpoint string, id string, claimLeaf string, refundLeaf string, privateKey string, servicePubKey string, preimageHex string, transactionHex string, lockupAddress string, destinationAddress string, feeRate int32, minerFee int32, network string) (string, error) {
	chain, err := swapNetwork(network)
	if err != nil {
		return "", err
	}

	keys, swapTree, err := swapKeysAndTree(claimLeaf, refundLeaf, privateKey, servicePubKey)
	if err != nil {
		return "", err
	}

	lockupTransaction, err := boltz.NewTxFromHex(boltz.CurrencyBtc, transactionHex, nil)
	if err != nil {
		return "", fmt.Errorf("error constructing lockup tx: %w", err)
	}

	vout, _, err := lockupTransaction.FindVout(chain, lockupAddress)
	if err != nil {
		return "", fmt.Errorf("error finding vout: %w", err)
	}

	preimage, err := hex.DecodeString(preimageHex)
	if err != nil {
		return "", fmt.Errorf("error decoding preimage hex string: %w", err)
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
		chain,
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
		&boltz.Api{URL: endpoint},
	)
	if err != nil {
		return "", fmt.Errorf("could not create claim transaction: %w", err)
	}

	txHex, err := claimTransaction.Serialize()
	if err != nil {
		return "", fmt.Errorf("could not serialize claim transaction: %w", err)
	}

	return txHex, nil
}

// BuildRefundTransaction builds and signs the refund of a submarine swap's
// lockup and returns it as hex without broadcasting it.
func BuildRefundTransaction(endpoint string, id string, claimLeaf string, refundLeaf string, transactionHex string, privateKey string, servicePubKey string, feeRate int32, timeoutBlockHeight int32, destinationAddress string, lockupAddress string, cooperative bool, network string) (string, error) {
	chain, err := swapNetwork(network)
	if err != nil {
		return "", err
	}

	keys, swapTree, err := swapKeysAndTree(claimLeaf, refundLeaf, privateKey, servicePubKey)
	if err != nil {
		return "", err
	}

	lockupTransaction, err := boltz.NewTxFromHex(boltz.CurrencyBtc, transactionHex, nil)
	if err != nil {
		return "", fmt.Errorf("error constructing lockup tx: %w", err)
	}

	vout, _, err := lockupTransaction.FindVout(chain, lockupAddress)
	if err != nil {
		return "", fmt.Errorf("error finding vout: %w", err)
	}

	satPerVbyte := float64(feeRate)
	refundTransaction, _, err := boltz.ConstructTransaction(
		chain,
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
		&boltz.Api{URL: endpoint},
	)
	if err != nil {
		return "", fmt.Errorf("could not create refund transaction: %w", err)
	}

	txHex, err := refundTransaction.Serialize()
	if err != nil {
		return "", fmt.Errorf("could not serialize refund transaction: %w", err)
	}

	return txHex, nil
}

// broadcastToMempoolSpace is the broadcast the Create* functions have always
// done. Callers that can should use the Build* functions and broadcast
// through the user's own explorer instead.
func broadcastToMempoolSpace(txHex string, isTestnet bool) (string, error) {
	broadcastUrl := "https://mempool.space/api/tx"
	if isTestnet {
		broadcastUrl = "https://mempool.space/testnet/api/tx"
	}

	req, err := http.NewRequest("POST", broadcastUrl, bytes.NewBufferString(txHex))
	if err != nil {
		return "", fmt.Errorf("failed to create HTTP request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send HTTP request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("non-200 response: %d, body: %s", resp.StatusCode, string(body))
	}

	return string(body), nil
}

// CreateReverseClaimTransaction builds a reverse swap claim and broadcasts it
// to mempool.space. Kept for app builds that predate
// BuildReverseClaimTransaction.
func CreateReverseClaimTransaction(endpoint string, id string, claimLeaf string, refundLeaf string, privateKey string, servicePubKey string, preimageHex string, transactionHex string, lockupAddress string, destinationAddress string, feeRate int32, minerFee int32, isTestnet bool) error {
	txHex, err := BuildReverseClaimTransaction(endpoint, id, claimLeaf, refundLeaf, privateKey, servicePubKey, preimageHex, transactionHex, lockupAddress, destinationAddress, feeRate, minerFee, legacyNetworkName(isTestnet))
	if err != nil {
		return err
	}

	_, err = broadcastToMempoolSpace(txHex, isTestnet)
	return err
}

// CreateRefundTransaction builds a submarine swap refund, broadcasts it to
// mempool.space and returns the txid. Kept for app builds that predate
// BuildRefundTransaction.
func CreateRefundTransaction(endpoint string, id string, claimLeaf string, refundLeaf string, transactionHex string, privateKey string, servicePubKey string, feeRate int32, timeoutBlockHeight int32, destinationAddress string, lockupAddress string, cooperative bool, isTestnet bool) (string, error) {
	txHex, err := BuildRefundTransaction(endpoint, id, claimLeaf, refundLeaf, transactionHex, privateKey, servicePubKey, feeRate, timeoutBlockHeight, destinationAddress, lockupAddress, cooperative, legacyNetworkName(isTestnet))
	if err != nil {
		return "", err
	}

	return broadcastToMempoolSpace(txHex, isTestnet)
}
