//go:build mobile
// +build mobile

package lndmobile

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/chantools/btc"
	"github.com/lightninglabs/chantools/lnd"
	"github.com/lightningnetwork/lnd/aezeed"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

const (
	defaultAPIURL        = "https://api.node-recovery.com"
	defaultTestnetAPIURL = "https://blockstream.info/testnet/api"
	defaultRegtestAPIURL = "http://localhost:3004"

	sweepRemoteClosedDefaultRecoveryWindow = 200
	sweepDustLimit                         = 600
)

var (
	chainParams = &chaincfg.MainNetParams
)

type targetAddr struct {
	addr       btcutil.Address
	pubKey     *btcec.PublicKey
	path       string
	keyDesc    *keychain.KeyDescriptor
	vouts      []*btc.Vout
	script     []byte
	scriptTree *input.CommitScriptTree
}

func SweepRemoteClosed(seedPhrase string, apiURL,
	sweepAddr string, recoveryWindow int32, feeRate int32, sleepSeconds int32,
	publish bool, isTestnet bool) (string, error) {

	if isTestnet {
		chainParams = &chaincfg.TestNet3Params
	}

	cipherSeedMnemonic := strings.Split(seedPhrase, " ")

	var mnemonic aezeed.Mnemonic
	copy(mnemonic[:], cipherSeedMnemonic)

	passphraseBytes := []byte("")

	// If we're unable to map it back into the ciphertext, then either the
	// mnemonic is wrong, or the passphrase is wrong.
	cipherSeed, err := mnemonic.ToCipherSeed(passphraseBytes)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt "+
			"seed with passphrase: %w", err)
	}
	extendedKey, err := hdkeychain.NewMaster(cipherSeed.Entropy[:], chainParams)
	if err != nil {
		return "", fmt.Errorf("failed to derive " +
			"master extended key")
	}

	var estimator input.TxWeightEstimator
	sweepScript, err := lnd.PrepareWalletAddress(
		sweepAddr, chainParams, &estimator, extendedKey, "sweep",
	)
	if err != nil {
		return "", fmt.Errorf("Error preparing sweep address: %v", err)
	}

	var (
		targets []*targetAddr
		api     = newExplorerAPI(apiURL)
	)

	for index := range recoveryWindow {
		time.Sleep(time.Duration(sleepSeconds) * time.Second)
		path := fmt.Sprintf("m/1017'/%d'/%d'/0/%d",
			chainParams.HDCoinType, keychain.KeyFamilyPaymentBase,
			index)
		parsedPath, err := lnd.ParsePath(path)
		if err != nil {
			return "", fmt.Errorf("error parsing path: %w", err)
		}

		hdKey, err := lnd.DeriveChildren(
			extendedKey, parsedPath,
		)
		if err != nil {
			return "", fmt.Errorf("eror deriving children: %w", err)
		}

		privKey, err := hdKey.ECPrivKey()
		if err != nil {
			return "", fmt.Errorf("could not derive private "+
				"key: %w", err)
		}

		foundTargets, err := queryAddressBalances(
			privKey.PubKey(), path, &keychain.KeyDescriptor{
				PubKey: privKey.PubKey(),
				KeyLocator: keychain.KeyLocator{
					Family: keychain.KeyFamilyPaymentBase,
					Index:  uint32(index),
				},
			}, api,
		)
		if err != nil {
			return "", fmt.Errorf("could not query API for "+
				"addresses with funds: %w", err)
		}
		targets = append(targets, foundTargets...)
	}

	// Create estimator and transaction template.
	var (
		signDescs        []*input.SignDescriptor
		sweepTx          = wire.NewMsgTx(2)
		totalOutputValue = uint64(0)
		prevOutFetcher   = txscript.NewMultiPrevOutFetcher(nil)
	)

	// Add all found target outputs.
	for _, target := range targets {
		for _, vout := range target.vouts {
			totalOutputValue += vout.Value

			txHash, err := chainhash.NewHashFromStr(
				vout.Outspend.Txid,
			)
			if err != nil {
				return "", fmt.Errorf("error parsing tx hash: %w",
					err)
			}
			pkScript, err := lnd.GetWitnessAddrScript(
				target.addr, chainParams,
			)
			if err != nil {
				return "", fmt.Errorf("error getting pk script: %w",
					err)
			}

			prevOutPoint := wire.OutPoint{
				Hash:  *txHash,
				Index: uint32(vout.Outspend.Vin),
			}
			prevTxOut := &wire.TxOut{
				PkScript: pkScript,
				Value:    int64(vout.Value),
			}
			prevOutFetcher.AddPrevOut(prevOutPoint, prevTxOut)
			txIn := &wire.TxIn{
				PreviousOutPoint: prevOutPoint,
				Sequence:         wire.MaxTxInSequenceNum,
			}
			sweepTx.TxIn = append(sweepTx.TxIn, txIn)
			inputIndex := len(sweepTx.TxIn) - 1

			var signDesc *input.SignDescriptor
			switch target.addr.(type) {
			case *btcutil.AddressWitnessPubKeyHash:
				estimator.AddP2WKHInput()

				signDesc = &input.SignDescriptor{
					KeyDesc:           *target.keyDesc,
					WitnessScript:     target.script,
					Output:            prevTxOut,
					HashType:          txscript.SigHashAll,
					PrevOutputFetcher: prevOutFetcher,
					InputIndex:        inputIndex,
				}

			case *btcutil.AddressWitnessScriptHash:
				estimator.AddWitnessInput(
					input.ToRemoteConfirmedWitnessSize,
				)
				txIn.Sequence = 1

				signDesc = &input.SignDescriptor{
					KeyDesc:           *target.keyDesc,
					WitnessScript:     target.script,
					Output:            prevTxOut,
					HashType:          txscript.SigHashAll,
					PrevOutputFetcher: prevOutFetcher,
					InputIndex:        inputIndex,
				}

			case *btcutil.AddressTaproot:
				estimator.AddWitnessInput(
					input.TaprootToRemoteWitnessSize,
				)
				txIn.Sequence = 1

				tree := target.scriptTree
				controlBlock, err := tree.CtrlBlockForPath(
					input.ScriptPathSuccess,
				)
				if err != nil {
					return "", err
				}
				controlBlockBytes, err := controlBlock.ToBytes()
				if err != nil {
					return "", err
				}

				script := tree.SettleLeaf.Script
				signMethod := input.TaprootScriptSpendSignMethod
				signDesc = &input.SignDescriptor{
					KeyDesc:           *target.keyDesc,
					WitnessScript:     script,
					Output:            prevTxOut,
					HashType:          txscript.SigHashDefault,
					PrevOutputFetcher: prevOutFetcher,
					ControlBlock:      controlBlockBytes,
					InputIndex:        inputIndex,
					SignMethod:        signMethod,
					TapTweak:          tree.TapscriptRoot,
				}
			}

			signDescs = append(signDescs, signDesc)
		}
	}

	if len(targets) == 0 || totalOutputValue < sweepDustLimit {
		return "", fmt.Errorf("found %d sweep targets with total value "+
			"of %d satoshis which is below the dust limit of %d",
			len(targets), totalOutputValue, sweepDustLimit)
	}

	// Calculate the fee based on the given fee rate and our weight
	// estimation.
	feeRateKWeight := chainfee.SatPerKVByte(1000 * feeRate).FeePerKWeight()
	totalFee := feeRateKWeight.FeeForWeight(estimator.Weight())

	// fmt.Infof("Fee %d sats of %d total amount (estimated weight %d)",
	// 	totalFee, totalOutputValue, estimator.Weight())

	sweepTx.TxOut = []*wire.TxOut{{
		Value:    int64(totalOutputValue) - int64(totalFee),
		PkScript: sweepScript,
	}}

	// Sign the transaction now.
	var (
		signer = &lnd.Signer{
			ExtendedKey: extendedKey,
			ChainParams: chainParams,
		}
		sigHashes = txscript.NewTxSigHashes(sweepTx, prevOutFetcher)
	)
	for idx, desc := range signDescs {
		desc.SigHashes = sigHashes
		desc.InputIndex = idx

		switch {
		// Simple Taproot Channels.
		case desc.SignMethod == input.TaprootScriptSpendSignMethod:
			witness, err := input.TaprootCommitSpendSuccess(
				signer, desc, sweepTx, nil,
			)
			if err != nil {
				return "", err
			}
			sweepTx.TxIn[idx].Witness = witness

		// Anchor Channels.
		case len(desc.WitnessScript) > 0:
			witness, err := input.CommitSpendToRemoteConfirmed(
				signer, desc, sweepTx,
			)
			if err != nil {
				return "", err
			}
			sweepTx.TxIn[idx].Witness = witness

		// Static Remote Key Channels.
		default:
			// The txscript library expects the witness script of a
			// P2WKH descriptor to be set to the pkScript of the
			// output...
			desc.WitnessScript = desc.Output.PkScript
			witness, err := input.CommitSpendNoDelay(
				signer, desc, sweepTx, true,
			)
			if err != nil {
				return "", err
			}
			sweepTx.TxIn[idx].Witness = witness
		}
	}

	var buf bytes.Buffer
	err = sweepTx.Serialize(&buf)
	if err != nil {
		return "", err
	}

	// Publish TX.
	if publish {
		response, err := api.PublishTx(
			hex.EncodeToString(buf.Bytes()),
		)
		if err != nil {
			return "", err
		}
		fmt.Printf("Published TX %s, response: %s",
			sweepTx.TxHash().String(), response)
	}

	// fmt.Infof("Transaction: %x", buf.Bytes())
	return hex.EncodeToString(buf.Bytes()), nil
}

func queryAddressBalances(pubKey *btcec.PublicKey, path string,
	keyDesc *keychain.KeyDescriptor, api *btc.ExplorerAPI) ([]*targetAddr,
	error) {

	var targets []*targetAddr
	queryAddr := func(address btcutil.Address, script []byte,
		scriptTree *input.CommitScriptTree) error {

		unspent, err := api.Unspent(address.EncodeAddress())
		if err != nil {
			return fmt.Errorf("could not query unspent: %w", err)
		}

		if len(unspent) > 0 {
			// fmt.Infof("Found %d unspent outputs for address %v",
			// 	len(unspent), address.EncodeAddress())
			targets = append(targets, &targetAddr{
				addr:       address,
				pubKey:     pubKey,
				path:       path,
				keyDesc:    keyDesc,
				vouts:      unspent,
				script:     script,
				scriptTree: scriptTree,
			})
		}

		return nil
	}

	p2wkh, err := lnd.P2WKHAddr(pubKey, chainParams)
	if err != nil {
		return nil, err
	}
	if err := queryAddr(p2wkh, nil, nil); err != nil {
		return nil, err
	}

	p2anchor, script, err := lnd.P2AnchorStaticRemote(pubKey, chainParams)
	if err != nil {
		return nil, err
	}
	if err := queryAddr(p2anchor, script, nil); err != nil {
		return nil, err
	}

	p2tr, scriptTree, err := lnd.P2TaprootStaticRemote(pubKey, chainParams)
	if err != nil {
		return nil, err
	}
	if err := queryAddr(p2tr, nil, scriptTree); err != nil {
		return nil, err
	}

	return targets, nil
}

func newExplorerAPI(apiURL string) *btc.ExplorerAPI {
	// Override for testnet if default is used.
	if apiURL == defaultAPIURL &&
		chainParams.Name == chaincfg.TestNet3Params.Name {

		return &btc.ExplorerAPI{BaseURL: defaultTestnetAPIURL}
	}

	// Also override for regtest if default is used.
	if apiURL == defaultAPIURL &&
		chainParams.Name == chaincfg.RegressionNetParams.Name {

		return &btc.ExplorerAPI{BaseURL: defaultRegtestAPIURL}
	}

	// Otherwise use the provided URL.
	return &btc.ExplorerAPI{BaseURL: apiURL}
}
