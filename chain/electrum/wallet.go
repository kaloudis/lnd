package electrum

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcwallet/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/checksum0/go-electrum/electrum"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lncfg"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

// Wallet is an Electrum-backed implementation of the lnwallet interfaces.
// NOTE: This is currently a placeholder implementation.
type Wallet struct {
	cfg    *lncfg.ElectrumConfig   // Reference to Electrum config
	client *electrum.Client        // Electrum client connection
	netCfg *chaincfg.Params        // Network parameters
	masterKey *hdkeychain.ExtendedKey // Master HD key
	chainSource *ElectrumChainSource  // Reference to parent chain source

	mu              sync.Mutex // Protects derivation indexes
	externalKeyIdx  uint32     // Tracks the next external address index
	internalKeyIdx  uint32     // Tracks the next internal (change) address index
	accountKeyIdxes map[string]uint32 // Tracks indexes for named accounts (if needed)

	// TODO: Add fields for UTXO management/caching
}

// NewWallet creates a new, uninitialized instance of the Electrum Wallet.
// Key initialization happens later via InitUnencrypted.
func NewWallet(cfg *lncfg.ElectrumConfig, client *electrum.Client,
	netParams *chaincfg.Params, chainSource *ElectrumChainSource) (*Wallet, error) {

	// TODO: Load current derivation indexes from persistent storage if possible.
	// For now, starting from 0.

	return &Wallet{
		cfg:             cfg,
		client:          client,
		netCfg:          netParams,
		// masterKey is initialized later
		chainSource:     chainSource,
		externalKeyIdx:  0,
		internalKeyIdx:  0,
		accountKeyIdxes: make(map[string]uint32),
	}, nil
}

// InitUnencrypted initializes the wallet with the master HD key.
// TODO: Implement proper encrypted initialization later.
func (w *Wallet) InitUnencrypted(masterKey *hdkeychain.ExtendedKey) error {
	if masterKey == nil {
		return fmt.Errorf("master key cannot be nil for InitUnencrypted")
	}
	if w.masterKey != nil {
		return fmt.Errorf("wallet already initialized")
	}

	w.masterKey = masterKey
	ltndLog.Infof("Electrum wallet initialized with master key")

	// TODO: Load derivation indexes from storage here if persistence is added.

	return nil
}

// Interface implementations (Placeholders)

// lnwallet.WalletController placeholders

// FetchInputInfo retrieves the UTXO specified by the passed OutPoint.
func (w *Wallet) FetchInputInfo(prevOut *wire.OutPoint) (*lnwallet.Utxo, error) {
	// Use the chainSource's GetUtxo method. We don't have the pkScript
	// readily available here, so pass nil. GetUtxo should handle this.
	// We also don't have a height hint or cancel channel specific to this call.
	txOut, err := w.chainSource.GetUtxo(prevOut, nil, 0, nil)
	if err != nil {
		// TODO: Map errors correctly (e.g., to lnwallet.ErrUtxoNotFound)
		return nil, fmt.Errorf("failed to get utxo %s from chain source: %w", prevOut, err)
	}

	// Get current block height for confirmation status.
	_, currentHeight, err := w.chainSource.GetBestBlock()
	if err != nil {
		return nil, fmt.Errorf("failed to get best block height: %w", err)
	}

	// Determine confirmations. This is difficult with Electrum's GetTransaction
	// which only returns raw hex. We need the transaction's block height.
	// Fetching history for the script hash is possible but inefficient here.
	// TODO: Implement proper confirmation calculation, possibly by enhancing
	// GetTransaction in ElectrumChainSource or using a UTXO cache that stores height.
	// Returning 0 confirmations as a placeholder.
	confirmations := int64(0)
	ltndLog.Warnf("FetchInputInfo for %s returning placeholder confirmation count (0) "+
		"due to Electrum protocol limitations.", prevOut)

	// Construct the Utxo object.
	utxo := &lnwallet.Utxo{
		AddressType:   lnwallet.WitnessPubKey, // Assuming P2WPKH for now
		Value:         btcutil.Amount(txOut.Value),
		PkScript:      txOut.PkScript,
		Confirmations: confirmations,
		OutPoint:      *prevOut,
		// KeyDescriptor information is missing here. Need to derive/lookup.
		// KeyDescriptor: keychain.KeyDescriptor{...},
	}

	ltndLog.Warnf("FetchInputInfo returning UTXO %s with placeholder confirmations and missing KeyDescriptor", prevOut)

	return utxo, nil
}
// ListUnspentWitness returns all UTXOs paying to witness addresses (P2WPKH)
// controlled by the wallet, with at least minConfs confirmations.
// NOTE: This implementation queries the server for each address individually
// and can be inefficient for wallets with many addresses. A caching mechanism
// based on address subscriptions is recommended for production use.
func (w *Wallet) ListUnspentWitness(minConfs int32) ([]*lnwallet.Utxo, error) {
	ltndLog.Infof("Listing unspent witness outputs with min %d confs (inefficient scan)", minConfs)

	var utxos []*lnwallet.Utxo
	addressType := lnwallet.WitnessPubKey

	_, currentHeight, err := w.chainSource.GetBestBlock()
	if err != nil {
		return nil, fmt.Errorf("failed to get best block height: %w", err)
	}

	// Define a reasonable lookahead window.
	// TODO: Make this configurable or use gap limit logic.
	const lookahead = 20

	w.mu.Lock()
	externalIdx := w.externalKeyIdx
	internalIdx := w.internalKeyIdx
	w.mu.Unlock()

	// Scan external addresses
	for i := uint32(0); i < externalIdx+lookahead; i++ {
		keyLoc := keychain.KeyLocator{Family: keychain.KeyFamilyWitness, Index: i}
		utxosForKey, err := w.listUnspentForKey(keyLoc, addressType, minConfs, currentHeight)
		if err != nil {
			// Log error but continue scanning other keys
			ltndLog.Errorf("Failed to list unspent for key %v: %v", keyLoc, err)
			continue
		}
		utxos = append(utxos, utxosForKey...)
	}

	// Scan internal (change) addresses
	for i := uint32(0); i < internalIdx+lookahead; i++ {
		keyLoc := keychain.KeyLocator{Family: keychain.KeyFamilyWitnessChange, Index: i}
		utxosForKey, err := w.listUnspentForKey(keyLoc, addressType, minConfs, currentHeight)
		if err != nil {
			// Log error but continue scanning other keys
			ltndLog.Errorf("Failed to list unspent for key %v: %v", keyLoc, err)
			continue
		}
		utxos = append(utxos, utxosForKey...)
	}

	ltndLog.Infof("Found %d witness UTXOs with >= %d confs", len(utxos), minConfs)
	return utxos, nil
}

// listUnspentForKey fetches and processes UTXOs for a single derived key.
func (w *Wallet) listUnspentForKey(keyLoc keychain.KeyLocator, addrType lnwallet.AddressType,
	minConfs int32, currentHeight int32) ([]*lnwallet.Utxo, error) {

	keyDesc, err := w.DeriveKey(keyLoc)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key %v: %w", keyLoc, err)
	}

	// Create the P2WPKH address.
	addr, err := btcutil.NewAddressWitnessPubKeyHash(
		btcutil.Hash160(keyDesc.PubKey.SerializeCompressed()), w.netCfg,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create address for key %v: %w", keyLoc, err)
	}

	// Convert address pkScript to Electrum script hash format.
	pkScript, err := lnwallet.WitnessPubKeyHashToScript(addr.WitnessProgram())
	if err != nil {
		return nil, fmt.Errorf("failed to get pkScript for address %s: %w", addr, err)
	}
	electrumScriptHash := scriptHashToElectrumScriptHash(pkScript)

	// Query Electrum server for UTXOs for this script hash.
	ctx, cancel := context.WithTimeout(context.Background(), w.cfg.RequestTimeout)
	defer cancel()
	unspentList, err := w.client.ScriptHashListUnspent(ctx, electrumScriptHash)
	if err != nil {
		// Don't return error if script hash simply has no history/utxos
		// TODO: Check for specific Electrum "no history" errors if possible.
		ltndLog.Debugf("No history/utxos found for script hash %s (key %v) or error: %v",
			electrumScriptHash, keyLoc, err)
		return nil, nil // Treat as no UTXOs found for this key
	}

	var utxos []*lnwallet.Utxo
	for _, item := range unspentList {
		// Calculate confirmations. Height 0 means unconfirmed (mempool).
		var confirmations int64
		txHeight := int32(item.Height) // Electrum uses 0 for mempool
		if txHeight > 0 {
			confs := currentHeight - txHeight + 1
			// Handle potential reorgs or slightly stale currentHeight.
			if confs < 0 {
				ltndLog.Warnf("Negative confirmation count (%d) for UTXO %s:%d "+
					"(current height %d, tx height %d). Treating as 0 confs.",
					confs, item.TxHash, item.TxPos, currentHeight, txHeight)
				confs = 0
			}
			confirmations = int64(confs)
		} else {
			// Unconfirmed transaction.
			confirmations = 0
		}

		// Skip if not enough confirmations.
		if confirmations < int64(minConfs) {
			continue
		}

		// Parse the transaction hash.
		txHash, err := chainhash.NewHashFromStr(item.TxHash)
		if err != nil {
			ltndLog.Errorf("Failed to parse tx hash %s for utxo: %v", item.TxHash, err)
			continue
		}

		utxo := &lnwallet.Utxo{
			AddressType:   addrType,
			Value:         btcutil.Amount(item.Value),
			PkScript:      pkScript, // Store the derived pkScript
			Confirmations: confirmations,
			OutPoint: wire.OutPoint{
				Hash:  *txHash,
				Index: uint32(item.TxPos),
			},
			KeyDescriptor: keyDesc, // Store the derived key descriptor
		}
		utxos = append(utxos, utxo)
	}

	return utxos, nil
}

// ListTransactionDetails returns a list of all known transactions relevant to the wallet.
// TODO: Implement by fetching history for all known/derived addresses and parsing.
func (w *Wallet) ListTransactionDetails() ([]*lnwallet.TransactionDetail, error) {
	ltndLog.Warnf("ListTransactionDetails not implemented for electrum wallet")
	// This requires iterating through known addresses, fetching history for each,
	// fetching full transactions, and constructing detail objects. Very intensive.
	return nil, fmt.Errorf("ListTransactionDetails not implemented for electrum wallet")
}

// SubscribeTransactions returns a TransactionSubscription which delivers transaction
// notifications.
// TODO: Implement using script hash subscriptions and history processing.
func (w *Wallet) SubscribeTransactions() (*lnwallet.TransactionSubscription, error) {
	ltndLog.Warnf("SubscribeTransactions not implemented for electrum wallet")
	// This would require managing subscriptions for all wallet addresses and
	// translating script hash history updates into TxNotifications.
	return nil, fmt.Errorf("SubscribeTransactions not implemented for electrum wallet")
}

// ListAccounts retrieves all accounts belonging to the wallet by default.
// TODO: Implement proper account handling if needed beyond default.
func (w *Wallet) ListAccounts(name string, acctType lnwallet.AddressType) ([]*lnwallet.Account, error) {
	ltndLog.Warnf("ListAccounts not implemented for electrum wallet (returning default)")
	// For now, just return the default account structure if requested.
	if name != "" && name != lnwallet.DefaultAccountName {
		return nil, fmt.Errorf("named accounts not supported yet")
	}
	if acctType != lnwallet.WitnessPubKey {
		return nil, fmt.Errorf("only P2WKH accounts supported yet")
	}

	// Need to get current external/internal indexes.
	w.mu.Lock()
	externalIdx := w.externalKeyIdx
	internalIdx := w.internalKeyIdx
	w.mu.Unlock()

	// Return a single default account representation.
	return []*lnwallet.Account{
		{
			Name:             lnwallet.DefaultAccountName,
			AddressType:      acctType,
			ExternalKeyCount: externalIdx,
			InternalKeyCount: internalIdx,
			// LastUsedExternalIndex and LastUsedInternalIndex require tracking usage.
		},
	}, nil
}

// RequiredReserve specifies the minimum amount that should be reserved for
// anchor channel lock-in.
func (w *Wallet) RequiredReserve(numOutputs int) btcutil.Amount {
	// Since we don't manage channel anchors directly in this basic wallet,
	// return 0. This might need adjustment if used for anchor channels.
	ltndLog.Warnf("RequiredReserve returning 0 for electrum wallet")
	return 0
}

// PublishTransaction broadcasts a transaction to the network via the Electrum server.
func (w *Wallet) PublishTransaction(tx *wire.MsgTx, label string) error {
	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		return fmt.Errorf("failed to serialize transaction: %w", err)
	}
	rawTxHex := hex.EncodeToString(buf.Bytes())

	ctx, cancel := context.WithTimeout(context.Background(), w.cfg.RequestTimeout)
	defer cancel()

	// Broadcast the transaction using the Electrum client.
	// The label is not used by the Electrum protocol itself.
	txHashStr, err := w.client.BroadcastTransaction(ctx, rawTxHex)
	if err != nil {
		// TODO: Map specific Electrum broadcast errors if possible.
		return fmt.Errorf("failed to broadcast transaction via electrum: %w", err)
	}

	// Sanity check the returned hash.
	if txHashStr != tx.TxHash().String() {
		ltndLog.Warnf("Broadcasted tx hash mismatch: expected %s, got %s",
			tx.TxHash().String(), txHashStr)
	} else {
		ltndLog.Infof("Broadcasted transaction %s (label: %s)", txHashStr, label)
	}

	return nil
}
func (w *Wallet) IsSynced() (bool, int64, error) {
	// TODO: Check Electrum server sync status? Or rely on GetBestBlock?
	// For now, assume synced if connected.
	_, _, err := w.chainSource.GetBestBlock()
	if err != nil {
		return false, 0, fmt.Errorf("cannot get best block: %w", err)
	}
	// Return current block height as timestamp for compatibility?
	// Or just return true, 0? Let's return true, 0 for now.
	return true, 0, nil
}

// SendOutputs creates, signs, and broadcasts a transaction paying to the
// specified outputs with the given fee rate.
func (w *Wallet) SendOutputs(outputs []*wire.TxOut, feeRate chainfee.SatPerKWeight, label string) (*wire.MsgTx, error) {
	// Use P2WKH for change address type by default.
	// TODO: Make change address type configurable if needed.
	changeAddrType := lnwallet.WitnessPubKey

	// Create the unsigned transaction and get the selected inputs.
	tx, selectedInputs, err := w.CreateSimpleTx(outputs, feeRate, changeAddrType)
	if err != nil {
		return nil, fmt.Errorf("failed to create transaction: %w", err)
	}

	// Ensure we got the same number of selected inputs as tx inputs.
	if len(selectedInputs) != len(tx.TxIn) {
		return nil, fmt.Errorf("mismatch between selected inputs (%d) and tx inputs (%d)",
			len(selectedInputs), len(tx.TxIn))
	}

	// Create the sighash calculator.
	// TODO: Ensure Taproot sighashes are handled correctly if/when P2TR is supported.
	sigHashes := txscript.NewTxSigHashes(tx)

	// Sign each input.
	for i, txIn := range tx.TxIn {
		prevOut := &txIn.PreviousOutPoint

		// Fetch the UTXO details, including the KeyDescriptor.
		// FetchInputInfo currently returns placeholder confirmations and
		// might be missing the KeyDescriptor. We rely on ListUnspentWitness
		// having populated it correctly during CreateSimpleTx's call.
		// Get the UTXO details from the list returned by CreateSimpleTx.
		utxo := selectedInputs[i]

		// Ensure the selected UTXO matches the transaction input.
		if utxo.OutPoint != *prevOut {
			return nil, fmt.Errorf("input %d outpoint mismatch: tx has %s, selected utxo has %s",
				i, prevOut, utxo.OutPoint)
		}

		// Construct the SignDescriptor using the UTXO info.
		signDesc := &input.SignDescriptor{
			KeyDesc:       utxo.KeyDescriptor,
			WitnessScript: nil, // P2WKH has no witness script
			Output: &wire.TxOut{ // Reconstruct TxOut from Utxo info
				Value:    int64(utxo.Value),
				PkScript: utxo.PkScript,
			},
			InputIndex: uint32(i),
			SigHashes:  sigHashes,
			HashType:   txscript.SigHashAll, // Default sighash type
			// SingleTweak and DoubleTweak are nil for standard P2WKH
		}

		// Sign the input.
		sig, err := w.SignOutputRaw(tx, signDesc)
		if err != nil {
			return nil, fmt.Errorf("failed to sign input %d (%s): %w", i, prevOut, err)
		}

		// Compute the witness stack.
		inputScript, err := w.ComputeInputScript(tx, signDesc)
		if err != nil {
			return nil, fmt.Errorf("failed to compute input script for input %d (%s): %w", i, prevOut, err)
		}

		// Assign the generated witness.
		tx.TxIn[i].Witness = inputScript.Witness
	}

	// Broadcast the signed transaction.
	err = w.PublishTransaction(tx, label)
	if err != nil {
		return nil, fmt.Errorf("failed to publish transaction: %w", err)
	}

	return tx, nil
}

// CreateSimpleTx creates a transaction paying to the specified outputs, selecting
// inputs from the wallet's available UTXOs. A change output is created if
// necessary. It returns the created transaction and the list of UTXOs chosen
// as inputs.
func (w *Wallet) CreateSimpleTx(outputs []*wire.TxOut, feeRate chainfee.SatPerKWeight, changeAddrType lnwallet.AddressType) (*wire.MsgTx, []*lnwallet.Utxo, error) {
	// 1. Calculate total output amount.
	var totalOutputValue btcutil.Amount
	for _, output := range outputs {
		totalOutputValue += btcutil.Amount(output.Value)
	}

	// 2. List available UTXOs (0-conf for selection).
	// TODO: Consider using minConfs > 0 depending on requirements.
	availableUtxos, err := w.ListUnspentWitness(0)
	if err != nil {
		return nil, fmt.Errorf("failed to list unspent witness outputs: %w", err)
	}

	// Filter out UTXOs that don't have KeyDescriptor (needed for weight estimation).
	// Our current ListUnspentWitness implementation *does* include it.
	spendableUtxos := make([]*lnwallet.Utxo, 0, len(availableUtxos))
	for _, utxo := range availableUtxos {
		if utxo.KeyDescriptor.PubKey == nil {
			ltndLog.Warnf("Skipping UTXO %s without PubKey in KeyDescriptor", utxo.OutPoint)
			continue
		}
		spendableUtxos = append(spendableUtxos, utxo)
	}

	if len(spendableUtxos) == 0 {
		return nil, fmt.Errorf("wallet has no spendable witness outputs")
	}

	// 3. Coin Selection (simple largest-first strategy).
	// Sort UTXOs by value descending.
	sort.Slice(spendableUtxos, func(i, j int) bool {
		return spendableUtxos[i].Value > spendableUtxos[j].Value
	})

	var (
		selectedUtxos []*lnwallet.Utxo
		totalInputValue btcutil.Amount
		estimatedWeight int64
		feeEstimate     btcutil.Amount
	)

	// Add outputs to estimate weight.
	txOuts := make([]*wire.TxOut, len(outputs))
	copy(txOuts, outputs)

	// Loop through sorted UTXOs, adding them until output value + fee is covered.
	for _, utxo := range spendableUtxos {
		selectedUtxos = append(selectedUtxos, utxo)
		totalInputValue += utxo.Value

		// Estimate weight with current inputs and outputs (plus potential change).
		// Assume P2WKH inputs and a P2WKH change output for estimation.
		// TODO: Handle different input/output/change types more accurately.
		numInputs := len(selectedUtxos)
		numOutputs := len(txOuts) + 1 // +1 for potential change
		estimatedWeight = input.EstimateWitnessTxWeight(numInputs, numOutputs, false)

		// Calculate fee based on estimated weight.
		feeEstimate = feeRate.FeeForWeight(estimatedWeight)

		// Check if we have enough input value.
		if totalInputValue >= totalOutputValue+feeEstimate {
			break // Found enough inputs
		}
	}

	// Check if enough funds were selected.
	if totalInputValue < totalOutputValue+feeEstimate {
		return nil, fmt.Errorf("insufficient funds: needed %v, available %v",
			totalOutputValue+feeEstimate, totalInputValue)
	}

	// 4. Calculate Change.
	changeAmount := totalInputValue - totalOutputValue - feeEstimate
	var changeOutput *wire.TxOut

	// Use the exact weight now that we know if change is needed.
	numOutputsFinal := len(txOuts)
	if changeAmount > 0 { // TODO: Add proper dust limit check
		numOutputsFinal++
	}
	finalWeight := input.EstimateWitnessTxWeight(len(selectedUtxos), numOutputsFinal, false)
	finalFee := feeRate.FeeForWeight(finalWeight)

	// Recalculate change with the final fee.
	changeAmount = totalInputValue - totalOutputValue - finalFee
	if changeAmount > 0 { // TODO: Add proper dust limit check (e.g., input.DustLimit())
		ltndLog.Debugf("Change amount %v is above dust limit", changeAmount)
		changeAddr, err := w.NewAddress(changeAddrType, true, "") // Get a change address
		if err != nil {
			return nil, fmt.Errorf("failed to get change address: %w", err)
		}
		changePkScript, err := lnwallet.PayToAddrScript(changeAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to get change pkScript: %w", err)
		}
		changeOutput = &wire.TxOut{
			Value:    int64(changeAmount),
			PkScript: changePkScript,
		}
		ltndLog.Debugf("Created change output %s paying %v", changeAddr.String(), changeAmount)
	} else {
		ltndLog.Debugf("Change amount %v is dust or zero, not creating change output", changeAmount)
	}

	// 5. Construct the Transaction.
	tx := wire.NewMsgTx(wire.TxVersion)

	// Add inputs.
	for _, utxo := range selectedUtxos {
		tx.AddTxIn(wire.NewTxIn(&utxo.OutPoint, nil, nil))
	}

	// Add original outputs.
	for _, output := range outputs {
		tx.AddTxOut(output)
	}

	// Add change output if created.
	if changeOutput != nil {
		tx.AddTxOut(changeOutput)
	}

	// TODO: Implement BIP 69 input/output sorting?

	ltndLog.Infof("Created transaction %s paying %v with %d inputs (%v), %d outputs (%v), fee %v",
		tx.TxHash(), totalOutputValue, len(tx.TxIn), totalInputValue, len(tx.TxOut),
		totalOutputValue+changeAmount, finalFee)

	// Return the created transaction and the selected inputs.
	return tx, selectedUtxos, nil
}
// NewAddress derives and returns the next external or internal address based
// on the requested type and account.
func (w *Wallet) NewAddress(addrType lnwallet.AddressType, change bool, account string) (btcutil.Address, error) {
	// We only support P2WKH (SegWit v0) for now with BIP84 derivation.
	if addrType != lnwallet.WitnessPubKey {
		return nil, fmt.Errorf("unsupported address type: %v", addrType)
	}
	// TODO: Support named accounts if necessary.
	if account != "" && account != lnwallet.DefaultAccountName {
		return nil, fmt.Errorf("named accounts not yet supported for electrum wallet")
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	var (
		keyFam keychain.KeyFamily
		index  uint32
	)

	if change {
		keyFam = keychain.KeyFamilyWitnessChange
		index = w.internalKeyIdx
		w.internalKeyIdx++ // Increment for next time
	} else {
		keyFam = keychain.KeyFamilyWitness
		index = w.externalKeyIdx
		w.externalKeyIdx++ // Increment for next time
	}

	// TODO: Persist updated indexes.

	keyLoc := keychain.KeyLocator{
		Family: keyFam,
		Index:  index,
	}

	keyDesc, err := w.DeriveKey(keyLoc)
	if err != nil {
		// Decrement index on error? Need careful state management.
		// For now, log and return error.
		ltndLog.Errorf("Failed to derive key for new address (%v, %d): %v", keyFam, index, err)
		return nil, fmt.Errorf("failed to derive key for new address: %w", err)
	}

	// Create the P2WPKH address from the derived public key.
	addr, err := btcutil.NewAddressWitnessPubKeyHash(
		btcutil.Hash160(keyDesc.PubKey.SerializeCompressed()), w.netCfg,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create p2wpkh address: %w", err)
	}

	ltndLog.Infof("Generated new address: %s (type: %v, change: %v, index: %d)",
		addr.String(), addrType, change, index)

	return addr, nil
}

// LastUnusedAddress returns the last unused address of the specified type.
// TODO: Implement proper unused address tracking (requires querying history).
func (w *Wallet) LastUnusedAddress(addrType lnwallet.AddressType, account string) (btcutil.Address, error) {
	ltndLog.Warnf("LastUnusedAddress not implemented for electrum wallet (using NewAddress)")
	// This is incorrect, as it returns a *new* address, not the last *unused* one.
	// Proper implementation requires checking address history via Electrum.
	return w.NewAddress(addrType, false, account)
}

// IsOurAddress checks if the passed address belongs to this wallet.
// TODO: Implement by deriving addresses and checking, potentially with caching.
func (w *Wallet) IsOurAddress(a btcutil.Address) bool {
	ltndLog.Warnf("IsOurAddress not implemented for electrum wallet (returning false)")
	// This requires deriving a range of addresses and comparing, which can be slow.
	// A Bloom filter or address cache would be better.
	return false
}

// GenerateNewAccount creates a new account (not yet supported).
func (w *Wallet) GenerateNewAccount(name string) error {
	ltndLog.Warnf("GenerateNewAccount not implemented for electrum wallet")
	return fmt.Errorf("GenerateNewAccount not implemented for electrum wallet")
}
func (w *Wallet) Unlock(password []byte, timeout time.Duration) error {
	// TODO: Implement if wallet uses local encryption
	return fmt.Errorf("Unlock not implemented for electrum wallet")
}
func (w *Wallet) Lock() error {
	// TODO: Implement if wallet uses local encryption
	return fmt.Errorf("Lock not implemented for electrum wallet")
}
func (w *Wallet) ChangePassword(old []byte, new []byte) error {
	// TODO: Implement if wallet uses local encryption
	return fmt.Errorf("ChangePassword not implemented for electrum wallet")
}
func (w *Wallet) Start() error {
	// No background processes needed for this placeholder
	return nil
}
func (w *Wallet) Stop() error {
	// No background processes needed for this placeholder
	return nil
}
func (w *Wallet) BackEnd() string {
	return BackendName
}

// input.Signer implementations

// SignOutputRaw generates a signature for the specified input index using the
// private key derived from the KeyDescriptor and applying any necessary tweaks.
func (w *Wallet) SignOutputRaw(tx *wire.MsgTx, signDesc *input.SignDescriptor) (input.Signature, error) {
	witnessScript := signDesc.WitnessScript

	// First, we'll derive the private key that corresponds to the input
	// being signed.
	privKey, err := w.DerivePrivKey(signDesc.KeyDesc)
	if err != nil {
		return nil, err
	}

	// Apply any tweaks to the private key.
	privKey = input.TweakPrivKey(privKey, signDesc.SingleTweak, signDesc.DoubleTweak)

	// Check that the key corresponds to the PkScript in case this is a
	// witness output. Keys derived using DerivePrivKey should always be
	// compressed.
	pubKeyBytes := privKey.PubKey().SerializeCompressed()
	switch {
	// If this is a p2wkh output, the witness script is the encoded pubkey.
	case signDesc.Output.WitnessVersion == 0 &&
		len(witnessScript) == 0 &&
		signDesc.Output.PkScript != nil:

		pubKeyHash := btcutil.Hash160(pubKeyBytes)
		pkhAddr, err := btcutil.NewAddressWitnessPubKeyHash(
			pubKeyHash, w.netCfg,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to create p2wkh addr: %w", err)
		}

		pkScript, err := lnwallet.PayToAddrScript(pkhAddr)
		if err != nil {
			return nil, err
		}

		// Ensure that the derived key matches the output script.
		if !bytes.Equal(pkScript, signDesc.Output.PkScript) {
			return nil, fmt.Errorf("derived key mismatch")
		}

	// If this is a p2wsh output, the witness script is the hash of the
	// provided witness script.
	case signDesc.Output.WitnessVersion == 0 && len(witnessScript) > 0:
		scriptHash := sha256.Sum256(witnessScript)
		pkhAddr, err := btcutil.NewAddressWitnessScriptHash(
			scriptHash[:], w.netCfg,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to create p2wsh addr: %w", err)
		}

		pkScript, err := lnwallet.PayToAddrScript(pkhAddr)
		if err != nil {
			return nil, err
		}

		// Ensure that the derived key matches the output script.
		if !bytes.Equal(pkScript, signDesc.Output.PkScript) {
			return nil, fmt.Errorf("derived key mismatch")
		}

	// If this is a p2tr output, the witness script is the encoded
	// taproot output key.
	case signDesc.Output.WitnessVersion == 1:
		taprootKey := txscript.ComputeTaprootOutputKey(
			privKey.PubKey(), signDesc.TaprootRoot,
		)
		addr, err := btcutil.NewAddressTaproot(
			schnorr.SerializePubKey(taprootKey), w.netCfg,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to create p2tr addr: %w", err)
		}

		pkScript, err := lnwallet.PayToAddrScript(addr)
		if err != nil {
			return nil, err
		}

		// Ensure that the derived key matches the output script.
		if !bytes.Equal(pkScript, signDesc.Output.PkScript) {
			return nil, fmt.Errorf("derived key mismatch")
		}

	default:
		return nil, fmt.Errorf("unsupported witness type: %v",
			signDesc.Output.WitnessVersion)
	}

	// Generate the signature using the provided signature scheme.
	// TODO: Handle different sighash types if needed.
	sig, err := input.RawTxInWitnessSignature(
		tx, signDesc.SigHashes, signDesc.InputIndex,
		signDesc.Output.Value, witnessScript, signDesc.HashType, privKey,
	)
	if err != nil {
		return nil, err
	}

	return sig, nil
}
// ComputeInputScript generates the witness stack needed to redeem the specified
// output based on the SignDescriptor.
func (w *Wallet) ComputeInputScript(tx *wire.MsgTx, signDesc *input.SignDescriptor) (*input.Script, error) {
	// Derive the public key that corresponds to the input being signed.
	keyDesc, err := w.DeriveKey(signDesc.KeyDesc)
	if err != nil {
		return nil, err
	}
	pubKey := keyDesc.PubKey

	// Apply any tweaks to the public key.
	pubKey = input.TweakPubKey(pubKey, signDesc.SingleTweak, signDesc.DoubleTweak)

	switch {
	// If this is a p2wkh output then we'll return the witness stack that
	// consists of the signature and the compressed pubkey.
	case signDesc.Output.WitnessVersion == 0 && len(signDesc.WitnessScript) == 0:
		witnessStack, err := input.WitnessStackForRawKey(
			signDesc.SigHashes, signDesc.InputIndex,
			signDesc.Output.Value, signDesc.Output.PkScript,
			signDesc.HashType, pubKey,
		)
		if err != nil {
			return nil, err
		}

		return &input.Script{
			Witness: witnessStack,
		}, nil

	// If this is a p2wsh output then we'll return the witness stack that
	// consists of the signature and the witness script.
	case signDesc.Output.WitnessVersion == 0 && len(signDesc.WitnessScript) > 0:
		witnessStack, err := input.WitnessStack(
			signDesc.SigHashes, signDesc.InputIndex,
			signDesc.Output.Value, signDesc.Output.PkScript,
			signDesc.HashType, signDesc.WitnessScript, pubKey,
		)
		if err != nil {
			return nil, err
		}

		return &input.Script{
			Witness: witnessStack,
		}, nil

	// If this is a p2tr output then we'll return the witness stack that
	// consists of the signature.
	case signDesc.Output.WitnessVersion == 1:
		// TODO: Implement P2TR input script computation if needed.
		return nil, fmt.Errorf("p2tr script computation not yet implemented")

	default:
		return nil, fmt.Errorf("unsupported witness type: %v",
			signDesc.Output.WitnessVersion)
	}
}

// keychain.SecretKeyRing implementations

// DeriveNextKey derives the next key for the given family and returns its
// descriptor.
func (w *Wallet) DeriveNextKey(keyFam keychain.KeyFamily) (keychain.KeyDescriptor, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	var index uint32
	// TODO: Handle other key families if needed.
	switch keyFam {
	case keychain.KeyFamilyWitness:
		index = w.externalKeyIdx
		w.externalKeyIdx++
	case keychain.KeyFamilyWitnessChange:
		index = w.internalKeyIdx
		w.internalKeyIdx++
	default:
		return keychain.KeyDescriptor{},
			fmt.Errorf("unsupported key family: %v", keyFam)
	}

	// TODO: Persist updated index.

	keyLoc := keychain.KeyLocator{
		Family: keyFam,
		Index:  index,
	}

	// Use the existing DeriveKey implementation.
	return w.DeriveKey(keyLoc)
}
// deriveKey derives the extended key for a given KeyLocator.
func (w *Wallet) deriveKey(keyLoc keychain.KeyLocator) (*hdkeychain.ExtendedKey, error) {
	// TODO: Handle different key families if needed (multisig, etc.)
	// This currently assumes BIP84 paths (m/84'/coin_type'/account'/change/index)
	// and uses keyLoc.Family as the 'change' component (0=external, 1=internal)
	// and keyLoc.Index as the address index. Account is assumed 0 for now.

	if keyLoc.Family != keychain.KeyFamilyWitness && keyLoc.Family != keychain.KeyFamilyWitnessChange {
		return nil, fmt.Errorf("unsupported key family: %v", keyLoc.Family)
	}

	// m / purpose' / coin_type' / account' / change / index
	// m / 84' / coin_type' / 0' / family / index
	purpose := uint32(hdkeychain.HardenedKeyStart + 84)
	coinType := uint32(hdkeychain.HardenedKeyStart + w.netCfg.HDCoinType)
	account := uint32(hdkeychain.HardenedKeyStart + 0) // Assuming account 0
	change := uint32(keyLoc.Family)                    // 0 for external, 1 for internal
	index := keyLoc.Index

	// Derive the child key.
	key := w.masterKey
	path := []uint32{purpose, coinType, account, change, index}
	var err error
	for _, element := range path {
		key, err = key.Child(element)
		if err != nil {
			return nil, fmt.Errorf("failed to derive key for path %v: %w", path, err)
		}
	}

	return key, nil
}

// DeriveKey derives the public key descriptor for a given KeyLocator.
func (w *Wallet) DeriveKey(keyLoc keychain.KeyLocator) (keychain.KeyDescriptor, error) {
	derivedKey, err := w.deriveKey(keyLoc)
	if err != nil {
		return keychain.KeyDescriptor{}, err
	}

	pubKey, err := derivedKey.ECPubKey()
	if err != nil {
		return keychain.KeyDescriptor{}, fmt.Errorf("failed to get public key: %w", err)
	}

	return keychain.KeyDescriptor{
		KeyLocator: keyLoc,
		PubKey:     pubKey,
	}, nil
}

// DerivePrivKey derives the private key for a given KeyDescriptor.
func (w *Wallet) DerivePrivKey(keyDesc keychain.KeyDescriptor) (*btcec.PrivateKey, error) {
	derivedKey, err := w.deriveKey(keyDesc.KeyLocator)
	if err != nil {
		return nil, err
	}

	privKey, err := derivedKey.ECPrivKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get private key: %w", err)
	}

	// Sanity check: Ensure the derived private key matches the public key
	// in the descriptor if it was provided.
	if keyDesc.PubKey != nil && !privKey.PubKey().IsEqual(keyDesc.PubKey) {
		return nil, fmt.Errorf("derived private key does not match provided public key")
	}

	return privKey, nil
}

// ECDH performs a scalar multiplication (ECDH) between the private key specified
// by the key descriptor and the given public key.
// TODO: Implement ECDH.
func (w *Wallet) ECDH(keyDesc keychain.KeyDescriptor, pub *btcec.PublicKey) ([32]byte, error) {
	ltndLog.Warnf("ECDH not implemented for electrum wallet")
	// privKey, err := w.DerivePrivKey(keyDesc)
	// if err != nil {
	//	 return [32]byte{}, err
	// }
	// return btcec.GenerateSharedSecret(privKey, pub), nil
	return [32]byte{}, fmt.Errorf("ECDH not implemented for electrum wallet")
}

// SignMessage signs a double-sha256 digest of the message with the private key
// specified by the key locator.
// TODO: Implement SignMessage.
func (w *Wallet) SignMessage(keyLoc keychain.KeyLocator, message []byte, doubleHash bool) (*btcec.Signature, error) {
	ltndLog.Warnf("SignMessage not implemented for electrum wallet")
	// privKey, err := w.DerivePrivKey(keychain.KeyDescriptor{KeyLocator: keyLoc})
	// if err != nil {
	//	 return nil, err
	// }
	// var digest []byte
	// if doubleHash {
	//	 digest = chainhash.DoubleHashB(message)
	// } else {
	//	 digest = chainhash.HashB(message)
	// }
	// return privKey.Sign(digest)
	return nil, fmt.Errorf("SignMessage not implemented for electrum wallet")
}

// SignMessageCompact signs a double-sha256 digest of the message with the
// private key specified by the key locator and returns the signature in the
// compact, recoverable format.
// TODO: Implement SignMessageCompact.
func (w *Wallet) SignMessageCompact(keyLoc keychain.KeyLocator, message []byte, doubleHash bool) ([]byte, error) {
	ltndLog.Warnf("SignMessageCompact not implemented for electrum wallet")
	// privKey, err := w.DerivePrivKey(keychain.KeyDescriptor{KeyLocator: keyLoc})
	// if err != nil {
	//	 return nil, err
	// }
	// var digest []byte
	// if doubleHash {
	//	 digest = chainhash.DoubleHashB(message)
	// } else {
	//	 digest = chainhash.HashB(message)
	// }
	// return schnorr.SignCompact(privKey, digest) // Or ecdsa.SignCompact
	return nil, fmt.Errorf("SignMessageCompact not implemented for electrum wallet")
}

// Compile-time checks to ensure Wallet satisfies the interfaces (will fail until implemented).
// var _ lnwallet.WalletController = (*Wallet)(nil)
// var _ input.Signer = (*Wallet)(nil)
// var _ keychain.SecretKeyRing = (*Wallet)(nil)
