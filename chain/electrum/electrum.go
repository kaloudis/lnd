package electrum

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"crypto/sha256"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
	"github.com/checksum0/go-electrum/electrum"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/chainreg"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/routing/chainview"
	"github.com/lightningnetwork/lnd/lncfg"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

// Compile time check to ensure ElectrumChainSource satisfies the chain notifier
// and fee estimator interfaces. Other interfaces (chainio, chainview, mempool)
// are partially implemented or pending.
var _ chainntnfs.ChainNotifier = (*ElectrumChainSource)(nil)
var _ chainfee.Estimator = (*ElectrumChainSource)(nil)
var _ keychain.SecretKeyRing = (*ElectrumChainSource)(nil)
var _ input.Signer = (*ElectrumChainSource)(nil)
var _ lnwallet.WalletController = (*ElectrumChainSource)(nil) // Partially implemented
var _ lnwallet.BlockChainIO = (*ElectrumChainSource)(nil)     // Partially implemented (via chainio.Interface)

// var _ chain.Interface = (*ElectrumChainSource)(nil) // Partially done
var _ chainview.FilteredChainView = (*ElectrumChainSource)(nil) // Partially done
var _ chainntnfs.MempoolWatcher = (*ElectrumChainSource)(nil)   // Partially done
// var _ input.Signer = (*ElectrumChainSource)(nil) // Requires key management
// var _ keychain.SecretKeyRing = (*Wallet)(nil) // Requires key management

// BackendName is the name of this backend.
const BackendName = chainreg.ElectrumBackendName

var (
	// ErrUnimplemented is returned for features that are not yet
	// implemented.
	ErrUnimplemented = errors.New("unimplemented")
)

// blockEpochClient holds the state for a client subscribing to block epochs.
type blockEpochClient struct {
	id           uint64
	epochChan    chan *chainntnfs.BlockEpoch
	cancelChan   chan struct{}
	canceled     uint32 // atomic
	initialEpoch *chainntnfs.BlockEpoch
}

// scriptHashUpdate represents a status update received from an Electrum server
// for a subscribed script hash.
type scriptHashUpdate struct {
	scriptHash string
	status     string // Electrum protocol returns a status string (hash of history)
}

// confirmationClient holds the state for a client subscribing to transaction
// confirmations.
type confirmationClient struct {
	id            uint64
	txid          *chainhash.Hash
	pkScript      []byte
	numConfs      uint32
	heightHint    uint32
	event         *chainntnfs.ConfirmationEvent
	scriptHash    string // Electrum script hash format
	txFoundHeight int32  // Height where the tx was found, 0 if not found yet
}

// spendClient holds the state for a client subscribing to outpoint spends.
type spendClient struct {
	id         uint64
	outpoint   *wire.OutPoint
	pkScript   []byte
	heightHint uint32
	event      *chainntnfs.SpendEvent
	scriptHash string // Electrum script hash format
}

// ElectrumChainSource is a chain backend implementation that uses an Electrum
// server for chain data and notifications.
type ElectrumChainSource struct {
	// TODO: Add necessary fields like Electrum client, config, etc.
	cfg    *lncfg.ElectrumConfig
	client *electrum.Client

	// TODO: Add fields for managing subscriptions, fee estimation cache, etc.

	quit chan struct{}
	wg   sync.WaitGroup
}

// New creates a new ElectrumChainSource.
// TODO: This constructor needs to be filled out.
func New(cfg *lncfg.ElectrumConfig, netParams *chainreg.BitcoinNetParams) (*ElectrumChainSource, error) {
	// TODO: Establish connection to Electrum server using cfg.ServerAddr,
	// cfg.UseTLS, cfg.ConnectTimeout, etc.
	client := electrum.NewClient()
	ctx, cancel := context.WithTimeout(context.Background(), cfg.ConnectTimeout)
	defer cancel()

	var err error
	if cfg.UseTLS {
		// TODO: Handle TLS connection properly, including certificate validation
		// if cfg.ValidateServerCertificate is true.
		// For now, assuming ConnectTLS exists and handles this.
		// err = client.ConnectTLS(ctx, cfg.ServerAddr, tlsConfig)
		return nil, fmt.Errorf("TLS connection not yet implemented")
	} else {
		err = client.ConnectTCP(ctx, cfg.ServerAddr)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to connect to electrum server %s: %w", cfg.ServerAddr, err)
	}

	// TODO: Perform ServerVersion handshake?

	return &ElectrumChainSource{
		cfg:    cfg,
		client: client,
		quit:   make(chan struct{}),
	}, nil
}

// Start starts the ElectrumChainSource.
func (e *ElectrumChainSource) Start() error {
	// TODO: Start necessary goroutines for handling subscriptions, pings, etc.
	return nil
}

// Stop stops the ElectrumChainSource.
func (e *ElectrumChainSource) Stop() error {
	close(e.quit)
	e.wg.Wait()
	// TODO: Close Electrum client connection?
	// e.client.Shutdown()
	return nil
}

// GetBlock implements the chainio.Interface.
// NOTE: Electrum protocol does not typically support fetching full blocks by hash.
// Marked as unimplemented.
func (e *ElectrumChainSource) GetBlock(blockHash *chainhash.Hash) (*wire.MsgBlock, error) {
	return nil, ErrUnimplemented
}

// GetBlockHeader implements the chainio.Interface.
// NOTE: Electrum protocol primarily allows fetching headers by height, not hash.
// Implementing this efficiently might require maintaining a local hash-to-height
// mapping populated by the header subscription, or iterating backwards from the
// tip, both of which add complexity. Marked as unimplemented for now.
func (e *ElectrumChainSource) GetBlockHeader(blockHash *chainhash.Hash) (*wire.BlockHeader, error) {
	ltndLog.Debugf("GetBlockHeader called for %s (unimplemented)", blockHash)
	return nil, ErrUnimplemented
}

// GetBlockHash implements the chainio.Interface.
func (e *ElectrumChainSource) GetBlockHash(blockHeight int64) (*chainhash.Hash, error) {
	// Electrum uses uint for height, ensure non-negative.
	if blockHeight < 0 {
		return nil, fmt.Errorf("block height must be non-negative")
	}
	height := uint(blockHeight)

	ctx, cancel := context.WithTimeout(context.Background(), e.cfg.RequestTimeout)
	defer cancel()

	// Use the Electrum client to get the block header for the given height.
	// Note: go-electrum's BlockHeader method might return the header hex, not just the hash.
	// We need the hash. Let's assume client.BlockHeader returns the header info needed.
	// If go-electrum doesn't have a direct way, this might need adjustment.
	// Assuming client.BlockHeader(ctx, height) returns *electrum.BlockHeader object
	headerInfo, err := e.client.BlockHeader(ctx, height)
	if err != nil {
		// Handle potential errors, e.g., height out of range.
		return nil, fmt.Errorf("failed to get block header for height %d: %w", height, err)
	}

	// Assuming headerInfo contains the hex string of the block hash.
	hash, err := chainhash.NewHashFromStr(headerInfo.Hex)
	if err != nil {
		return nil, fmt.Errorf("failed to parse block hash %s for height %d: %w",
			headerInfo.Hex, height, err)
	}

	return hash, nil
}

// GetBestBlock implements the chainio.Interface.
// TODO: Implement using Electrum client (likely via block header subscription).
func (e *ElectrumChainSource) GetBestBlock() (*chainhash.Hash, int32, error) {
	return nil, 0, ErrUnimplemented
}

// GetUtxo implements the chainio.Interface. It fetches the transaction containing
// the outpoint and returns the specific TxOut.
func (e *ElectrumChainSource) GetUtxo(op *wire.OutPoint, pkScript []byte,
	heightHint uint32, cancel <-chan struct{}) (*wire.TxOut, error) {

	// Use a context that respects the cancel channel.
	ctx, ctxCancel := context.WithCancel(context.Background())
	defer ctxCancel()

	go func() {
		select {
		case <-cancel:
			ctxCancel()
		case <-ctx.Done():
		}
	}()

	// Use a timeout for the underlying transaction fetch.
	fetchCtx, fetchCancel := context.WithTimeout(ctx, e.cfg.RequestTimeout)
	defer fetchCancel()

	// Get the transaction using the existing GetTransaction method.
	// We need to wrap it in a function that respects the outer context/cancel.
	var tx *wire.MsgTx
	var err error
	txChan := make(chan struct{})
	go func() {
		tx, err = e.GetTransaction(&op.Hash)
		close(txChan)
	}()

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("GetUtxo canceled for outpoint %s", op)
	case <-fetchCtx.Done():
		// If the fetch context timed out before the main context, check which error occurred.
		if ctx.Err() != nil {
			return nil, fmt.Errorf("GetUtxo canceled for outpoint %s", op)
		}
		return nil, fmt.Errorf("GetTransaction timed out for outpoint %s", op)
	case <-txChan:
		// Transaction fetch completed (or errored).
	}

	if err != nil {
		// TODO: Map Electrum 'not found' errors to chain.ErrUtxoNotFound?
		return nil, fmt.Errorf("failed to get transaction %s for utxo: %w", op.Hash, err)
	}

	// Check if the index is valid for the transaction.
	if op.Index >= uint32(len(tx.TxOut)) {
		return nil, fmt.Errorf("invalid output index %d for tx %s", op.Index, op.Hash)
	}

	txOut := tx.TxOut[op.Index]

	// As a sanity check, ensure the pkScript matches if provided.
	// Electrum doesn't use pkScript for lookup, so this is a post-fetch check.
	if pkScript != nil && !bytes.Equal(txOut.PkScript, pkScript) {
		return nil, fmt.Errorf("pkScript mismatch for utxo %s", op)
	}

	return txOut, nil
}

// GetTransaction implements the chainio.Interface.
func (e *ElectrumChainSource) GetTransaction(txid *chainhash.Hash) (*wire.MsgTx, error) {
	ctx, cancel := context.WithTimeout(context.Background(), e.cfg.RequestTimeout)
	defer cancel()

	// Get the transaction hex from the Electrum server.
	txHex, err := e.client.GetTransactionHex(ctx, txid.String())
	if err != nil {
		// Handle errors, e.g., transaction not found.
		// TODO: Map Electrum errors to chainio/btcwallet errors if necessary.
		return nil, fmt.Errorf("failed to get transaction %s: %w", txid, err)
	}

	// Decode the hex string into a wire.MsgTx.
	txBytes, err := hex.DecodeString(txHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode transaction hex for %s: %w", txid, err)
	}

	var msgTx wire.MsgTx
	if err := msgTx.Deserialize(bytes.NewReader(txBytes)); err != nil {
		return nil, fmt.Errorf("failed to deserialize transaction %s: %w", txid, err)
	}

	// Verify the TxHash matches the requested txid.
	if *msgTx.TxHash() != *txid {
		return nil, fmt.Errorf("mismatch tx hash for txid %s (got %s)",
			txid, msgTx.TxHash())
	}

	return &msgTx, nil
}

// EstimateFeePerKW implements the chainfee.Estimator interface.
// TODO: Implement using Electrum client's EstimateFee.
func (e *ElectrumChainSource) EstimateFeePerKW(numBlocks uint32) (chainfee.SatPerKWeight, error) {
	return 0, ErrUnimplemented
}

// RelayFeePerKW implements the chainfee.Estimator interface.
// TODO: Determine how to get relay fee from Electrum, might need a default/fallback.
func (e *ElectrumChainSource) RelayFeePerKW() chainfee.SatPerKWeight {
	// Electrum protocol doesn't directly expose relay fee.
	// Return a reasonable default or fetch from another source if possible.
	return 253 // Default relay fee in sat/kw
}

// RegisterConfirmationsNtfn implements the chainntnfs.ChainNotifier interface.
func (e *ElectrumChainSource) RegisterConfirmationsNtfn(txid *chainhash.Hash,
	pkScript []byte, numConfs, heightHint uint32,
	options ...chainntnfs.NotifierOption) (*chainntnfs.ConfirmationEvent, error) {

	if numConfs == 0 {
		return nil, fmt.Errorf("number of confirmations must be > 0")
	}

	// Apply notifier options.
	ntfnOpts := chainntnfs.DefaultNotifierOptions()
	for _, opt := range options {
		opt(ntfnOpts)
	}

	// Create the event struct to be returned. The caller can use this to
	// cancel the notification or receive the event.
	event := &chainntnfs.ConfirmationEvent{
		Confirmed:  make(chan *chainntnfs.TxConfirmation, 1),
		CancelChan: make(chan struct{}),
		// CancelID will be assigned later.
	}

	electrumScriptHash := scriptHashToElectrumScriptHash(pkScript)

	// Ensure we are subscribed to this script hash.
	_, err := e.subscribeScriptHash(pkScript)
	if err != nil {
		return nil, fmt.Errorf("failed to subscribe script hash %s for conf "+
			"ntfn: %w", electrumScriptHash, err)
	}

	// Fetch initial history to check if already confirmed.
	ctx, cancel := context.WithTimeout(context.Background(), e.cfg.RequestTimeout)
	defer cancel()
	history, err := e.client.ScriptHashGetHistory(ctx, electrumScriptHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get history for script hash %s "+
			"for conf ntfn: %w", electrumScriptHash, err)
	}

	e.bestBlockMtx.RLock()
	currentHeight := e.bestBlock.Height
	currentHash := e.bestBlock.Hash
	e.bestBlockMtx.RUnlock()

	var txFoundHeight int32
	for _, item := range history {
		if item.TxHash == txid.String() {
			txHeight := int32(item.Height)
			if txHeight > 0 { // Found and confirmed
				txFoundHeight = txHeight
				confs := uint32(currentHeight - txHeight + 1)
				if confs >= numConfs {
					ltndLog.Infof("Tx %s already has %d confirmations "+
						"(current height %d, tx height %d), "+
						"dispatching confirmation immediately.",
						txid, confs, currentHeight, txHeight)

					// TODO: Need block hash for TxConfirmation.
					// Fetching the block header just for this might
					// be slow if GetBlockHeader remains unimplemented.
					// Using current best block hash as placeholder.
					confDetails := &chainntnfs.TxConfirmation{
						Tx:          nil, // Tx details not readily available
						BlockHash:   currentHash,
						BlockHeight: uint32(currentHeight),
						TxIndex:     0, // TxIndex not available
						// Block field requires fetching the block.
					}

					// Send confirmation non-blockingly.
					select {
					case event.Confirmed <- confDetails:
					default:
						ltndLog.Warnf("Receiver for tx %s conf "+
							"notification not ready", txid)
					}

					// Set CancelID to 1 to indicate immediate dispatch.
					atomic.StoreUint32(&event.CancelID, 1)

					// Return the event immediately.
					return event, nil
				}
				// Found but not enough confirmations yet.
				ltndLog.Debugf("Tx %s found at height %d, needs %d confs, "+
					"has %d", txid, txHeight, numConfs, confs)
			} else {
				// Found but unconfirmed.
				ltndLog.Debugf("Tx %s found but unconfirmed", txid)
			}
			// Found the tx, break history search.
			break
		}
	}

	// If we reach here, the tx is either not found or not confirmed enough.
	// Register the client for future notifications.
	e.scriptHashClientMtx.Lock()
	clientID := e.nextClientID
	e.nextClientID++
	event.CancelID = clientID // Assign the unique ID for cancellation.

	client := &confirmationClient{
		id:            clientID,
		txid:          txid,
		pkScript:      pkScript,
		numConfs:      numConfs,
		heightHint:    heightHint,
		event:         event,
		scriptHash:    electrumScriptHash,
		txFoundHeight: txFoundHeight, // Store height if found but not enough confs
	}

	e.confClientsByScriptHash[electrumScriptHash] = append(
		e.confClientsByScriptHash[electrumScriptHash], client,
	)
	e.scriptHashClientMtx.Unlock()

	ltndLog.Debugf("Registered confirmation notification for client %d, "+
		"txid %s, script hash %s, num_confs %d",
		clientID, txid, electrumScriptHash, numConfs)

	// Set up the cancellation logic.
	go func() {
		select {
		case <-event.CancelChan:
			ltndLog.Debugf("Confirmation notification cancelled by caller "+
				"for client %d, txid %s", client.id, client.txid)
			e.removeConfirmationClient(client.scriptHash, client.id)
		case <-e.quit:
			// Daemon shutting down. The main stop logic will handle cleanup.
		}
	}()

	return event, nil
}

// removeConfirmationClient removes a confirmation client from the internal maps.
// MUST be called with scriptHashClientMtx held.
func (e *ElectrumChainSource) removeConfirmationClient(scriptHash string, clientID uint64) {
	clients := e.confClientsByScriptHash[scriptHash]
	for i, c := range clients {
		if c.id == clientID {
			// Remove the client by slicing.
			e.confClientsByScriptHash[scriptHash] = append(clients[:i], clients[i+1:]...)
			ltndLog.Debugf("Removed confirmation client %d for script hash %s", clientID, scriptHash)

			// If no clients remain, consider unsubscribing.
			// if len(e.confClientsByScriptHash[scriptHash]) == 0 && len(e.spendClientsByScriptHash[scriptHash]) == 0 {
			//     delete(e.scriptHashSubscriptions, scriptHash)
			//     // TODO: Call Electrum unsubscribe method if available.
			//     ltndLog.Infof("Unsubscribed from script hash %s", scriptHash)
			// }
			return
		}
	}
	ltndLog.Warnf("Could not find confirmation client %d to remove for script hash %s", clientID, scriptHash)
}

// RegisterSpendNtfn implements the chainntnfs.ChainNotifier interface.
func (e *ElectrumChainSource) RegisterSpendNtfn(outpoint *wire.OutPoint, pkScript []byte,
	heightHint uint32) (*chainntnfs.SpendEvent, error) {

	// Create the event struct to be returned.
	event := &chainntnfs.SpendEvent{
		Spend:      make(chan *chainntnfs.SpendDetail, 1),
		CancelChan: make(chan struct{}),
		// CancelID will be assigned later.
	}

	electrumScriptHash := scriptHashToElectrumScriptHash(pkScript)

	// Ensure we are subscribed to this script hash.
	_, err := e.subscribeScriptHash(pkScript)
	if err != nil {
		return nil, fmt.Errorf("failed to subscribe script hash %s for spend "+
			"ntfn: %w", electrumScriptHash, err)
	}

	// Fetch initial history to check if already spent.
	ctx, cancel := context.WithTimeout(context.Background(), e.cfg.RequestTimeout)
	defer cancel()
	history, err := e.client.ScriptHashGetHistory(ctx, electrumScriptHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get history for script hash %s "+
			"for spend ntfn: %w", electrumScriptHash, err)
	}

	// Check history for a spending transaction.
	for _, item := range history {
		// Fetch the full transaction details.
		spendingTx, err := e.GetTransaction(&item.TxHash)
		if err != nil {
			ltndLog.Warnf("Failed to get tx %s while checking spend "+
				"for %s: %v", item.TxHash, outpoint, err)
			continue // Skip this history item if we can't fetch it
		}

		// Check if any input matches the target outpoint.
		for i, txIn := range spendingTx.TxIn {
			if txIn.PreviousOutPoint == *outpoint {
				ltndLog.Infof("Outpoint %s already spent by tx %s, "+
					"dispatching spend notification immediately.",
					outpoint, item.TxHash)

				spendDetails := &chainntnfs.SpendDetail{
					SpentOutPoint:     outpoint,
					SpenderTxHash:     &item.TxHash,
					SpendingTx:        spendingTx,
					SpenderInputIndex: uint32(i),
					SpendingHeight:    int32(item.Height), // Can be 0 if mempool spend
				}

				// Send notification non-blockingly.
				select {
				case event.Spend <- spendDetails:
				default:
					ltndLog.Warnf("Receiver for outpoint %s spend "+
						"notification not ready", outpoint)
				}

				// Set CancelID to 1 to indicate immediate dispatch.
				atomic.StoreUint32(&event.CancelID, 1)

				// Return the event immediately.
				return event, nil
			}
		}
	}

	// If we reach here, the outpoint is not spent yet.
	// Register the client for future notifications.
	e.scriptHashClientMtx.Lock()
	clientID := e.nextClientID
	e.nextClientID++
	event.CancelID = clientID // Assign the unique ID for cancellation.

	client := &spendClient{
		id:         clientID,
		outpoint:   outpoint,
		pkScript:   pkScript,
		heightHint: heightHint,
		event:      event,
		scriptHash: electrumScriptHash,
	}

	e.spendClientsByScriptHash[electrumScriptHash] = append(
		e.spendClientsByScriptHash[electrumScriptHash], client,
	)
	e.scriptHashClientMtx.Unlock()

	ltndLog.Debugf("Registered spend notification for client %d, "+
		"outpoint %s, script hash %s",
		clientID, outpoint, electrumScriptHash)

	// Set up the cancellation logic.
	go func() {
		select {
		case <-event.CancelChan:
			ltndLog.Debugf("Spend notification cancelled by caller "+
				"for client %d, outpoint %s", client.id, client.outpoint)
			e.removeSpendClient(client.scriptHash, client.id)
		case <-e.quit:
			// Daemon shutting down. The main stop logic will handle cleanup.
		}
	}()

	return event, nil
}

// removeSpendClient removes a spend client from the internal maps.
// MUST be called with scriptHashClientMtx held.
func (e *ElectrumChainSource) removeSpendClient(scriptHash string, clientID uint64) {
	clients := e.spendClientsByScriptHash[scriptHash]
	for i, c := range clients {
		if c.id == clientID {
			// Remove the client by slicing.
			e.spendClientsByScriptHash[scriptHash] = append(clients[:i], clients[i+1:]...)
			ltndLog.Debugf("Removed spend client %d for script hash %s", clientID, scriptHash)

			// If no clients remain, consider unsubscribing.
			// if len(e.confClientsByScriptHash[scriptHash]) == 0 && len(e.spendClientsByScriptHash[scriptHash]) == 0 {
			//     delete(e.scriptHashSubscriptions, scriptHash)
			//     // TODO: Call Electrum unsubscribe method if available.
			//     ltndLog.Infof("Unsubscribed from script hash %s", scriptHash)
			// }
			return
		}
	}
	ltndLog.Warnf("Could not find spend client %d to remove for script hash %s", clientID, scriptHash)
}

// RegisterBlockEpochNtfn implements the chainntnfs.ChainNotifier interface.
func (e *ElectrumChainSource) RegisterBlockEpochNtfn(
	initialEpoch *chainntnfs.BlockEpoch) (*chainntnfs.BlockEpochEvent, error) {

	e.blockEpochClientMtx.Lock()
	defer e.blockEpochClientMtx.Unlock()

	clientID := e.nextBlockEpochClientID
	e.nextBlockEpochClientID++

	client := &blockEpochClient{
		id:           clientID,
		epochChan:    make(chan *chainntnfs.BlockEpoch, 1), // Buffer 1 for immediate delivery
		cancelChan:   make(chan struct{}),
		initialEpoch: initialEpoch,
	}

	e.blockEpochClients[clientID] = client

	epochEvent := &chainntnfs.BlockEpochEvent{
		Epochs: client.epochChan,
		Cancel: func() {
			// Signal cancellation to the handler goroutine.
			close(client.cancelChan)

			// Mark client as canceled atomically.
			atomic.StoreUint32(&client.canceled, 1)

			// Remove the client from the map.
			e.blockEpochClientMtx.Lock()
			delete(e.blockEpochClients, client.id)
			e.blockEpochClientMtx.Unlock()

			ltndLog.Debugf("Cancelled block epoch notification for client %d", client.id)
		},
	}

	// If the client provided an initial epoch, check if we need to send
	// the current best block immediately.
	if initialEpoch != nil {
		e.bestBlockMtx.RLock()
		currentBest := e.bestBlock
		e.bestBlockMtx.RUnlock()

		// If the client's known height is lower than ours, send ours.
		if initialEpoch.Height < currentBest.Height {
			// Use non-blocking send in case the client cancels immediately.
			select {
			case client.epochChan <- &currentBest:
			case <-client.cancelChan:
				atomic.StoreUint32(&client.canceled, 1)
				delete(e.blockEpochClients, client.id) // Need lock again? No, already removed in Cancel.
			case <-e.quit:
			}
		}
	}

	ltndLog.Debugf("Registered new block epoch notification client %d", client.id)

	return epochEvent, nil
}

// scriptHashToElectrumScriptHash converts a Bitcoin script (pkScript) into the
// format required by the Electrum protocol (sha256 hash, reversed, hex-encoded).
func scriptHashToElectrumScriptHash(pkScript []byte) string {
	// 1. Calculate SHA256 hash of the script.
	scriptHashBytes := sha256.Sum256(pkScript)

	// 2. Reverse the byte order. Electrum uses little-endian for script hashes.
	for i, j := 0, len(scriptHashBytes)-1; i < j; i, j = i+1, j-1 {
		scriptHashBytes[i], scriptHashBytes[j] = scriptHashBytes[j], scriptHashBytes[i]
	}

	// 3. Encode the reversed hash as a hexadecimal string.
	return hex.EncodeToString(scriptHashBytes[:])
}

// notificationHandler processes incoming messages from the Electrum client,
// identifying and handling relevant notifications like script hash status changes.
// NOTE: This function's implementation depends heavily on how the go-electrum
// client exposes incoming messages (e.g., via a Listen() method or callbacks).
// The following is a conceptual implementation assuming a blocking Listen method
// that provides notifications.
func (e *ElectrumChainSource) notificationHandler() {
	defer e.wg.Done()

	ltndLog.Info("Starting Electrum notification handler")
	defer ltndLog.Info("Stopped Electrum notification handler")

	// Create a context that we can cancel from the main shutdown signal.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-e.quit
		ltndLog.Info("Notification handler shutting down...")
		cancel()
	}()

	// TODO: Replace this with the actual mechanism from go-electrum.
	// This might be client.Listen(ctx) or involve setting callbacks before
	// starting a client run loop.
	// We assume Listen blocks until context is cancelled or an error occurs.
	// We also assume it internally handles different notification types
	// and we can somehow hook into it or parse its output.

	// --- Conceptual Example ---
	// err := e.client.Listen(ctx, func(notification interface{}) {
	//	 switch ntf := notification.(type) {
	//	 case *electrum.ScriptHashSubscription: // Assuming this type exists
	//		 e.handleScriptHashUpdate(ntf.ScriptHash, ntf.Status)
	//	 case *electrum.BlockHeader: // Header updates might also come here
	//		 // Handle header updates if not handled by headerSubscriptionHandler
	//		 ltndLog.Debugf("Received header via main listener: %v", ntf)
	//	 default:
	//		 ltndLog.Warnf("Received unknown notification type: %T", ntf)
	//	 }
	// })
	// if err != nil && !errors.Is(err, context.Canceled) {
	//	 ltndLog.Errorf("Electrum client Listen exited with error: %v", err)
	//	 // TODO: Trigger reconnection or shutdown?
	// }
	// --- End Conceptual Example ---

	// Since the actual mechanism is unknown, we just wait for quit for now.
	// The warning below highlights that this needs implementation.
	ltndLog.Warnf("Electrum notificationHandler needs implementation " +
		"based on go-electrum's message handling API (client.Listen?)")
// keepaliveHandler periodically pings the Electrum server to maintain the
// connection and detect potential disconnections.
func (e *ElectrumChainSource) keepaliveHandler() {
	defer e.wg.Done()

	// Use a ticker for periodic pings. A 1-minute interval is usually safe.
	// TODO: Make this interval configurable?
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	ltndLog.Info("Starting Electrum keepalive handler")
	defer ltndLog.Info("Stopped Electrum keepalive handler")

	for {
		select {
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), e.cfg.RequestTimeout)
			err := e.client.Ping(ctx)
			cancel() // Release context resources promptly
			if err != nil {
				// Log the error. Depending on the error type, we might
				// want to trigger reconnection logic here in the future.
				ltndLog.Warnf("Electrum keepalive ping failed: %v", err)
				// TODO: Implement reconnection logic if ping fails consistently?
			} else {
				ltndLog.Debugf("Electrum keepalive ping successful")
			}

		case <-e.quit:
			return
		}
	}
}

// handleScriptHashUpdate processes a status change notification for a specific
// script hash. It fetches the latest history and dispatches notifications.
func (e *ElectrumChainSource) handleScriptHashUpdate(scriptHash, newStatus string) {
	e.scriptHashClientMtx.Lock()
	currentStatus, subscribed := e.scriptHashSubscriptions[scriptHash]
	if !subscribed {
		ltndLog.Warnf("Received status update for unsubscribed script hash %s", scriptHash)
		e.scriptHashClientMtx.Unlock()
		return
	}

	// If status hasn't changed, nothing to do.
	if newStatus == currentStatus {
		e.scriptHashClientMtx.Unlock()
		return
	}

	// Status changed, update our record.
	e.scriptHashSubscriptions[scriptHash] = newStatus
	hasConfClients := len(e.confClientsByScriptHash[scriptHash]) > 0
	hasSpendClients := len(e.spendClientsByScriptHash[scriptHash]) > 0
	e.scriptHashClientMtx.Unlock() // Unlock before potentially long call

	// If no clients are interested, we still update the status but don't need
	// to fetch history.
	if !hasConfClients && !hasSpendClients {
		ltndLog.Debugf("Status updated for script hash %s, but no clients registered", scriptHash)
		return
	}

	ltndLog.Infof("Status changed for script hash %s, fetching history...", scriptHash)

	// Fetch the latest history for this script hash.
	ctx, cancel := context.WithTimeout(context.Background(), e.cfg.RequestTimeout)
	defer cancel()
	history, err := e.client.ScriptHashGetHistory(ctx, scriptHash)
	if err != nil {
		ltndLog.Errorf("Failed to get history for script hash %s after status update: %v", scriptHash, err)
		return
	}

	// Process the history and notify relevant clients.
	e.processScriptHistory(scriptHash, history)
}

// processScriptHistory iterates through the history of a script hash and
// notifies relevant confirmation and spend clients.
func (e *ElectrumChainSource) processScriptHistory(scriptHash string,
	history electrum.HistoryResult) {

	e.scriptHashClientMtx.Lock()
	confClients := e.confClientsByScriptHash[scriptHash]
	spendClients := e.spendClientsByScriptHash[scriptHash]
	e.scriptHashClientMtx.Unlock()

	e.bestBlockMtx.RLock()
	currentHeight := e.bestBlock.Height
	e.bestBlockMtx.RUnlock()

	// Keep track of clients to remove after processing.
	var confirmedClientsToRemove []uint64
	var spentClientsToRemove []uint64

	ltndLog.Debugf("Processing history for script hash %s (%d items)",
		scriptHash, len(history))

	// --- Process Confirmation Notifications ---
	ltndLog.Debugf("Checking %d confirmation clients for script hash %s",
		len(confClients), scriptHash)
	for _, client := range confClients {
		clientID := atomic.LoadUint64(&client.event.CancelID) // Use CancelID as the client ID
		// Skip if client has cancelled.
		if clientID == 0 { // Cancel sets ID to 0 in chainntnfs/height_hint_cache.go#L105 (or similar logic)
			ltndLog.Tracef("Skipping cancelled confirmation client %d for script hash %s",
				client.id, scriptHash) // Use internal client.id for logging if needed
			continue
		}

		// If we already found the tx, just check confirmations.
		if client.txFoundHeight > 0 {
			confs := uint32(currentHeight - client.txFoundHeight + 1)
			if confs >= client.numConfs {
				ltndLog.Infof("Dispatching %d confirmation(s) for client %d, txid %s",
					confs, client.id, client.txid)
				select {
				case client.event.Confirmed <- &chainntnfs.TxConfirmation{BlockHeight: currentHeight}: // TODO: Need actual block hash/details
					confirmedClientsToRemove = append(confirmedClientsToRemove, client.id)
				case <-client.event.CancelChan: // Assuming CancelChan exists
					confirmedClientsToRemove = append(confirmedClientsToRemove, client.id)
				case <-e.quit:
					return
				}
			}
			continue
		}

		// Search history for the target txid.
		for _, item := range history {
			if item.TxHash == client.txid.String() {
				txHeight := int32(item.Height)
				// Electrum uses 0 for unconfirmed, >0 for confirmed height.
				if txHeight > 0 {
					client.txFoundHeight = txHeight
					confs := uint32(currentHeight - txHeight + 1)
					ltndLog.Infof("Found tx %s for client %d at height %d (%d confs)",
						client.txid, client.id, txHeight, confs)

					if confs >= client.numConfs {
						ltndLog.Infof("Dispatching %d confirmation(s) for client %d, txid %s",
							confs, client.id, client.txid)
						select {
						case client.event.Confirmed <- &chainntnfs.TxConfirmation{BlockHeight: currentHeight}: // TODO: Need actual block hash/details
							confirmedClientsToRemove = append(confirmedClientsToRemove, client.id)
						case <-client.event.CancelChan:
							confirmedClientsToRemove = append(confirmedClientsToRemove, client.id)
						case <-e.quit:
							return
						}
					}
				} else {
					// Tx is in history but unconfirmed (height 0 or -1).
					ltndLog.Debugf("Tx %s for client %d found but unconfirmed",
						client.txid, client.id)
				}
				// Found the tx, no need to check further history items for this client.
				break
			}
		}
	}

	// --- Process Spend Notifications ---
	ltndLog.Debugf("Checking %d spend clients for script hash %s",
		len(spendClients), scriptHash)
	for _, client := range spendClients {
		clientID := atomic.LoadUint64(&client.event.CancelID) // Use CancelID as the client ID
		// Skip if client has cancelled.
		if clientID == 0 {
			ltndLog.Tracef("Skipping cancelled spend client %d for script hash %s",
				client.id, scriptHash) // Use internal client.id for logging if needed
			continue
		}

		// Check history for a spending transaction.
		for _, item := range history {
			// TODO: This is potentially very inefficient as it fetches
			// the full transaction for every item in the history on
			// every status update. Consider optimizations if possible,
			// maybe only fetch txs confirmed since last check?
			spendingTx, err := e.GetTransaction(&item.TxHash)
			if err != nil {
				ltndLog.Warnf("Failed to get tx %s while checking spend "+
					"for %s: %v", item.TxHash, client.outpoint, err)
				continue // Skip this history item if we can't fetch it
			}

			// Check if any input matches the target outpoint.
			for i, txIn := range spendingTx.TxIn {
				if txIn.PreviousOutPoint == *client.outpoint {
					ltndLog.Infof("Dispatching spend notification for "+
						"client %d, outpoint %s spent by tx %s",
						client.id, client.outpoint, item.TxHash)

					spendDetails := &chainntnfs.SpendDetail{
						SpentOutPoint:     client.outpoint,
						SpenderTxHash:     &item.TxHash,
						SpendingTx:        spendingTx,
						SpenderInputIndex: uint32(i),
						SpendingHeight:    int32(item.Height), // Can be 0 if mempool spend
					}

					// Send notification non-blockingly.
					select {
					case client.event.Spend <- spendDetails:
						spentClientsToRemove = append(spentClientsToRemove, client.id)
					case <-client.event.CancelChan: // Assuming CancelChan exists
						spentClientsToRemove = append(spentClientsToRemove, client.id)
					case <-e.quit:
						return
					}
					// Found the spending tx for this client, move to next client.
					goto nextSpendClient
				}
			}
		}
	nextSpendClient:
	}

	// --- Clean up finished clients ---
	if len(confirmedClientsToRemove) > 0 || len(spentClientsToRemove) > 0 {
		e.scriptHashClientMtx.Lock()
		for _, id := range confirmedClientsToRemove {
			// Find the client in the slice and remove it.
			clients := e.confClientsByScriptHash[scriptHash]
			for i, c := range clients {
				if c.id == id {
					e.confClientsByScriptHash[scriptHash] = append(clients[:i], clients[i+1:]...)
					break
				}
			}
		}
		for _, id := range spentClientsToRemove {
			// Find the client in the slice and remove it.
			clients := e.spendClientsByScriptHash[scriptHash]
			for i, c := range clients {
				if c.id == id {
					e.spendClientsByScriptHash[scriptHash] = append(clients[:i], clients[i+1:]...)
					break
				}
			}
		}

		// If no clients remain for this script hash, consider unsubscribing.
		shouldUnsubscribe := len(e.confClientsByScriptHash[scriptHash]) == 0 &&
			len(e.spendClientsByScriptHash[scriptHash]) == 0

		// Get the cancel function before unlocking, but call it after unlocking.
		cancelFunc, listenerExists := e.scriptHashListeners[scriptHash]

		e.scriptHashClientMtx.Unlock() // Unlock before potential unsubscribe/cancel call

		if shouldUnsubscribe {
			ltndLog.Infof("No more clients for script hash %s, cleaning up subscription.", scriptHash)

			// Remove from our subscription status map.
			e.scriptHashClientMtx.Lock()
			delete(e.scriptHashSubscriptions, scriptHash)
			e.scriptHashClientMtx.Unlock()

			// Cancel the listener goroutine if it exists.
			if listenerExists {
				ltndLog.Debugf("Cancelling listener goroutine for script hash %s", scriptHash)
				cancelFunc()
				// Remove from listener map *after* cancelling.
				e.scriptHashClientMtx.Lock()
				delete(e.scriptHashListeners, scriptHash)
				e.scriptHashClientMtx.Unlock()
			} else {
				ltndLog.Warnf("Listener cancel func not found for script hash %s during cleanup", scriptHash)
			}

			// TODO: Attempt to call Electrum server unsubscribe method if available.
			ltndLog.Warnf("Electrum server unsubscribe call needs implementation/verification.")
			// Example:
			// ctxUnsub, cancelUnsub := context.WithTimeout(context.Background(), e.cfg.RequestTimeout)
			// unsubscribed, err := e.client.ScriptHashUnsubscribe(ctxUnsub, scriptHash)
			// cancelUnsub()
			// if err != nil {
			//     ltndLog.Errorf("Failed to unsubscribe from script hash %s: %v", scriptHash, err)
			//     // Handle error: Maybe re-subscribe later or log persistently?
			// } else if !unsubscribed {
			//     ltndLog.Warnf("Server reported failure to unsubscribe from script hash %s", scriptHash)
			// } else {
			//     ltndLog.Infof("Unsubscribed from script hash %s", scriptHash)
			// }
		}
	}
}

// subscribeScriptHash ensures we are subscribed to status updates for the given
// pkScript via the Electrum server.
func (e *ElectrumChainSource) subscribeScriptHash(pkScript []byte) (string, error) {
	electrumScriptHash := scriptHashToElectrumScriptHash(pkScript)

	e.scriptHashClientMtx.Lock()
	defer e.scriptHashClientMtx.Unlock()

	// If already subscribed, return the current status.
	if status, ok := e.scriptHashSubscriptions[electrumScriptHash]; ok {
		return status, nil
	}

	// Not subscribed yet, call the Electrum client's subscribe method.
	// ** ASSUMPTION: ScriptHashSubscribe returns (initialStatus, statusChan, error) **
	ctxSub, cancelSub := context.WithTimeout(context.Background(), e.cfg.RequestTimeout)
	defer cancelSub()
	initialStatus, statusChan, err := e.client.ScriptHashSubscribe(ctxSub, electrumScriptHash)
	if err != nil {
		return "", fmt.Errorf("failed to subscribe to script hash %s: %w",
			electrumScriptHash, err)
	}

	// Store the initial status and mark as subscribed.
	e.scriptHashSubscriptions[electrumScriptHash] = initialStatus

	ltndLog.Infof("Subscribed to script hash %s, initial status: %s",
		electrumScriptHash, initialStatus)

	return initialStatus, nil
}

// FilterBlock implements the chainview.FilteredChainView interface.
// NOTE: Electrum protocol does not easily support fetching all transactions
// in a block. Implementing this efficiently requires alternative strategies.
// Marked as unimplemented for now.
func (e *ElectrumChainSource) FilterBlock(blockHash *chainhash.Hash) (*chainview.FilteredBlock, error) {
	ltndLog.Debugf("FilterBlock called for %s (unimplemented)", blockHash)
	return nil, ErrUnimplemented
}

// FilterBlockConnected implements the chainview.FilteredChainView interface.
// NOTE: See FilterBlock. Marked as unimplemented for now.
func (e *ElectrumChainSource) FilterBlockConnected(blockHash *chainhash.Hash) (*chainview.FilteredBlock, error) {
	ltndLog.Debugf("FilterBlockConnected called for %s (unimplemented)", blockHash)
	return nil, ErrUnimplemented
}

// SubscribeTxNotifications implements the chainntnfs.MempoolWatcher interface.
// NOTE: Electrum protocol does not support general mempool transaction
// notifications. Marked as unimplemented.
func (e *ElectrumChainSource) SubscribeTxNotifications() (*chainntnfs.TxNotifications, error) {
	ltndLog.Warnf("SubscribeTxNotifications called (unimplemented)")
	return nil, ErrUnimplemented
}

// SubscribeSpendNotifications implements the chainntnfs.MempoolWatcher interface.
// NOTE: Electrum protocol does not support general mempool spend
// notifications. Marked as unimplemented.
func (e *ElectrumChainSource) SubscribeSpendNotifications(
	outpoint wire.OutPoint) (*chainntnfs.SpendNotifications, error) {

	ltndLog.Warnf("SubscribeSpendNotifications called for %s (unimplemented)", outpoint)
	return nil, ErrUnimplemented
}

// BackEnd returns the name of the backend.
func (e *ElectrumChainSource) BackEnd() string {
	return BackendName
}

// ListTransactionDetails returns a list of all known transactions relevant to the wallet.
// TODO(#electrum): Implement by fetching history for all known/derived addresses
// and parsing transaction details. This requires iterating potentially many
// addresses and fetching full transaction data, which can be slow. A local
// cache or persistent storage of known transactions would be beneficial.
func (e *ElectrumChainSource) ListTransactionDetails() ([]*lnwallet.TransactionDetail, error) {
	ltndLog.Warnf("ListTransactionDetails not implemented for electrum backend")
	return nil, fmt.Errorf("ListTransactionDetails not implemented for electrum backend")
}

// SubscribeTransactions returns a TransactionSubscription which delivers transaction
// notifications.
// TODO(#electrum): Implement using script hash subscriptions and history processing.
// This requires managing subscriptions for all derived wallet addresses and
// translating script hash history updates into detailed TxNotifications,
// potentially involving fetching full transaction data.
func (e *ElectrumChainSource) SubscribeTransactions() (*lnwallet.TransactionSubscription, error) {
	ltndLog.Warnf("SubscribeTransactions not implemented for electrum backend")
	return nil, fmt.Errorf("SubscribeTransactions not implemented for electrum backend")
}

// ListAccounts retrieves all accounts belonging to the wallet by default.
// TODO: Implement proper account handling if needed beyond default.
func (e *ElectrumChainSource) ListAccounts(name string, acctType lnwallet.AddressType) ([]*lnwallet.Account, error) {
	ltndLog.Warnf("ListAccounts not implemented for electrum wallet (returning default)")
	// For now, just return the default account structure if requested.
	if name != "" && name != lnwallet.DefaultAccountName {
		return nil, fmt.Errorf("named accounts not supported yet")
	}
	if acctType != lnwallet.WitnessPubKey {
		return nil, fmt.Errorf("only P2WKH accounts supported yet")
	}

	// Need to get current external/internal indexes.
	e.mu.Lock()
	externalIdx := e.externalKeyIdx
	internalIdx := e.internalKeyIdx
	e.mu.Unlock()

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
func (e *ElectrumChainSource) RequiredReserve(numOutputs int) btcutil.Amount {
	// Since we don't manage channel anchors directly in this basic wallet,
	// return 0. This might need adjustment if used for anchor channels.
	ltndLog.Warnf("RequiredReserve returning 0 for electrum wallet")
	return 0
}

// LastUnusedAddress returns the last unused address of the specified type.
// TODO(#electrum): Implement proper unused address tracking. This requires
// querying the history of derived addresses within the lookahead window to find
// the first one without any transaction history.
func (e *ElectrumChainSource) LastUnusedAddress(addrType lnwallet.AddressType, account string) (btcutil.Address, error) {
	ltndLog.Warnf("LastUnusedAddress not implemented for electrum backend")
	// Returning an error is safer than returning a potentially incorrect address.
	return nil, fmt.Errorf("LastUnusedAddress not implemented for electrum backend")
}

// IsOurAddress checks if the passed address belongs to this wallet.
// TODO(#electrum): Implement by deriving addresses within the known range +
// lookahead and comparing. This can be slow without caching or a Bloom filter.
func (e *ElectrumChainSource) IsOurAddress(a btcutil.Address) bool {
	// Returning false is safer than potentially claiming an address incorrectly.
	// ltndLog.Warnf("IsOurAddress check not fully implemented for electrum backend")
	return false
}

// GenerateNewAccount creates a new account (currently only default supported).
func (e *ElectrumChainSource) GenerateNewAccount(name string) error {
	// Currently only the default account is implicitly supported.
	if name == lnwallet.DefaultAccountName {
		return fmt.Errorf("default account already exists")
	}
	ltndLog.Warnf("GenerateNewAccount: named accounts not supported for electrum backend")
	return fmt.Errorf("GenerateNewAccount: named accounts not supported for electrum backend")
}

// Unlock performs wallet decryption. Assumes no local encryption for now.
func (e *ElectrumChainSource) Unlock(password []byte, timeout time.Duration) error {
	ltndLog.Warnf("Unlock called but not implemented (no local encryption assumed)")
	// TODO: Implement if local key material/seed is encrypted.
	return nil // No-op if not encrypted
}

// Lock performs wallet encryption. Assumes no local encryption for now.
func (e *ElectrumChainSource) Lock() error {
	ltndLog.Warnf("Lock called but not implemented (no local encryption assumed)")
	// TODO: Implement if local key material/seed is encrypted.
	return nil // No-op if not encrypted
}

// ChangePassword changes the wallet's password. Assumes no local encryption.
func (e *ElectrumChainSource) ChangePassword(old []byte, new []byte) error {
	ltndLog.Warnf("ChangePassword called but not implemented (no local encryption assumed)")
	// TODO: Implement if local key material/seed is encrypted.
	return fmt.Errorf("ChangePassword not implemented for electrum wallet")
}

// TODO: Add helper methods for interacting with the Electrum client, managing
// subscriptions, handling responses, etc.
