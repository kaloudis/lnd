//go:build mobile
// +build mobile

package lndmobile

import (
	"bytes"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/BoltzExchange/boltz-client/v2/pkg/boltz"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

func TestSwapNetwork(t *testing.T) {
	for name, want := range map[string]*boltz.Network{
		"mainnet":  boltz.MainNet,
		"bitcoin":  boltz.MainNet,
		"testnet":  boltz.TestNet,
		"testnet3": boltz.TestNet,
		"testnet4": boltz.TestNet,
		"signet":   boltz.TestNet,
		"regtest":  boltz.Regtest,
	} {
		got, err := swapNetwork(name)
		require.NoError(t, err, name)
		require.Same(t, want, got, name)
	}

	_, err := swapNetwork("liquid")
	require.Error(t, err)
}

// swapFixture is a regtest swap lockup and the material to spend it. As
// built by newReverseSwapFixture it is a reverse swap lockup paying our
// claim leaf, shaped like the ones Boltz creates.
type swapFixture struct {
	ourKey, serverKey     *btcec.PrivateKey
	preimage              []byte
	claimLeaf, refundLeaf []byte
	lockupAddress         string
	lockupHex             string
	lockupTxid            chainhash.Hash
}

func newReverseSwapFixture(t *testing.T) swapFixture {
	t.Helper()

	ourKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	serverKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	preimage := bytes.Repeat([]byte{7}, 32)

	claimLeaf, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_SIZE).AddInt64(32).AddOp(txscript.OP_EQUALVERIFY).
		AddOp(txscript.OP_HASH160).AddData(btcutil.Hash160(preimage)).
		AddOp(txscript.OP_EQUALVERIFY).
		AddData(schnorr.SerializePubKey(ourKey.PubKey())).
		AddOp(txscript.OP_CHECKSIG).
		Script()
	require.NoError(t, err)

	refundLeaf, err := txscript.NewScriptBuilder().
		AddData(schnorr.SerializePubKey(serverKey.PubKey())).
		AddOp(txscript.OP_CHECKSIGVERIFY).
		AddInt64(150).AddOp(txscript.OP_CHECKLOCKTIMEVERIFY).
		Script()
	require.NoError(t, err)

	tree := &boltz.SwapTree{
		ClaimLeaf:  leaf(hex.EncodeToString(claimLeaf)),
		RefundLeaf: leaf(hex.EncodeToString(refundLeaf)),
	}
	require.NoError(t, tree.Init(boltz.CurrencyBtc, false, ourKey, serverKey.PubKey()))
	lockupAddress, err := tree.Address(boltz.Regtest, nil)
	require.NoError(t, err)

	address, err := btcutil.DecodeAddress(lockupAddress, boltz.Regtest.Btc)
	require.NoError(t, err)
	script, err := txscript.PayToAddrScript(address)
	require.NoError(t, err)

	lockup := wire.NewMsgTx(2)
	lockup.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{1}}, nil, nil))
	lockup.AddTxOut(wire.NewTxOut(100000, script))
	var buf bytes.Buffer
	require.NoError(t, lockup.Serialize(&buf))

	return swapFixture{
		ourKey:        ourKey,
		serverKey:     serverKey,
		preimage:      preimage,
		claimLeaf:     claimLeaf,
		refundLeaf:    refundLeaf,
		lockupAddress: lockupAddress,
		lockupHex:     hex.EncodeToString(buf.Bytes()),
		lockupTxid:    lockup.TxHash(),
	}
}

func TestBuildReverseClaimTransactionDoesNotBroadcast(t *testing.T) {
	fixture := newReverseSwapFixture(t)

	// A host that refuses every request: the cooperative claim fails and
	// boltz-client falls back to the script path. Nothing may be posted
	// anywhere else.
	var requests atomic.Int32
	host := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			http.NotFound(w, r)
		},
	))
	defer host.Close()

	destination, err := btcutil.NewAddressTaproot(
		bytes.Repeat([]byte{2}, 32), boltz.Regtest.Btc,
	)
	require.NoError(t, err)

	txHex, err := BuildReverseClaimTransaction(
		host.URL, "swap", hex.EncodeToString(fixture.claimLeaf),
		hex.EncodeToString(fixture.refundLeaf),
		hex.EncodeToString(fixture.ourKey.Serialize()),
		hex.EncodeToString(fixture.serverKey.PubKey().SerializeCompressed()),
		hex.EncodeToString(fixture.preimage), fixture.lockupHex,
		fixture.lockupAddress, destination.EncodeAddress(), 2, 300, "regtest",
	)
	require.NoError(t, err)

	raw, err := hex.DecodeString(txHex)
	require.NoError(t, err)
	claim := wire.NewMsgTx(2)
	require.NoError(t, claim.Deserialize(bytes.NewReader(raw)))

	// spends the lockup, pays the destination less the exact miner fee,
	// and carries the preimage in the script-path witness
	require.Len(t, claim.TxIn, 1)
	require.Equal(t, fixture.lockupTxid, claim.TxIn[0].PreviousOutPoint.Hash)
	require.Len(t, claim.TxOut, 1)
	require.Equal(t, int64(100000-300), claim.TxOut[0].Value)
	destinationScript, err := txscript.PayToAddrScript(destination)
	require.NoError(t, err)
	require.Equal(t, destinationScript, claim.TxOut[0].PkScript)
	require.Contains(t, claim.TxIn[0].Witness, fixture.preimage)

	// the only requests went to the swap host, for the cooperative claim
	require.Positive(t, requests.Load())
}

func TestBuildReverseClaimTransactionRejectsUnknownNetwork(t *testing.T) {
	fixture := newReverseSwapFixture(t)

	_, err := BuildReverseClaimTransaction(
		"http://127.0.0.1:1", "swap", hex.EncodeToString(fixture.claimLeaf),
		hex.EncodeToString(fixture.refundLeaf),
		hex.EncodeToString(fixture.ourKey.Serialize()),
		hex.EncodeToString(fixture.serverKey.PubKey().SerializeCompressed()),
		hex.EncodeToString(fixture.preimage), fixture.lockupHex,
		fixture.lockupAddress, fixture.lockupAddress, 2, 300, "liquid",
	)
	require.ErrorContains(t, err, "unsupported network")
}

func TestBuildRefundTransactionDoesNotBroadcast(t *testing.T) {
	var requests atomic.Int32
	host := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			http.NotFound(w, r)
		},
	))
	defer host.Close()

	destination, err := btcutil.NewAddressTaproot(
		bytes.Repeat([]byte{3}, 32), boltz.Regtest.Btc,
	)
	require.NoError(t, err)

	refund := newRefundFixture(t)
	txHex, err := BuildRefundTransaction(
		host.URL, "swap", hex.EncodeToString(refund.claimLeaf),
		hex.EncodeToString(refund.refundLeaf), refund.lockupHex,
		hex.EncodeToString(refund.ourKey.Serialize()),
		hex.EncodeToString(refund.serverKey.PubKey().SerializeCompressed()),
		2, 150, destination.EncodeAddress(), refund.lockupAddress, false,
		"regtest",
	)
	require.NoError(t, err)

	raw, err := hex.DecodeString(txHex)
	require.NoError(t, err)
	tx := wire.NewMsgTx(2)
	require.NoError(t, tx.Deserialize(bytes.NewReader(raw)))

	require.Len(t, tx.TxIn, 1)
	require.Equal(t, refund.lockupTxid, tx.TxIn[0].PreviousOutPoint.Hash)
	require.Equal(t, uint32(150), tx.LockTime)
	require.Len(t, tx.TxOut, 1)
	require.Less(t, tx.TxOut[0].Value, int64(100000))

	// an uncooperative refund never asks the host for anything
	require.Zero(t, requests.Load())
}

// newRefundFixture is a regtest submarine swap lockup: the server claims
// with the preimage, and we can refund after block 150.
func newRefundFixture(t *testing.T) swapFixture {
	t.Helper()

	ourKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	serverKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	preimage := bytes.Repeat([]byte{9}, 32)

	claimLeaf, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_HASH160).AddData(btcutil.Hash160(preimage)).
		AddOp(txscript.OP_EQUALVERIFY).
		AddData(schnorr.SerializePubKey(serverKey.PubKey())).
		AddOp(txscript.OP_CHECKSIG).
		Script()
	require.NoError(t, err)

	refundLeaf, err := txscript.NewScriptBuilder().
		AddData(schnorr.SerializePubKey(ourKey.PubKey())).
		AddOp(txscript.OP_CHECKSIGVERIFY).
		AddInt64(150).AddOp(txscript.OP_CHECKLOCKTIMEVERIFY).
		Script()
	require.NoError(t, err)

	tree := &boltz.SwapTree{
		ClaimLeaf:  leaf(hex.EncodeToString(claimLeaf)),
		RefundLeaf: leaf(hex.EncodeToString(refundLeaf)),
	}
	require.NoError(t, tree.Init(boltz.CurrencyBtc, false, ourKey, serverKey.PubKey()))
	lockupAddress, err := tree.Address(boltz.Regtest, nil)
	require.NoError(t, err)

	address, err := btcutil.DecodeAddress(lockupAddress, boltz.Regtest.Btc)
	require.NoError(t, err)
	script, err := txscript.PayToAddrScript(address)
	require.NoError(t, err)

	lockup := wire.NewMsgTx(2)
	lockup.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{2}}, nil, nil))
	lockup.AddTxOut(wire.NewTxOut(100000, script))
	var buf bytes.Buffer
	require.NoError(t, lockup.Serialize(&buf))

	return swapFixture{
		ourKey:        ourKey,
		serverKey:     serverKey,
		preimage:      preimage,
		claimLeaf:     claimLeaf,
		refundLeaf:    refundLeaf,
		lockupAddress: lockupAddress,
		lockupHex:     hex.EncodeToString(buf.Bytes()),
		lockupTxid:    lockup.TxHash(),
	}
}
