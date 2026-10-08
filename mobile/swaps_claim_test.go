//go:build mobile
// +build mobile

package lndmobile

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/stretchr/testify/require"
)

// submarineClaimHost plays the swap host for a cooperative submarine swap
// claim: it hands out its MuSig2 public nonce, and when the client posts its
// partial signature, it signs too and combines the two into the final
// key-path signature.
type submarineClaimHost struct {
	t         *testing.T
	session   *musig2.Session
	nonce     [musig2.PubNonceSize]byte
	sigHash   [32]byte
	outputKey *btcec.PublicKey
	finalSig  *schnorr.Signature
	posts     int
}

func newSubmarineClaimHost(t *testing.T, serverKey *btcec.PrivateKey,
	clientKey *btcec.PublicKey, claimLeaf, refundLeaf []byte,
	sigHash [32]byte) *submarineClaimHost {

	t.Helper()

	// Boltz aggregates [server, client] in that order and tweaks the result
	// with the root of the two-leaf swap tree.
	tree := txscript.AssembleTaprootScriptTree(
		txscript.NewBaseTapLeaf(claimLeaf),
		txscript.NewBaseTapLeaf(refundLeaf),
	)
	rootHash := tree.RootNode.TapHash()
	keys := []*btcec.PublicKey{serverKey.PubKey(), clientKey}

	internal, _, _, err := musig2.AggregateKeys(keys, false)
	require.NoError(t, err)
	tweak := musig2.KeyTweakDesc{
		Tweak: *chainhash.TaggedHash(
			chainhash.TagTapTweak,
			schnorr.SerializePubKey(internal.FinalKey), rootHash[:],
		),
		IsXOnly: true,
	}
	output, _, _, err := musig2.AggregateKeys(
		keys, false, musig2.WithKeyTweaks(tweak),
	)
	require.NoError(t, err)

	ctx, err := musig2.NewContext(
		serverKey, false, musig2.WithTweakedContext(tweak),
		musig2.WithKnownSigners(keys),
	)
	require.NoError(t, err)
	session, err := ctx.NewSession()
	require.NoError(t, err)

	return &submarineClaimHost{
		t:         t,
		session:   session,
		nonce:     session.PublicNonce(),
		sigHash:   sigHash,
		outputKey: output.FinalKey,
	}
}

func (h *submarineClaimHost) ServeHTTP(w http.ResponseWriter,
	r *http.Request) {

	h.posts++
	require.Equal(h.t, http.MethodPost, r.Method)
	require.Equal(h.t, "/v2/swap/submarine/swap/claim", r.URL.Path)

	var body struct {
		PubNonce         string `json:"pubNonce"`
		PartialSignature string `json:"partialSignature"`
	}
	require.NoError(h.t, json.NewDecoder(r.Body).Decode(&body))

	clientNonce, err := hex.DecodeString(body.PubNonce)
	require.NoError(h.t, err)
	require.Len(h.t, clientNonce, musig2.PubNonceSize)
	haveAll, err := h.session.RegisterPubNonce(
		[musig2.PubNonceSize]byte(clientNonce),
	)
	require.NoError(h.t, err)
	require.True(h.t, haveAll)

	_, err = h.session.Sign(h.sigHash)
	require.NoError(h.t, err)

	clientPartial, err := hex.DecodeString(body.PartialSignature)
	require.NoError(h.t, err)
	var partial musig2.PartialSignature
	require.NoError(h.t, partial.Decode(bytes.NewReader(clientPartial)))
	haveFinal, err := h.session.CombineSig(&partial)
	require.NoError(h.t, err)
	require.True(h.t, haveFinal)
	h.finalSig = h.session.FinalSig()

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte("{}"))
}

// submarineSwapLeaves are the leaves of a submarine swap tree: the server
// claims with the preimage, and the client can refund after block 150.
func submarineSwapLeaves(t *testing.T, serverKey *btcec.PublicKey,
	clientKey *btcec.PublicKey) ([]byte, []byte) {

	t.Helper()

	claimLeaf, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_HASH160).
		AddData(btcutil.Hash160(bytes.Repeat([]byte{9}, 32))).
		AddOp(txscript.OP_EQUALVERIFY).
		AddData(schnorr.SerializePubKey(serverKey)).
		AddOp(txscript.OP_CHECKSIG).
		Script()
	require.NoError(t, err)

	refundLeaf, err := txscript.NewScriptBuilder().
		AddData(schnorr.SerializePubKey(clientKey)).
		AddOp(txscript.OP_CHECKSIGVERIFY).
		AddInt64(150).AddOp(txscript.OP_CHECKLOCKTIMEVERIFY).
		Script()
	require.NoError(t, err)

	return claimLeaf, refundLeaf
}

// TestCreateClaimTransactionCompletesMusig2 checks that the client's partial
// signature, made from the hex claim details the host returns, combines with
// the host's into a valid signature for the swap's output key. Before the
// details were hex-decoded, Sign rejected the 64-character hash.
func TestCreateClaimTransactionCompletesMusig2(t *testing.T) {
	clientKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	serverKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	claimLeaf, refundLeaf := submarineSwapLeaves(
		t, serverKey.PubKey(), clientKey.PubKey(),
	)
	sigHash := [32]byte{1, 2, 3, 4}

	host := newSubmarineClaimHost(
		t, serverKey, clientKey.PubKey(), claimLeaf, refundLeaf,
		sigHash,
	)
	server := httptest.NewServer(host)
	defer server.Close()

	// The host's GET /swap/submarine/{id}/claim returns both as hex.
	err = CreateClaimTransaction(
		server.URL, "swap", hex.EncodeToString(claimLeaf),
		hex.EncodeToString(refundLeaf),
		hex.EncodeToString(clientKey.Serialize()),
		hex.EncodeToString(serverKey.PubKey().SerializeCompressed()),
		hex.EncodeToString(sigHash[:]),
		hex.EncodeToString(host.nonce[:]),
	)
	require.NoError(t, err)

	require.Equal(t, 1, host.posts)
	require.NotNil(t, host.finalSig)
	require.True(t, host.finalSig.Verify(sigHash[:], host.outputKey))
}

func TestCreateClaimTransactionRejectsMalformedHex(t *testing.T) {
	clientKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	serverKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	claimLeaf, refundLeaf := submarineSwapLeaves(
		t, serverKey.PubKey(), clientKey.PubKey(),
	)

	posts := 0
	server := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			posts++
		},
	))
	defer server.Close()

	validHash := hex.EncodeToString(bytes.Repeat([]byte{1}, 32))
	validNonce := hex.EncodeToString(
		bytes.Repeat([]byte{2}, musig2.PubNonceSize),
	)

	for name, args := range map[string][2]string{
		"hash":  {"not hex", validNonce},
		"nonce": {validHash, "not hex"},
	} {
		err := CreateClaimTransaction(
			server.URL, "swap", hex.EncodeToString(claimLeaf),
			hex.EncodeToString(refundLeaf),
			hex.EncodeToString(clientKey.Serialize()),
			hex.EncodeToString(
				serverKey.PubKey().SerializeCompressed(),
			),
			args[0], args[1],
		)
		require.Error(t, err, name)
	}
	require.Zero(t, posts)
}
