//go:build mobile
// +build mobile

package lndmobile

// Local permissions manager that replaces lightning-terminal's perms.Manager
// for LNC. The lightning-terminal fork's perms mock returns zero-valued
// subserver configs, which lnd v0.21's CreateSubServer rejects (e.g.
// "FeeEstimator must be set to create WalletKit RPC server"), so
// perms.NewManager fails and InitLNC errors on every call. Building the
// URI-to-permissions map here keeps the mock configs in lockstep with the
// lnd version this fork is based on.

import (
	"net"

	"github.com/lightningnetwork/lnd"
	"github.com/lightningnetwork/lnd/autopilot"
	"github.com/lightningnetwork/lnd/chainreg"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/autopilotrpc"
	"github.com/lightningnetwork/lnd/lnrpc/chainrpc"
	"github.com/lightningnetwork/lnd/lnrpc/invoicesrpc"
	"github.com/lightningnetwork/lnd/lnrpc/neutrinorpc"
	"github.com/lightningnetwork/lnd/lnrpc/peersrpc"
	"github.com/lightningnetwork/lnd/lnrpc/routerrpc"
	"github.com/lightningnetwork/lnd/lnrpc/signrpc"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/lightningnetwork/lnd/lnrpc/watchtowerrpc"
	"github.com/lightningnetwork/lnd/lnrpc/wtclientrpc"
	"github.com/lightningnetwork/lnd/lntest/mock"
	"github.com/lightningnetwork/lnd/routing"
	"github.com/lightningnetwork/lnd/sweep"
	"gopkg.in/macaroon-bakery.v2/bakery"
)

// whiteListedLNDMethods is a map of all lnd RPC methods that don't require
// any macaroon authentication.
var whiteListedLNDMethods = map[string][]bakery.Op{
	"/lnrpc.WalletUnlocker/GenSeed":        {},
	"/lnrpc.WalletUnlocker/InitWallet":     {},
	"/lnrpc.WalletUnlocker/UnlockWallet":   {},
	"/lnrpc.WalletUnlocker/ChangePassword": {},

	// The State service must be available at all times, even before we
	// can check macaroons, so we whitelist it.
	"/lnrpc.State/SubscribeState": {},
	"/lnrpc.State/GetState":       {},
}

// PermissionsManager maps gRPC URIs to the macaroon permissions required to
// invoke them. It covers the main RPC server as well as every subserver
// compiled into this build.
type PermissionsManager struct {
	perms map[string][]bakery.Op
}

// NewPermissionsManager creates a new permissions manager populated with the
// permissions of the main RPC server and all registered subservers.
func NewPermissionsManager() (*PermissionsManager, error) {
	permissions := lnd.MainRPCServerPermissions()

	for uri, ops := range whiteListedLNDMethods {
		permissions[uri] = ops
	}

	// Collect the macaroon permissions of every registered subserver. The
	// mock config satisfies each subserver's constructor sanity checks;
	// only the static permissions map is read from the result.
	for _, subServer := range lnrpc.RegisteredSubServers() {
		_, perms, err := subServer.NewGrpcHandler().CreateSubServer(
			&mockConfig{},
		)
		if err != nil {
			return nil, err
		}

		for uri, ops := range perms {
			permissions[uri] = ops
		}
	}

	return &PermissionsManager{perms: permissions}, nil
}

// URIPermissions returns the permissions required for a given URI. Returns
// false if the URI is not found in the permissions map.
func (pm *PermissionsManager) URIPermissions(uri string) ([]bakery.Op, bool) {
	ops, ok := pm.perms[uri]
	return ops, ok
}

// mockConfig implements lnrpc.SubServerConfigDispatcher. It provides just
// enough of each subserver's config for CreateSubServer's sanity checks to
// pass so that the subserver's macaroon permissions can be extracted. The
// stub values mirror lightning-terminal's perms/mock.go.
type mockConfig struct{}

var _ lnrpc.SubServerConfigDispatcher = (*mockConfig)(nil)

// FetchConfig returns a minimal viable config for the given subserver name.
func (t *mockConfig) FetchConfig(subServerName string) (interface{}, bool) {
	switch subServerName {
	case "InvoicesRPC":
		return &invoicesrpc.Config{}, true
	case "WatchtowerClientRPC":
		return &wtclientrpc.Config{
			Resolver: func(_, _ string) (*net.TCPAddr, error) {
				return nil, nil
			},
		}, true
	case "AutopilotRPC":
		return &autopilotrpc.Config{
			Manager: &autopilot.Manager{},
		}, true
	case "ChainRPC":
		return &chainrpc.Config{
			ChainNotifier: &chainreg.NoChainBackend{},
			Chain:         &mock.ChainIO{},
		}, true
	case "NeutrinoKitRPC":
		return &neutrinorpc.Config{}, true
	case "PeersRPC":
		return &peersrpc.Config{}, true
	case "RouterRPC":
		return &routerrpc.Config{
			Router: &routing.ChannelRouter{},
		}, true
	case "SignRPC":
		return &signrpc.Config{
			Signer: &mock.DummySigner{},
		}, true
	case "WalletKitRPC":
		return &walletrpc.Config{
			FeeEstimator: &chainreg.NoChainBackend{},
			Wallet:       &mock.WalletController{},
			KeyRing:      &mock.SecretKeyRing{},
			Sweeper:      &sweep.UtxoSweeper{},
			Chain:        &mock.ChainIO{},
		}, true
	case "WatchtowerRPC":
		return &watchtowerrpc.Config{}, true
	default:
		return nil, false
	}
}
