package lncfg

import "time"

// ElectrumConfig holds the configuration options for the daemon's connection to
// an Electrum server.
type ElectrumConfig struct {
	// ServerAddr specifies the host:port of the Electrum server.
	ServerAddr string `long:"server" description:"host:port of the Electrum server"`

	// UseTLS indicates whether to use TLS for the connection.
	UseTLS bool `long:"tls" description:"Use TLS for the Electrum server connection"`

	// ValidateServerCertificate indicates whether the Electrum server's TLS
	// certificate should be validated. Only applies if UseTLS is true.
	ValidateServerCertificate bool `long:"validateservercert" description:"Validate the Electrum server's TLS certificate"`

	// ConnectTimeout is the timeout for establishing the connection.
	ConnectTimeout time.Duration `long:"connecttimeout" description:"Timeout for connecting to the Electrum server"`

	// RequestTimeout is the default timeout for requests made to the server.
	RequestTimeout time.Duration `long:"requesttimeout" description:"Default timeout for requests to the Electrum server"`

	// PersistTxHistory specifies whether the transaction history fetched
	// from the Electrum server should be persisted to disk.
	PersistTxHistory bool `long:"persisttxhistory" description:"Persist transaction history fetched from the Electrum server"`
}
