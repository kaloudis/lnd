//go:build mobile
// +build mobile

package lndmobile

import (
	"github.com/btcsuite/btclog"
	"github.com/lightningnetwork/lnd"
	"github.com/lightningnetwork/lnd/build"
)

const Subsystem = "MOBL"

var (
	log btclog.Logger
)

// SetupLoggers initializes all package-global logger variables.
func SetupLoggers(root *build.RotatingLogWriter, intercept Interceptor) {
	genLogger := genSubLogger(root, intercept)

	log = build.NewSubLogger(Subsystem, genLogger)

	lnd.SetSubLogger(root, Subsystem, log)
}

// genSubLogger creates a logger for a subsystem. We provide an instance of
// a signal.Interceptor to be able to shutdown in the case of a critical error.
func genSubLogger(root *build.RotatingLogWriter,
	interceptor Interceptor) func(string) btclog.Logger {

	// Create a shutdown function which will request shutdown from our
	// interceptor if it is listening.
	shutdown := func() {
		if !interceptor.Listening() {
			return
		}

		interceptor.RequestShutdown()
	}

	// Return a function which will create a sublogger from our root
	// logger without shutdown fn.
	return func(tag string) btclog.Logger {
		return root.GenSubLogger(tag, shutdown)
	}
}
