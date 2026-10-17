// Package deploy contains certificate deployment targets. Callers provide
// certificate material and decide when deployment should run.
package deploy

import "context"

type Material struct {
	FullChainPEM  []byte
	PrivateKeyPEM []byte
}

type Result struct {
	Target   string
	Location string
	Written  bool
	Pending  bool              // remote task accepted; call Poll before treating deployment as complete
	Metadata map[string]string // provider IDs or asynchronous task IDs to persist
}

type Target interface {
	Kind() string
	Check(context.Context) error
	Deploy(context.Context, Material) (Result, error)
}

// Poller is implemented by targets whose Deploy call starts an asynchronous
// remote task. Callers must persist Result and keep polling until Pending is
// false or an error is returned.
type Poller interface {
	Poll(context.Context, Result) (Result, error)
}
