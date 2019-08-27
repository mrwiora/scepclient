package scepclient

import (
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"scepclient/scepserver"
)



// Client is a SCEP Client
type Client interface {
	scepserver.Service
	Supports(cap string) bool
}

// New creates a SCEP Client.
func New(
	serverURL string,
	logger log.Logger,
) (Client, error) {
	endpoints, err := scepserver.MakeClientEndpoints(serverURL)
	if err != nil {
		return nil, err
	}
	logger = level.Info(logger)
	return endpoints, nil
}
