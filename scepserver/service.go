package scepserver

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"github.com/go-kit/kit/endpoint"
	httptransport "github.com/go-kit/kit/transport/http"
	"github.com/pkg/errors"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
)
// Service is the interface for all supported SCEP server operations.
type Service interface {
	// GetCACaps returns a list of options
	// which are supported by the server.
	GetCACaps(ctx context.Context) ([]byte, error)

	// GetCACert returns CA certificate or
	// a CA certificate chain with intermediates
	// in a PKCS#7 Degenerate Certificates format
	GetCACert(ctx context.Context) ([]byte, int, error)

	// PKIOperation handles incoming SCEP messages such as PKCSReq and
	// sends back a CertRep PKIMessag.
	PKIOperation(ctx context.Context, msg []byte) ([]byte, error)

	// GetNextCACert returns a replacement certificate or certificate chain
	// when the old one expires. The response format is a PKCS#7 Degenerate
	// Certificates type.
	GetNextCACert(ctx context.Context) ([]byte, error)
}

const maxPayloadSize = 2 << 20

// possible SCEP operations
const (
	getCACaps     = "GetCACaps"
	getCACert     = "GetCACert"
	pkiOperation  = "PKIOperation"
	getNextCACert = "GetNextCACert"
)

const (
	certChainHeader = "application/x-x509-ca-ra-cert"
	leafHeader      = "application/x-x509-ca-cert"
	pkiOpHeader     = "application/x-pki-message"
)

// SCEPResponse is a SCEP server response.
// Business errors will be encoded as a CertRep message
// with pkiStatus FAILURE and a failInfo attribute.
type SCEPResponse struct {
	operation string
	CACertNum int
	Data      []byte
	Err       error
}

type Endpoints struct {
	GetEndpoint  endpoint.Endpoint
	PostEndpoint endpoint.Endpoint

	mtx          sync.RWMutex
	capabilities []byte
}

// SCEPRequest is a SCEP server request.
type SCEPRequest struct {
	Operation string
	Message   []byte
}

func (e *Endpoints) GetCACaps(ctx context.Context) ([]byte, error) {
	request := SCEPRequest{Operation: getCACaps}
	response, err := e.GetEndpoint(ctx, request)
	if err != nil {
		return nil, err
	}
	resp := response.(SCEPResponse)

	e.mtx.Lock()
	e.capabilities = resp.Data
	e.mtx.Unlock()

	return resp.Data, resp.Err
}

func (e *Endpoints) Supports(cap string) bool {
	e.mtx.RLock()
	defer e.mtx.RUnlock()

	if len(e.capabilities) == 0 {
		e.mtx.RUnlock()
		e.GetCACaps(context.Background())
		e.mtx.RLock()
	}
	return bytes.Contains(e.capabilities, []byte(cap))
}

func (e *Endpoints) GetCACert(ctx context.Context) ([]byte, int, error) {
	request := SCEPRequest{Operation: getCACert}
	response, err := e.GetEndpoint(ctx, request)
	if err != nil {
		return nil, 0, err
	}
	resp := response.(SCEPResponse)
	return resp.Data, resp.CACertNum, resp.Err
}

func (e *Endpoints) PKIOperation(ctx context.Context, msg []byte) ([]byte, error) {
	var ee endpoint.Endpoint
	if e.Supports("POSTPKIOperation") || e.Supports("SCEPStandard") {
		ee = e.PostEndpoint
	} else {
		ee = e.GetEndpoint
	}

	request := SCEPRequest{Operation: pkiOperation, Message: msg}
	response, err := ee(ctx, request)
	if err != nil {
		return nil, err
	}
	resp := response.(SCEPResponse)
	return resp.Data, resp.Err
}

func (e *Endpoints) GetNextCACert(ctx context.Context) ([]byte, error) {
	var request SCEPRequest
	response, err := e.GetEndpoint(ctx, request)
	if err != nil {
		return nil, err
	}
	resp := response.(SCEPResponse)
	return resp.Data, resp.Err
}

// EncodeSCEPRequest encodes a SCEP HTTP Request. Used by the client.
func EncodeSCEPRequest(ctx context.Context, r *http.Request, request interface{}) error {
	req := request.(SCEPRequest)
	params := r.URL.Query()
	params.Set("operation", req.Operation)
	switch r.Method {
	case "GET":
		if len(req.Message) > 0 {
			msg := base64.URLEncoding.EncodeToString(req.Message)
			params.Set("message", msg)
		}
		r.URL.RawQuery = params.Encode()
		return nil
	case "POST":
		body := bytes.NewReader(req.Message)
		// recreate the request here because IIS does not support chunked encoding by default
		// and Go doesn't appear to set Content-Length if we use an io.ReadCloser
		u := r.URL
		u.RawQuery = params.Encode()
		rr, err := http.NewRequest("POST", u.String(), body)
		if err != nil {
			// return errors.Wrapf(err, "creating new POST request for %s", req.Operation)
			log.Fatal(" creating new POST request for %s", req.Operation)
		}
		*r = *rr
		return nil
	default:
		return fmt.Errorf("scep: %s method not supported", r.Method)
	}
}

// DecodeSCEPResponse decodes a SCEP response
func DecodeSCEPResponse(ctx context.Context, r *http.Response) (interface{}, error) {
	if r.StatusCode != http.StatusOK && r.StatusCode >= 400 {
		body, _ := ioutil.ReadAll(io.LimitReader(r.Body, 4096))
		return nil, fmt.Errorf("http request failed with status %s, msg: %s",
			r.Status,
			string(body),
		)
	}
	data, err := ioutil.ReadAll(io.LimitReader(r.Body, maxPayloadSize))
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	resp := SCEPResponse{
		Data: data,
	}
	header := r.Header.Get("Content-Type")
	if header == certChainHeader {
		// we only set it to two to indicate a cert chain.
		// the actual number of certs will be in the payload.
		resp.CACertNum = 2
	}
	return resp, nil
}

// EncodeSCEPResponse writes a SCEP response back to the SCEP client.
func encodeSCEPResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	resp := response.(SCEPResponse)
	if resp.Err != nil {
		http.Error(w, resp.Err.Error(), http.StatusInternalServerError)
		return nil
	}
	w.Header().Set("Content-Type", contentHeader(resp.operation, resp.CACertNum))
	w.Write(resp.Data)
	return nil
}

func contentHeader(op string, certNum int) string {
	switch op {
	case "GetCACert":
		if certNum > 1 {
			return certChainHeader
		}
		return leafHeader
	case "PKIOperation":
		return pkiOpHeader
	default:
		return "text/plain"
	}
}

// extract message from request
func message(r *http.Request) ([]byte, error) {
	switch r.Method {
	case "GET":
		var msg string
		q := r.URL.Query()
		if _, ok := q["message"]; ok {
			msg = q.Get("message")
		}
		return []byte(msg), nil
	case "POST":
		return ioutil.ReadAll(io.LimitReader(r.Body, maxPayloadSize))
	default:
		return nil, errors.New("method not supported")
	}
}

func MakeClientEndpoints(instance string) (*Endpoints, error) {
	if !strings.HasPrefix(instance, "http") {
		instance = "http://" + instance
	}
	tgt, err := url.Parse(instance)
	if err != nil {
		return nil, err
	}

	options := []httptransport.ClientOption{}

	return &Endpoints{
		GetEndpoint: httptransport.NewClient(
			"GET",
			tgt,
			EncodeSCEPRequest,
			DecodeSCEPResponse,
			options...).Endpoint(),
		PostEndpoint: httptransport.NewClient(
			"POST",
			tgt,
			EncodeSCEPRequest,
			DecodeSCEPResponse,
			options...).Endpoint(),
	}, nil
}
