package abiquo_api

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	// "net/url"
	"os"
	// "strings"
	"time"

	"github.com/ernesto-jimenez/httplogger"
	"github.com/go-resty/resty"
	"github.com/nhjk/oauth"
)

type AbiquoClient struct {
	client *resty.Client
}

func GetClient(apiurl string, user string, pass string, insecure bool) *AbiquoClient {
	rc := resty.New()

	baseTransport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
	}

	logger := &httpLogger{
		log: log.New(os.Stderr, "log - ", log.LstdFlags),
	}

	var baseClient *http.Client
	if os.Getenv("ABIQUO_DEBUG") != "" {
		baseClient = &http.Client{
			Transport: httplogger.NewLoggedTransport(baseTransport, logger),
		}
	} else {
		baseClient = &http.Client{
			Transport: baseTransport,
		}
	}

	rc.SetHostURL(apiurl)
	rc.SetBasicAuth(user, pass)
	rc.SetTransport(baseClient.Transport)

	return &AbiquoClient{client: rc}
}

func GetOAuthClient(apiurl string, api_key string, api_secret string, token string, token_secret string, insecure bool) *AbiquoClient {
	rc := resty.New()

	rc.SetPreRequestHook(func(c *resty.Client, r *resty.Request) error {
		req := r.RawRequest

		consumer := &oauth.Consumer{api_key, api_secret}
		consumer.Authorize(req, &oauth.Token{token, token_secret})

		return nil
	})

	baseTransport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
	}

	logger := &httpLogger{
		log: log.New(os.Stderr, "log - ", log.LstdFlags),
	}

	var baseClient *http.Client
	if os.Getenv("ABIQUO_DEBUG") != "" {
		baseClient = &http.Client{
			Transport: httplogger.NewLoggedTransport(baseTransport, logger),
		}
	} else {
		baseClient = &http.Client{
			Transport: baseTransport,
		}
	}

	rc.SetHostURL(apiurl)
	rc.SetTransport(baseClient.Transport)

	return &AbiquoClient{client: rc}
}

type httpLogger struct {
	log *log.Logger
}

func (l *httpLogger) LogRequest(req *http.Request) {
	l.log.Printf(
		"Request %s %s",
		req.Method,
		req.URL.String(),
	)
	for name, value := range req.Header {
		l.log.Printf("Header '%v': '%v'\n", name, value)
	}
}

func (l *httpLogger) LogResponse(req *http.Request, res *http.Response, err error, duration time.Duration) {
	duration /= time.Millisecond
	if err != nil {
		l.log.Println(err)
	} else {
		l.log.Printf(
			"Response method=%s status=%d durationMs=%d %s",
			req.Method,
			res.StatusCode,
			duration,
			req.URL.String(),
		)
		for name, value := range res.Header {
			l.log.Printf("Header '%v': '%v'\n", name, value)
		}
	}
}

func (c *AbiquoClient) GetConfigProperties() ([]ConfigProperty, error) {
	var propsCol ConfigPropertyCollection
	var allprops []ConfigProperty

	props_resp, err := c.client.R().SetHeader("Accept", "application/vnd.abiquo.systemproperties+json").
		Get(fmt.Sprintf("%s/config/properties", c.client.HostURL))
	if err != nil {
		return allprops, err
	}

	err = json.Unmarshal(props_resp.Body(), &propsCol)
	if err != nil {
		return allprops, err
	}
	for {
		for _, p := range propsCol.Collection {
			allprops = append(allprops, p)
		}

		if propsCol.HasNext() {
			next_link := propsCol.GetNext()
			props_resp, err = c.client.R().SetHeader("Accept", "application/vnd.abiquo.systemproperties+json").
				Get(next_link.Href)
			if err != nil {
				return allprops, err
			}
			json.Unmarshal(props_resp.Body(), &propsCol)
		} else {
			break
		}
	}
	return allprops, nil
}

func (c *AbiquoClient) GetConfigProperty(name string) (ConfigProperty, error) {
	var prop ConfigProperty
	props, err := c.GetConfigProperties()
	if err != nil {
		return prop, err
	}
	for _, p := range props {
		if p.Name == name {
			return p, nil
		}
	}
	errorMsg := fmt.Sprintf("Property '%s' was not found.", name)
	return prop, errors.New(errorMsg)
}

func (c *AbiquoClient) GetVDCs() ([]VDC, error) {
	var vdcscol VdcCollection
	var allVdcs []VDC

	vdcs_resp, err := c.client.R().SetHeader("Accept", "application/vnd.abiquo.virtualdatacenters+json").
		Get(fmt.Sprintf("%s/cloud/virtualdatacenters", c.client.HostURL))
	if err != nil {
		return allVdcs, err
	}

	err = json.Unmarshal(vdcs_resp.Body(), &vdcscol)
	if err != nil {
		return allVdcs, err
	}
	for {
		for _, v := range vdcscol.Collection {
			allVdcs = append(allVdcs, v)
		}

		if vdcscol.HasNext() {
			next_link := vdcscol.GetNext()
			vdcs_resp, err = c.client.R().SetHeader("Accept", "application/vnd.abiquo.virtualdatacenters+json").
				Get(next_link.Href)
			if err != nil {
				return allVdcs, err
			}
			json.Unmarshal(vdcs_resp.Body(), &vdcscol)
		} else {
			break
		}
	}
	return allVdcs, nil
}

func (c *AbiquoClient) GetVMByUrl(vm_url string) (VirtualMachine, error) {
	var vm VirtualMachine

	vm_raw, err := c.client.R().SetHeader("Accept", "application/vnd.abiquo.virtualmachine+json").
		Get(vm_url)
	if err != nil {
		return vm, err
	}
	if vm_raw.StatusCode() == 404 {
		return vm, errors.New("NOT FOUND")
	}
	json.Unmarshal(vm_raw.Body(), &vm)
	return vm, nil
}
