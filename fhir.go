package fhir

import (
	_ "embed"
	"fmt"
	"os"
	"regexp"

	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/plugins/inputs"
)

//go:embed sample.conf
var sampleConfig string

type FHIR struct {
	ServerURLs         []string        `toml:"server_url"`
	Username           string          `toml:"username"`
	Password           string          `toml:"password"`
	SSLCert            string          `toml:"ssl_cert"`
	InsecureSkipVerify bool            `toml:"insecure_skip_verify"`
	Log                telegraf.Logger `toml:"-"`
}

func (f *FHIR) Description() string {
	return "a FHIR server monitoring plugin"
}

func (f *FHIR) SampleConfig() string {
	return sampleConfig
}

func (f *FHIR) Init() error {
	if len(f.ServerURLs) == 0 {
		return fmt.Errorf("server URLs cannot be empty")
	}

	hostnameRegex := regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$|^localhost$`)
	fqdnRegex := regexp.MustCompile(`^(?:[a-zA-Z0-9_-]+\.)*[a-zA-Z0-9][a-zA-Z0-9_-]*\.[a-zA-Z]{2,11}?$`)
	pathRegex := regexp.MustCompile(`^/(?:[a-zA-Z0-9_-]+/?)*$`)

	for _, serverURL := range f.ServerURLs {
		parsedURL, err := url.Parse(serverURL)
		if err != nil {
			return fmt.Errorf("invalid server URL: %s", serverURL)
		}

		if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
			return fmt.Errorf("invalid URL scheme in %s, must be http or https", serverURL)
		}

		if !hostnameRegex.MatchString(parsedURL.Hostname()) && !fqdnRegex.MatchString(parsedURL.Hostname()) {
			return fmt.Errorf("invalid hostname or FQDN in URL: %s", serverURL)
		}

		if parsedURL.Path != "" && !pathRegex.MatchString(parsedURL.Path) {
			return fmt.Errorf("invalid path in URL: %s", serverURL)
		}
	}

	// Additional validation can be added here
	return nil
}

func (f *FHIR) Gather(acc telegraf.Accumulator) error {
	for _, serverURL := range f.ServerURLs {
		resourceTypes, err := f.getResourceTypes(serverURL)
		if err != nil {
			f.Log.Errorf("Error querying resource types from %s: %v", serverURL, err)
			continue
		}

		for _, resourceType := range resourceTypes {
			count, err := f.getResourceCount(serverURL, resourceType)
			if err != nil {
				f.Log.Errorf("Error querying resource %s from %s: %v", resourceType, serverURL, err)
				continue
			}
			acc.AddFields("fhir_resources", map[string]interface{}{resourceType: count}, map[string]string{"server": serverURL})
		}
	}
	return nil
}

func (f *FHIR) getResourceTypes(serverURL string) ([]string, error) {
	var resourceTypes []string

	// Construct the URL for the capability statement
	requestUrl := serverURL + "/metadata"

	// Make the HTTP GET request
	response, err := f.makeRequest(requestUrl)
	if err != nil {
		return nil, fmt.Errorf("error making request to %s: %v", requestUrl, err)
	}
	defer func() {
		if cerr := response.Body.Close(); cerr != nil {
			f.Log.Errorf("error closing response body: %v", cerr)
		}
	}()

	// Check for HTTP error
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error response from FHIR server: %s", response.Status)
	}

	// Decode the JSON response
	var data struct {
		Rest []struct {
			Resource []struct {
				Type string `json:"type"`
			} `json:"resource"`
		} `json:"rest"`
	}
	if err := json.NewDecoder(response.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("error decoding JSON response: %v", err)
	}

	// Extract resource types
	for _, rest := range data.Rest {
		for _, resource := range rest.Resource {
			resourceTypes = append(resourceTypes, resource.Type)
		}
	}

	return resourceTypes, nil
}

func (f *FHIR) getResourceCount(serverURL string, resourceType string) (int, error) {
	requestUrl := fmt.Sprintf("%s/%s?_summary=count", serverURL, resourceType)
	response, err := f.makeRequest(requestUrl)
	if err != nil {
		return 0, fmt.Errorf("error making request to %s: %v", requestUrl, err)
	}
	defer func() {
		if cerr := response.Body.Close(); cerr != nil {
			f.Log.Errorf("error closing response body: %v", cerr)
		}
	}()

	if response.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("received non-OK response from server: %s", response.Status)
	}

	var result struct {
		Total int `json:"total"`
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return 0, fmt.Errorf("error decoding response body: %w", err)
	}

	return result.Total, nil
}

func (f *FHIR) makeRequest(url string) (*http.Response, error) {
	// Load custom CA certificate
	var tlsConfig *tls.Config
	if f.SSLCert != "" {
		caCert, err := os.ReadFile(f.SSLCert)
		if err != nil {
			return nil, fmt.Errorf("error reading CA certificate file: %w", err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig = &tls.Config{
			RootCAs: caCertPool,
		}
	} else if f.InsecureSkipVerify {
		tlsConfig = &tls.Config{InsecureSkipVerify: true}
	}

	// Create a client with the custom TLS configuration
	client := &http.Client{}
	if tlsConfig != nil {
		client.Transport = &http.Transport{TLSClientConfig: tlsConfig}
	}

	// Make the request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	if f.Username != "" && f.Password != "" {
		req.SetBasicAuth(f.Username, f.Password)
	}
	return client.Do(req)
}

func init() {
	inputs.Add("fhir", func() telegraf.Input { return &FHIR{} })
}
