# Telegraf input plugin for FHIR resource counts

This input plugin for Telegraf allows to count available resources of FHIR servers.

The plugin queries FHIR endpoints through HTTP requests.

The configuration allows to query multiple FHIR endpoints through the plugin. Each
endpoint is queried for supported resource types and each supported type is then
counted through a `_summary=count` request.

## Configuration

| Parameter              | Description                                                                           | Example                                                                      |
|------------------------|---------------------------------------------------------------------------------------|------------------------------------------------------------------------------|
| `server_urls`          | A list of FHIR endpoints to query.                                                    | `["https://example-fhir-server-1.com", "https://example-fhir-server-2.com"]` |
| `username`             | Optional username used for basic auth at the endpoint.                                | `"user"`                                                                     |
| `password`             | Optional password used for basic auth at the endpoint.                                | `"P@SSW0RD"`                                                                 |
| `ssl_cert`             | Optional path to a custom CA certificate (for self-signed certificates)               | `"/path/to/cert.pem"`                                                        |                          |
| `insecure_skip_verify` | Optional completely disable SSL certificate verification (insecure, use with caution) | `false`                                                                      |

## Caveats

If your endpoint responds slow, due to large amounts of resources and/or bad caching
you may need to reconfigure your telegraf instance for larger timeouts.