# Bitcoin Auth (Go)

The `go-bitcoin-auth` library simplifies authenticating REST APIs using Bitcoin keys by generating and verifying cryptographic signatures in an `X-Auth-Token` header.

## Installation

To install the `go-bitcoin-auth` library, use `go get`:

```bash
go get github.com/b-open-io/go-bitcoin-auth
```

## Generating an Auth Token

Import the library and generate a token:

```go
import (
	"fmt"
	"time" // Required for timestamp in AuthPayload if you construct it manually for verification

	auth "github.com/b-open-io/go-bitcoin-auth"
)

func main() {
	privateKeyWif := "yourPrivateKeyWif" // Replace with your actual WIF private key
	requestPath := "/some/api/path?param1=value1"
	bodyString := `{"key":"value"}` // Optional: include if your request has a body

	// Generate token with body, default scheme (brc77) and encoding (utf8)
	configWithBody := auth.AuthConfig{
		PrivateKeyWIF: privateKeyWif,
		RequestPath:   requestPath,
		Body:          bodyString,
	}
	token, err := auth.GetAuthToken(configWithBody)
	if err != nil {
		fmt.Println("Error generating token:", err)
		return
	}
	fmt.Println("Generated Token:", token)

	// Generate token without body, using bsm scheme
	configNoBodyBsm := auth.AuthConfig{
		PrivateKeyWIF: privateKeyWif,
		RequestPath:   requestPath,
		Scheme:        auth.SchemeBSM,
	}
	tokenNoBody, err := auth.GetAuthToken(configNoBodyBsm)
	if err != nil {
		fmt.Println("Error generating token (no body, bsm):", err)
		return
	}
	fmt.Println("Generated Token (No Body, BSM):", tokenNoBody)

	// Include it in your API request header: 'X-Auth-Token': token
}
```

## Features

*   **Auth Token Generation & Verification**: Simple functions for handling tokens.
*   **Dual Cryptographic Schemes**: Supports legacy 'bsm' (Bitcoin Signed Message) and modern 'brc77' (recommended, based on [BRC-77](https://github.com/bitcoin-sv/BRCs/blob/master/peer-to-peer/0077.md)).
*   **Minimal Dependencies**: Designed to be lightweight.

## Usage Details

Tokens include:

*   Public key derived from the private key (hex-encoded, compressed)
*   Request path (including query parameters)
*   ISO8601 timestamp (e.g., `2006-01-02T15:04:05.000Z`)
*   SHA256 hash of the body (if present, hex-encoded)
*   Signing scheme ('bsm' or 'brc77')

Token format:

```
pubkey|scheme|timestamp|requestPath|signature
```

Cryptographic schemes:

*   `auth.SchemeBRC77` (`"brc77"`): Default and recommended.
*   `auth.SchemeBSM` (`"bsm"`): Legacy Bitcoin Signed Message.

## Parsing & Verification

### Parsing a Token

```go
import (
	"fmt"
	auth "github.com/b-open-io/go-bitcoin-auth"
)

func main() {
    // Assume 'tokenWithBody' is a previously generated token string
    tokenWithBody := "yourGeneratedTokenString" // Replace with an actual token

	parsedToken, err := auth.ParseAuthToken(tokenWithBody)
	if err != nil {
		fmt.Println("Failed to parse bitcoin-auth token:", err)
		return
	}
	fmt.Printf("Parsed Token: Pubkey: %s, Scheme: %s, Timestamp: %s, Path: %s\n",
		parsedToken.Pubkey, parsedToken.Scheme, parsedToken.Timestamp, parsedToken.RequestPath)
}
```

### Verifying Tokens

```go
import (
	"fmt"
	"time"
	auth "github.com/b-open-io/go-bitcoin-auth"
)

func main() {
    // Assume 'tokenWithBody' and 'tokenNoBodyBsm' are previously generated token strings
	// Assume 'privateKeyWif', 'requestPath', and 'bodyString' are defined as in token generation example
	privateKeyWif := "yourPrivateKeyWif"
	requestPath := "/some/api/path?param1=value1"
	bodyString := `{"key":"value"}`

	// Example: Generate a token to verify (replace with actual token in practice)
	configForVerification := auth.AuthConfig{
		PrivateKeyWIF: privateKeyWif,
		RequestPath:   requestPath,
		Body:          bodyString,
	}
	tokenWithBody, _ := auth.GetAuthToken(configForVerification)

	configNoBodyForVerification := auth.AuthConfig{
		PrivateKeyWIF: privateKeyWif,
		RequestPath:   requestPath,
		Scheme:        auth.SchemeBSM,
	}
	tokenNoBodyBsm, _ := auth.GetAuthToken(configNoBodyForVerification)


	// Verification payload for a token with a body
	// IMPORTANT: Timestamp should be the server's current time when receiving the request
	payloadForVerification := auth.AuthPayload{
		RequestPath: requestPath,
		Timestamp:   time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		Body:        bodyString, // Original, unencoded body string
	}

	isValid, err := auth.VerifyAuthToken(tokenWithBody, payloadForVerification,
		auth.WithTimePad(5*time.Minute),          // Allow 5-minute clock skew
		auth.WithBodyEncoding(auth.EncodingUTF8), // Specify body encoding if not default
	)
	if err != nil {
		fmt.Println("Error verifying token:", err)
	} else {
		fmt.Println("Token with body is valid:", isValid)
	}

	// Verification payload for a token without a body
	payloadNoBody := auth.AuthPayload{
		RequestPath: requestPath,
		Timestamp:   time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
	}

	isValidNoBody, err := auth.VerifyAuthToken(tokenNoBodyBsm, payloadNoBody, auth.WithTimePad(5*time.Minute))
	if err != nil {
		fmt.Println("Error verifying token (no body):", err)
	} else {
		fmt.Println("Token no body (BSM) is valid:", isValidNoBody)
	}
}
```

**Security Note**: Always handle your WIF private key securely. Never expose it in client-side code or commit it to version control without appropriate safeguards.

## API Reference

### `GetAuthToken(config AuthConfig) (string, error)`

Generates an authentication token.

*   `config`: An `AuthConfig` struct containing all necessary parameters:
    *   `PrivateKeyWIF`: Private key in WIF (Wallet Import Format). (Required)
    *   `RequestPath`: The full URL path, including any query parameters. (Required)
    *   `Body`: The request body as a string. Pass an empty string if no body. (Optional)
    *   `Scheme`: Signing scheme (`auth.SchemeBRC77` or `auth.SchemeBSM`). Defaults to `auth.SchemeBRC77` if an empty string is provided in `config.Scheme`.
    *   `BodyEncoding`: Encoding for the `Body` (`auth.EncodingUTF8`, `auth.EncodingHex`, or `auth.EncodingBase64`). Defaults to `auth.EncodingUTF8` if an empty string is provided in `config.BodyEncoding`. Relevant only if `Body` is not empty.

Returns the generated token string and an error if one occurred.

### `VerifyAuthToken(tokenString string, target AuthPayload, opts ...VerifyOption) (bool, error)`

Verifies an authentication token.

*   `tokenString`: The authentication token string to verify.
*   `target`: An `AuthPayload` struct containing the expected values for `RequestPath`, `Timestamp`, and `Body` (if applicable). The timestamp in `target` should be the current time on the server (or the time the request was received), which will be compared against the timestamp in the token.
*   `opts`: Variadic functional options:
    *   `auth.WithTimePad(duration time.Duration)`: Sets the allowed time difference (clock skew) between the token's timestamp and `target.Timestamp`. Defaults to 5 minutes.
    *   `auth.WithBodyEncoding(encoding string)`: Sets the encoding of `target.Body` if present (must be one of `auth.EncodingUTF8`, `auth.EncodingHex`, `auth.EncodingBase64`). Defaults to `auth.EncodingUTF8`. This is used to decode `target.Body` before hashing for comparison if the token includes a body hash.

Returns `true` if the token is valid, `false` otherwise. An error is returned if parsing fails or an unexpected issue occurs during verification (e.g., invalid encoding specified). A `false` result with `nil` error means the token is structurally valid but does not match the target payload (e.g., signature mismatch, timestamp out of range, path mismatch, body hash mismatch).

### `ParseAuthToken(tokenString string) (*AuthToken, error)`

Parses a token string into an `AuthToken` struct.

*   `tokenString`: The authentication token string.

Returns a pointer to an `AuthToken` struct (`{ Pubkey, Scheme, Timestamp, RequestPath, Signature }`) or `nil` and an error if parsing fails (e.g., invalid format, unknown scheme).

## Types

### `AuthToken`

```go
package auth // Assuming these types are in the 'auth' package

// AuthToken represents the parsed structure of an authentication token.
type AuthToken struct {
	Pubkey      string
	Scheme      string
	Timestamp   string // ISO8601 format (e.g., "2006-01-02T15:04:05.000Z")
	RequestPath string
	Signature   string // Base64 encoded signature
}
```

### `AuthPayload`

Data required for signing (implicitly via `AuthConfig`) and verification.

```go
package auth // Assuming these types are in the 'auth' package

// AuthPayload represents the data used for verifying a token against.
type AuthPayload struct {
	RequestPath string
	Timestamp   string // ISO8601 format (e.g., "2006-01-02T15:04:05.000Z"); for verification, this is the server's current/target time
	Body        string // Optional request body string, matching the encoding specified during verification
}
```

Example `AuthPayload` construction:

```go
import (
	"time"
	auth "github.com/b-open-io/go-bitcoin-auth" // Assuming your types are accessible via this import
)

// Payload with a body
payloadWithBody := auth.AuthPayload{
	RequestPath: "/api/items",
	Timestamp:   time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
	Body:        `{"name":"gadget","price":9.99}`,
}

// Payload without a body
payloadNoBody := auth.AuthPayload{
	RequestPath: "/api/items/123",
	Timestamp:   time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
}
```

## Development

Ensure you have Go installed.

To build the library:

```bash
go build ./...
```

To run tests:

```bash
go test ./...
```
