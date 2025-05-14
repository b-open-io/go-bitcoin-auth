package auth

// AuthConfig holds the configuration for generating an authentication token.
type AuthConfig struct {
	PrivateKeyWIF string `json:"privateKeyWif"`          // WIF-encoded private key (mandatory)
	RequestPath   string `json:"requestPath"`            // Full API endpoint path (mandatory)
	Body          string `json:"body,omitempty"`         // Optional request body string
	Scheme        string `json:"scheme,omitempty"`       // Optional: "brc77" (default) or "bsm"
	BodyEncoding  string `json:"bodyEncoding,omitempty"` // Optional: "utf8" (default), "hex", or "base64"
}

// AuthToken represents the parsed structure of an authentication token.
type AuthToken struct {
	Pubkey      string `json:"pubkey"`
	Scheme      string `json:"scheme"`
	Timestamp   string `json:"timestamp"` // ISO8601 format
	RequestPath string `json:"requestPath"`
	Signature   string `json:"signature"` // Base64 encoded
}

// AuthPayload represents the data used for verifying a token against.
type AuthPayload struct {
	RequestPath string `json:"requestPath"`
	Timestamp   string `json:"timestamp"`      // ISO8601 format; for verification, this is the server's current/target time
	Body        string `json:"body,omitempty"` // Optional request body string, matching the encoding specified during verification
}

// Constants for schemes and encodings
const (
	SchemeBRC77 = "brc77"
	SchemeBSM   = "bsm"

	EncodingUTF8   = "utf8"
	EncodingHex    = "hex"
	EncodingBase64 = "base64"
)
