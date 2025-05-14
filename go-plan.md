# Go Porting Plan: bitcoin-auth Library

## 1. Overview
   - **Purpose:** The `bitcoin-auth` library simplifies authenticating REST APIs using Bitcoin keys. It provides utilities to generate and verify cryptographic signatures, typically transmitted in an `X-Auth-Token` HTTP header.
   - **Goal:** To create a Go language equivalent of the existing TypeScript `bitcoin-auth` library, offering the same core functionality, API structure, and security characteristics.

## 2. Core Concepts (from TypeScript version)
   - **Auth Token:** A string formatted as `pubkey|scheme|timestamp|requestPath|signature`.
     - `pubkey`: The hex-encoded public key corresponding to the private key used for signing.
     - `scheme`: The cryptographic signature scheme used ("brc77" or "bsm").
     - `timestamp`: ISO8601 formatted timestamp indicating when the token was generated.
     - `requestPath`: The full request path, including any query parameters, that is being authenticated.
     - `signature`: The Base64 encoded cryptographic signature.
   - **Signing Schemes:**
     - `brc77` (Default): Utilizes BRC-77 specifications for signing, typically via a method like `SignedMessage.sign()` from a BSV-compatible SDK.
     - `bsm`: Uses the legacy Bitcoin Signed Message format, typically via a method like `BSM.sign()`.
   - **Body Hashing:** If a request body is included in the authentication, its SHA256 hash (hex encoded) is part of the message signed.
   - **Body Encodings:** The request body string can be interpreted as `utf8` (default), `hex`, or `base64` before hashing.

## 3. Proposed Go Project Structure
   ```
   bitcoin-auth-go/
   ├── go.mod
   ├── README.md
   ├── auth.go         // Core logic for token generation, parsing, verification
   ├── auth_test.go    // Unit tests
   ├── types.go        // Struct definitions (AuthConfig, AuthToken, AuthPayload)
   └── examples/       // Optional: Usage examples
       └── main.go
   ```

## 4. Go Data Structures (to be defined in `types.go`)

   ```go
   package auth

   // AuthConfig holds the configuration for generating an authentication token.
   type AuthConfig struct {
       PrivateKeyWIF string // WIF-encoded private key (mandatory)
       RequestPath   string // Full API endpoint path (mandatory)
       Body          string // Optional request body string
       Scheme        string // Optional: "brc77" (default) or "bsm"
       BodyEncoding  string // Optional: "utf8" (default), "hex", or "base64"
   }

   // AuthToken represents the parsed structure of an authentication token.
   type AuthToken struct {
       Pubkey      string
       Scheme      string
       Timestamp   string // ISO8601 format
       RequestPath string
       Signature   string // Base64 encoded
   }

   // AuthPayload represents the data used for verifying a token against.
   type AuthPayload struct {
       RequestPath string
       Timestamp   string // ISO8601 format; for verification, this is the server's current/target time
       Body        string // Optional request body string, matching the encoding specified during verification
   }

   // Constants for schemes and encodings
   const (
       SchemeBRC77 = "brc77"
       SchemeBSM   = "bsm"

       EncodingUTF8   = "utf8"
       EncodingHex    = "hex"
       EncodingBase64 = "base64"
   )
   ```

## 5. Go API Design (to be implemented in `auth.go`)

   ```go
   package authalb

   import "time"

   // GetAuthToken generates an authentication token.
   func GetAuthToken(config AuthConfig) (string, error) {
       // ... implementation ...
   }

   // ParseAuthToken parses a token string into an AuthToken struct.
   func ParseAuthToken(tokenString string) (*AuthToken, error) {
       // ... implementation ...
   }

   // VerifyOption defines a functional option for VerifyAuthToken.
   type VerifyOption func(*verifyOptions)

   type verifyOptions struct {
       timePad      time.Duration
       bodyEncoding string
   }

   // WithTimePad sets the time padding for token verification.
   func WithTimePad(duration time.Duration) VerifyOption {
       return func(o *verifyOptions) {
           o.timePad = duration
       }
   }

   // WithBodyEncoding sets the body encoding for token verification.
   func WithBodyEncoding(encoding string) VerifyOption {
       return func(o *verifyOptions) {
           o.bodyEncoding = encoding
       }
   }

   // VerifyAuthToken verifies an authentication token against a target payload.
   // Default timePad is 5 minutes. Default bodyEncoding is "utf8".
   func VerifyAuthToken(tokenString string, target AuthPayload, opts ...VerifyOption) (bool, error) {
       // ... implementation ...
   }
   ```

## 6. Detailed Functional Requirements & Implementation Guidance

### 6.1. `GetAuthToken(config AuthConfig) (string, error)`
   - **Input Validation:**
     - `config.PrivateKeyWIF` must not be empty.
     - `config.RequestPath` must not be empty.
   - **Defaults:**
     - If `config.Scheme` is empty, use `SchemeBRC77`.
     - If `config.BodyEncoding` is empty, use `EncodingUTF8`. Validate against known encodings.
   - **Steps:**
      1.  **Private Key & Public Key:**
          - Use a Go Bitcoin library to parse `config.PrivateKeyWIF` into a private key object.
          - Derive the corresponding public key. Convert the public key to its compressed hex string representation.
      2.  **Timestamp:**
          - Get the current time in UTC.
          - Format it as an ISO8601 string (e.g., `YYYY-MM-DDTHH:MM:SS.mmmZ`). `time.Now().UTC().Format(time.RFC3339Nano)` can be customized to match the exact precision.
      3.  **Body Processing & Hashing:**
          - `bodyHashHex := ""`
          - If `config.Body` is not empty:
              - Convert `config.Body` (string) to `[]byte` based on `config.BodyEncoding`:
                  - `EncodingUTF8`: `bodyBytes := []byte(config.Body)`
                  - `EncodingHex`: `bodyBytes, err := hex.DecodeString(config.Body)`
                  - `EncodingBase64`: `bodyBytes, err := base64.StdEncoding.DecodeString(config.Body)`
                  - Handle potential decoding errors.
              - Calculate SHA256 hash of `bodyBytes`: `hash := sha256.Sum256(bodyBytes)`.
              - Convert the hash to a lowercase hex string: `bodyHashHex = hex.EncodeToString(hash[:])`.
      4.  **Message Construction:**
          - `messageToSign := fmt.Sprintf("%s|%s|%s", config.RequestPath, timestamp, bodyHashHex)`
          - `messageBytes := []byte(messageToSign)`
      5.  **Signature Generation (Crypto):**
          - `signatureBase64 := ""`
          - If `config.Scheme == SchemeBRC77`:
              - Sign `messageBytes` using the private key with a BRC-77 compliant method (e.g., `SignedMessage.Sign(messageBytes, privateKey)` if the library supports it directly).
              - The result from the signing function (if it's raw bytes) must be Base64 standard encoded.
          - Else if `config.Scheme == SchemeBSM`:
              - Sign `messageBytes` using the private key with a BSM compliant method (e.g., `BSM.Sign(messageBytes, privateKey)`). This usually involves a specific prefix like "Bitcoin Signed Message:\n" and hashing. The library function should ideally handle this and return a Base64 encoded signature directly.
          - Handle potential signing errors.
      6.  **Token Assembly:**
          - `token := fmt.Sprintf("%s|%s|%s|%s|%s", pubKeyHex, config.Scheme, timestamp, config.RequestPath, signatureBase64)`
      7.  Return `token, nil`.

### 6.2. `ParseAuthToken(tokenString string) (*AuthToken, error)`
   - **Steps:**
      1.  `parts := strings.Split(tokenString, "|")`
      2.  If `len(parts) != 5`, return `nil, errors.New("invalid token structure: expected 5 parts")`.
      3.  `scheme := parts[1]`
      4.  If `scheme != SchemeBRC77 && scheme != SchemeBSM`, return `nil, errors.New("invalid token scheme")`.
      5.  `timestampStr := parts[2]`
      6.  Attempt to parse `timestampStr` (e.g., `time.Parse(time.RFC3339Nano, timestampStr)`). If error, return `nil, errors.New("invalid timestamp format")`.
      7.  Return `&AuthToken{Pubkey: parts[0], Scheme: scheme, Timestamp: timestampStr, RequestPath: parts[3], Signature: parts[4]}, nil`.

### 6.3. `VerifyAuthToken(tokenString string, target AuthPayload, opts ...VerifyOption)`
   - **Options Processing:**
     - `options := verifyOptions{timePad: 5 * time.Minute, bodyEncoding: EncodingUTF8}`
     - Apply `opts`.
   - **Steps:**
      1.  `parsedToken, err := ParseAuthToken(tokenString)`
      2.  If `err != nil` or `parsedToken == nil`, return `false, err`.
      3.  **Timestamp Verification:**
          - `tokenTime, err := time.Parse(time.RFC3339Nano, parsedToken.Timestamp)` (handle error)
          - `targetTime, err := time.Parse(time.RFC3339Nano, target.Timestamp)` (handle error)
          - `lowerBound := targetTime.Add(-options.timePad)`
          - `upperBound := targetTime.Add(options.timePad)`
          - If `tokenTime.Before(lowerBound) || tokenTime.After(upperBound)`, return `false, nil` (or a specific "timestamp out of range" error).
      4.  **Request Path Verification:**
          - If `parsedToken.RequestPath != target.RequestPath`, return `false, nil` (or "request path mismatch" error).
      5.  **Public Key Validation (Crypto):**
          - Attempt to parse/validate `parsedToken.Pubkey` as a valid public key hex string using the Bitcoin library. If it fails, return `false, errors.New("invalid public key in token")`.
      6.  **Target Body Processing & Hashing:**
          - `expectedBodyHashHex := ""`
          - If `target.Body` is not empty:
              - Convert `target.Body` (string) to `[]byte` based on `options.bodyEncoding` (similar to `GetAuthToken`, handle errors).
              - Calculate SHA256 hash: `hash := sha256.Sum256(bodyBytes)`.
              - `expectedBodyHashHex = hex.EncodeToString(hash[:])`.
      7.  **Message Reconstruction for Verification:**
          - `messageToVerify := fmt.Sprintf("%s|%s|%s", target.RequestPath, parsedToken.Timestamp, expectedBodyHashHex)`
          - `messageBytes := []byte(messageToVerify)`
      8.  **Signature Verification (Crypto):**
          - `signatureBytes, err := base64.StdEncoding.DecodeString(parsedToken.Signature)` (handle error)
          - `isValid := false`
          - If `parsedToken.Scheme == SchemeBRC77`:
              - `isValid, err = BRC77Verify(messageBytes, signatureBytes, parsedToken.Pubkey)` (using a hypothetical BRC-77 verify function from the lib).
          - Else if `parsedToken.Scheme == SchemeBSM`:
              - `isValid, err = BSMVerify(messageBytes, parsedToken.Signature /*BSM often takes base64 sig directly*/, parsedToken.Pubkey)` (using a hypothetical BSM verify).
          - Handle verification errors (e.g., signature malformed vs. signature invalid).
      9.  Return `isValid, nil`.

## 7. Cryptographic Operations & Dependencies
   - A Go library providing Bitcoin primitives is essential. Potential candidates: `github.com/libsv/go-bk` (Bitcoin SV specific), `github.com/btcsuite/btcd` (more Bitcoin Core focused, but has primitives), or others. The choice will depend on direct support for BSM and BRC-77 like signing/verification.
   - **Required primitives from the library:**
      - WIF decoding into a private key structure.
      - Derivation of a public key (compressed hex format) from a private key.
      - SHA256 hashing: `crypto/sha256` from Go standard library.
      - Hex encoding/decoding: `encoding/hex` from Go standard library.
      - Base64 encoding/decoding: `encoding/base64` from Go standard library.
      - **BSM Signing:** A function that takes message bytes and a private key, performs the BSM-specific hashing and prefixing, signs, and returns a Base64 encoded signature string.
      - **BSM Verification:** A function that takes original message bytes, a Base64 encoded signature string, and a public key (hex or object), and returns a boolean.
      - **BRC-77 Signing (`SignedMessage.Sign` equivalent):** A function that takes message bytes and a private key, signs according to BRC-77 (which might involve its own specific message preparation different from BSM), and returns the raw signature bytes. The Go wrapper will then Base64 encode this.
      - **BRC-77 Verification (`SignedMessage.Verify` equivalent):** A function that takes original message bytes, raw signature bytes (after Base64 decoding in Go code), and a public key (hex or object), and returns a boolean.
   - **Fallback:** If direct BRC-77 high-level functions are unavailable, the library must provide low-level ECDSA signing and verification on the `secp256k1` curve, and the BRC-77 message formatting/hashing logic would need to be implemented manually in Go, ensuring it matches the behavior of `@bsv/sdk`.

## 8. Testing Strategy (`auth_test.go`)
   - Use Go's standard `testing` package.
   - **Test Table / Subtests:** Employ table-driven tests for various scenarios.
   - **Golden Test Vectors:** Generate a set of test vectors (WIF, path, body, scheme, encoding -> expected token components, especially signature) using the reference TypeScript implementation. This is crucial for ensuring cross-language compatibility if exact signature matching is desired, though the primary goal is successful verification.
   - **Coverage:**
      - `GetAuthToken`:
         - All combinations of `scheme` and `bodyEncoding`.
         - With and without `body`.
         - Paths with and without query parameters.
         - Error conditions (e.g., invalid WIF).
      - `ParseAuthToken`:
         - Valid tokens for both schemes.
         - Malformed tokens (incorrect part count, invalid scheme, bad timestamp format).
      - `VerifyAuthToken`:
         - Successful verification for all valid scheme/encoding combinations.
         - Timestamp mismatches (within and outside `timePad`).
         - `RequestPath` mismatches.
         - `Body` content mismatches.
         - `BodyEncoding` mismatches between generation and verification.
         - Invalid signatures (tampered, wrong key).
         - Invalid public key format in token.
         - Malformed token string input.
   - **Time Mocking:** For consistent timestamp-related tests, consider a helper to inject or mock `time.Now()`.

## 9. Go `README.md` Structure
   - Project title and brief description.
   - Installation: `go get github.com/yourusername/bitcoin-auth-go` (or final path).
   - **Usage Examples (Go code snippets):**
     - Basic token generation (`GetAuthToken`).
     - Token generation with body and different schemes/encodings.
     - Token parsing (`ParseAuthToken`).
     - Token verification (`VerifyAuthToken`) with and without options.
   - **API Reference:**
     - Brief description of `AuthConfig`, `AuthToken`, `AuthPayload` structs.
     - Signatures and descriptions for `GetAuthToken`, `ParseAuthToken`, `VerifyAuthToken`, and functional options like `WithTimePad`, `WithBodyEncoding`.
   - Development: `go build`, `go test`.
   - License.

## 10. General Go Idioms & Best Practices
    - Adhere to standard Go formatting (`gofmt`/`goimports`).
    - Use idiomatic error handling (return `error` as the last value). Define custom error types or use `fmt.Errorf` / `errors.New` as appropriate.
    - Write clear, concise Go documentation comments for all exported types, functions, and constants.
    - Ensure thread-safety if any global state is used (though this library is unlikely to require it).
    - Strive for minimal external dependencies beyond the core Bitcoin library and standard library.