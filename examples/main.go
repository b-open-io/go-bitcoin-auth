package main

import (
	"fmt"
	"time"

	auth "github.com/b-open-io/go-bitcoin-auth"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

func main() {
	privateKey, err := ec.NewPrivateKey()
	if err != nil {
		fmt.Printf("Error generating private key: %v\n", err)
	}

	requestPathWithParams := "/api/data?filter=active&page=1"
	requestBodyString := `{"message":"Hello, Bitcoin!"}`

	fmt.Println("--- Token Generation ---")

	// Example 1: Generate token with a body, default scheme (brc77), default encoding (utf8)
	fmt.Println("\nGenerating token with body (brc77, utf8)...")
	configWithBody := auth.AuthConfig{
		PrivateKeyWIF: privateKey.Wif(),
		RequestPath:   requestPathWithParams,
		Body:          requestBodyString,
		// Scheme and BodyEncoding will use defaults (brc77, utf8)
	}
	tokenWithBody, err := auth.GetAuthToken(configWithBody)
	if err != nil {
		fmt.Printf("Error generating token with body: %v\n", err)
	} else {
		fmt.Printf("Generated Token: %s\n", tokenWithBody)
	}

	// Example 2: Generate token without a body, using BSM scheme
	fmt.Println("\nGenerating token without body (bsm)...")
	requestPathNoParams := "/api/action"
	configNoBodyBsm := auth.AuthConfig{
		PrivateKeyWIF: privateKey.Wif(),
		RequestPath:   requestPathNoParams,
		Scheme:        auth.SchemeBSM,
	}
	tokenNoBodyBsm, err := auth.GetAuthToken(configNoBodyBsm)
	if err != nil {
		fmt.Printf("Error generating token (no body, bsm): %v\n", err)
	} else {
		fmt.Printf("Generated Token: %s\n", tokenNoBodyBsm)
	}

	// Example 3: Generate token with a body, brc77 scheme, and base64 encoded body
	fmt.Println("\nGenerating token with base64 encoded body (brc77)...")
	// Note: The actual body content for base64 would typically be binary data encoded as base64.
	// For this example, we'll use the same JSON string, but imagine it's base64.
	// The library expects the string passed to `body` to be the *already encoded* string if bodyEncoding is 'base64' or 'hex'.
	bodyAsBase64 := "eyJtZXNzYWdlIjoiSGVsbG8sIEJpdGNvaW4hIn0=" // This is base64 of `{"message":"Hello, Bitcoin!"}`
	configWithBase64Body := auth.AuthConfig{
		PrivateKeyWIF: privateKey.Wif(),
		RequestPath:   requestPathWithParams,
		Body:          bodyAsBase64,
		Scheme:        auth.SchemeBRC77,
		BodyEncoding:  auth.EncodingBase64,
	}
	tokenWithBase64Body, err := auth.GetAuthToken(configWithBase64Body)
	if err != nil {
		fmt.Printf("Error generating token with base64 body: %v\n", err)
	} else {
		fmt.Printf("Generated Token: %s\n", tokenWithBase64Body)
	}

	fmt.Println("\n--- Token Parsing & Verification ---")

	// Parsing Example (using tokenWithBody from above)
	if tokenWithBody != "" {
		fmt.Println("\nParsing token with body...")
		parsedToken, err := auth.ParseAuthToken(tokenWithBody)
		if err != nil {
			fmt.Printf("Error parsing token: %v\n", err)
		} else {
			fmt.Printf("Successfully parsed token:\n  Pubkey: %s\n  Scheme: %s\n  Timestamp: %s\n  RequestPath: %s\n  Signature: %s... (truncated)\n",
				parsedToken.Pubkey, parsedToken.Scheme, parsedToken.Timestamp, parsedToken.RequestPath, parsedToken.Signature[:20])
		}
	}

	// Verification Example 1 (using tokenWithBody)
	if tokenWithBody != "" {
		fmt.Println("\nVerifying token with body (brc77, utf8)...")
		// IMPORTANT: For verification, the timestamp in AuthPayload should be current time on the server.
		// The token's embedded timestamp will be compared against this, allowing for a timePadMinutes skew.
		payloadForVerification := auth.AuthPayload{
			RequestPath: requestPathWithParams,
			Timestamp:   time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
			Body:        requestBodyString, // Original, unencoded body string
		}
		isValid, err := auth.VerifyAuthToken(tokenWithBody, payloadForVerification,
			auth.WithTimePad(5*time.Minute),
			auth.WithBodyEncoding(auth.EncodingUTF8),
		)
		if err != nil {
			fmt.Printf("Error verifying token: %v\n", err)
		} else {
			fmt.Printf("Token verification successful: %t\n", isValid)
		}

		// Example of failed verification due to body mismatch
		fmt.Println("\nVerifying token with incorrect body...")
		payloadMismatch := auth.AuthPayload{
			RequestPath: requestPathWithParams,
			Timestamp:   time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
			Body:        "different body",
		}
		isValid, err = auth.VerifyAuthToken(tokenWithBody, payloadMismatch,
			auth.WithTimePad(5*time.Minute),
			auth.WithBodyEncoding(auth.EncodingUTF8),
		)
		if err != nil {
			fmt.Printf("Error during verification (expected due to mismatch): %v\n", err)
		} else if !isValid {
			fmt.Printf("Token verification failed as expected due to body mismatch.\n")
		} else {
			fmt.Printf("Token verification successful (unexpected for mismatch): %t\n", isValid)
		}
	}

	// Verification Example 2 (using tokenNoBodyBsm)
	if tokenNoBodyBsm != "" {
		fmt.Println("\nVerifying token without body (bsm)...")
		payloadNoBodyVerify := auth.AuthPayload{
			RequestPath: requestPathNoParams,
			Timestamp:   time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		}
		isValid, err := auth.VerifyAuthToken(tokenNoBodyBsm, payloadNoBodyVerify, auth.WithTimePad(5*time.Minute)) // Default body encoding is utf8, not relevant here
		if err != nil {
			fmt.Printf("Error verifying token: %v\n", err)
		} else {
			fmt.Printf("Token verification successful: %t\n", isValid)
		}
	}

	// Verification Example 3 (using tokenWithBase64Body)
	if tokenWithBase64Body != "" {
		fmt.Println("\nVerifying token with base64 encoded body (brc77)...")
		payloadForBase64Verification := auth.AuthPayload{
			RequestPath: requestPathWithParams,
			Timestamp:   time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
			Body:        bodyAsBase64, // The *already encoded* base64 string
		}
		isValid, err := auth.VerifyAuthToken(tokenWithBase64Body, payloadForBase64Verification,
			auth.WithTimePad(10*time.Minute), // Example with different time pad
			auth.WithBodyEncoding(auth.EncodingBase64),
		)
		if err != nil {
			fmt.Printf("Error verifying base64 token: %v\n", err)
		} else {
			fmt.Printf("Token verification successful: %t\n", isValid)
		}
	}

	fmt.Println("\n--- End of Examples ---")
	fmt.Println("Ensure your privateKeyWif is kept secure and not hardcoded in production.")
}
