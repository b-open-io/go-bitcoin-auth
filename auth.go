package auth

import (
	"bytes" // For constructing the BRC-77 envelope
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big" // For "anyone can verify" key
	"strings"
	"time"

	// For DoubleHashB
	bsm "github.com/bsv-blockchain/go-sdk/compat/bsm" // Correct package for BRC-77
	"github.com/bsv-blockchain/go-sdk/message"        // Added for BRC-77 Sign/Verify
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	scripts "github.com/bsv-blockchain/go-sdk/script"
)

const brc77VersionString = "42423301" // BRC-77 Message Signing Protocol Version

// GetAuthToken generates an authentication token.
func GetAuthToken(config AuthConfig) (string, error) {
	privateKeyWIF := config.PrivateKeyWIF
	if privateKeyWIF == "" {
		return "", errors.New("PrivateKeyWIF must not be empty")
	}
	if config.RequestPath == "" {
		return "", errors.New("RequestPath must not be empty")
	}

	scheme := config.Scheme
	if scheme == "" {
		scheme = SchemeBRC77
	}
	if scheme != SchemeBRC77 && scheme != SchemeBSM {
		return "", fmt.Errorf("invalid scheme: %s. Must be %s or %s", scheme, SchemeBRC77, SchemeBSM)
	}

	bodyEncoding := config.BodyEncoding
	if bodyEncoding == "" {
		bodyEncoding = EncodingUTF8
	}
	if bodyEncoding != EncodingUTF8 && bodyEncoding != EncodingHex && bodyEncoding != EncodingBase64 {
		return "", fmt.Errorf("invalid bodyEncoding: %s. Must be %s, %s, or %s", bodyEncoding, EncodingUTF8, EncodingHex, EncodingBase64)
	}

	originalSignerPrivKey, err := ec.PrivateKeyFromWif(privateKeyWIF)
	if err != nil {
		return "", fmt.Errorf("failed to parse PrivateKeyWIF: %w", err)
	}
	originalSignerPubKey := originalSignerPrivKey.PubKey()
	compressedPubKeyBytes := originalSignerPubKey.Compressed()
	originalSignerPubKeyHex := hex.EncodeToString(compressedPubKeyBytes)

	timestamp := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")

	bodyHashHex := ""
	if config.Body != "" {
		var bodyBytesToHash []byte
		var decodeErr error
		switch bodyEncoding {
		case EncodingUTF8:
			bodyBytesToHash = []byte(config.Body)
		case EncodingHex:
			bodyBytesToHash, decodeErr = hex.DecodeString(config.Body)
		case EncodingBase64:
			bodyBytesToHash, decodeErr = base64.StdEncoding.DecodeString(config.Body)
		}
		if decodeErr != nil {
			return "", fmt.Errorf("failed to decode body with encoding %s: %w", bodyEncoding, decodeErr)
		}
		hash := sha256.Sum256(bodyBytesToHash)
		bodyHashHex = hex.EncodeToString(hash[:])
	}

	payloadToSignString := fmt.Sprintf("%s|%s|%s", config.RequestPath, timestamp, bodyHashHex)
	payloadToSignBytes := []byte(payloadToSignString) // This is the raw message for BRC-77

	var signatureBase64 string
	if scheme == SchemeBRC77 {
		// Create the "anyone can verify" recipient public key (corresponds to private key D=1)
		anyoneCanVerifyPrivKey, err := ec.NewPrivateKey() // Instantiate
		if err != nil {
			return "", fmt.Errorf("BRC-77: failed to instantiate anyoneCanVerifyPrivKey: %w", err)
		}
		anyoneCanVerifyPrivKey.D = big.NewInt(1)
		// anyoneCanVerifyPubKey := anyoneCanVerifyPrivKey.PubKey() // No longer explicitly needed for Sign if nil implies 'anyone'

		// message.Sign handles BRC-42 derivation and envelope creation
		// Pass nil for forWhom to indicate an "anyone can verify" signature (BRC-77 verifier indicator 0x00)
		signatureEnvelopeBytes, err := message.Sign(payloadToSignBytes, originalSignerPrivKey, nil)
		if err != nil {
			return "", fmt.Errorf("BRC-77: message.Sign failed: %w", err)
		}
		signatureBase64 = base64.StdEncoding.EncodeToString(signatureEnvelopeBytes)

	} else if scheme == SchemeBSM {
		// BSM uses bsm.SignMessage (this part remains unchanged)
		bsmSignatureBytes, err := bsm.SignMessage(originalSignerPrivKey, payloadToSignBytes) // Note: BSM also signs the same payload string
		if err != nil {
			return "", fmt.Errorf("BSM: bsm.SignMessage failed: %w", err)
		}
		signatureBase64 = base64.StdEncoding.EncodeToString(bsmSignatureBytes)
	}

	token := fmt.Sprintf("%s|%s|%s|%s|%s", originalSignerPubKeyHex, scheme, timestamp, config.RequestPath, signatureBase64)
	return token, nil
}

// ParseAuthToken parses a token string into an AuthToken struct.
func ParseAuthToken(tokenString string) (*AuthToken, error) {
	parts := strings.Split(tokenString, "|")
	if len(parts) != 5 {
		return nil, errors.New("invalid token structure: expected 5 parts")
	}

	scheme := parts[1]
	if scheme != SchemeBRC77 && scheme != SchemeBSM {
		return nil, fmt.Errorf("invalid token scheme: %s. Must be %s or %s", scheme, SchemeBRC77, SchemeBSM)
	}

	timestampStr := parts[2]
	_, err := time.Parse("2006-01-02T15:04:05.000Z", timestampStr)
	if err != nil {
		return nil, fmt.Errorf("invalid timestamp format: %s, expected YYYY-MM-DDTHH:mm:ss.sssZ. Error: %w", timestampStr, err)
	}

	return &AuthToken{
		Pubkey:      parts[0],
		Scheme:      scheme,
		Timestamp:   timestampStr,
		RequestPath: parts[3],
		Signature:   parts[4],
	}, nil
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
	options := verifyOptions{
		timePad:      5 * time.Minute,
		bodyEncoding: EncodingUTF8,
	}
	for _, opt := range opts {
		opt(&options)
	}

	if options.bodyEncoding != EncodingUTF8 && options.bodyEncoding != EncodingHex && options.bodyEncoding != EncodingBase64 {
		return false, fmt.Errorf("invalid bodyEncoding option: %s. Must be %s, %s, or %s", options.bodyEncoding, EncodingUTF8, EncodingHex, EncodingBase64)
	}

	parsedToken, err := ParseAuthToken(tokenString)
	if err != nil {
		return false, fmt.Errorf("failed to parse token: %w", err)
	}

	tokenTime, err := time.Parse("2006-01-02T15:04:05.000Z", parsedToken.Timestamp)
	if err != nil {
		return false, fmt.Errorf("invalid timestamp in token: %w", err)
	}
	targetTime, err := time.Parse("2006-01-02T15:04:05.000Z", target.Timestamp)
	if err != nil {
		return false, fmt.Errorf("invalid timestamp in target payload: %w", err)
	}

	lowerBound := targetTime.Add(-options.timePad)
	upperBound := targetTime.Add(options.timePad)

	if tokenTime.Before(lowerBound) || tokenTime.After(upperBound) {
		return false, nil // Timestamp out of allowed window, not an error, just invalid.
	}

	if parsedToken.RequestPath != target.RequestPath {
		return false, nil // Request path mismatch, not an error, just invalid.
	}

	originalSignerPubKeyFromTokenBytes, err := hex.DecodeString(parsedToken.Pubkey)
	if err != nil {
		return false, fmt.Errorf("failed to decode original public key: %w", err)
	}
	originalSignerPubKeyToVerify, err := ec.PublicKeyFromBytes(originalSignerPubKeyFromTokenBytes)
	if err != nil {
		return false, fmt.Errorf("failed to parse original public key: %w", err)
	}

	expectedBodyHashHex := ""
	if target.Body != "" {
		var bodyBytesToHash []byte
		var decodeErr error
		switch options.bodyEncoding {
		case EncodingUTF8:
			bodyBytesToHash = []byte(target.Body)
		case EncodingHex:
			bodyBytesToHash, decodeErr = hex.DecodeString(target.Body)
		case EncodingBase64:
			bodyBytesToHash, decodeErr = base64.StdEncoding.DecodeString(target.Body)
		}
		if decodeErr != nil {
			return false, fmt.Errorf("failed to decode target body with encoding %s: %w", options.bodyEncoding, decodeErr)
		}
		hash := sha256.Sum256(bodyBytesToHash)
		expectedBodyHashHex = hex.EncodeToString(hash[:])
	}

	payloadToVerifyString := fmt.Sprintf("%s|%s|%s", target.RequestPath, parsedToken.Timestamp, expectedBodyHashHex)
	payloadToVerifyBytes := []byte(payloadToVerifyString)

	signatureEnvelopeBytes, err := base64.StdEncoding.DecodeString(parsedToken.Signature)
	if err != nil {
		return false, fmt.Errorf("failed to decode signature: %w", err)
	}

	var isValid bool
	var verificationError error

	if parsedToken.Scheme == SchemeBRC77 {
		// First, check if the public key in the token matches the one in the signature envelope.
		// This needs to be done manually if message.Verify only returns bool, error.
		reader := bytes.NewReader(signatureEnvelopeBytes)
		versionBytes := make([]byte, 4)
		if _, err = reader.Read(versionBytes); err != nil || hex.EncodeToString(versionBytes) != brc77VersionString {
			return false, fmt.Errorf("BRC-77: invalid version or read error from envelope: %v", err)
		}
		senderPubKeyBytesFromEnvelope := make([]byte, 33)
		if _, err = reader.Read(senderPubKeyBytesFromEnvelope); err != nil {
			return false, fmt.Errorf("BRC-77: failed to read sender pubkey from envelope: %w", err)
		}
		if !bytes.Equal(senderPubKeyBytesFromEnvelope, originalSignerPubKeyToVerify.Compressed()) {
			return false, errors.New("BRC-77: public key in token header does not match public key in signature envelope")
		}

		// Now, verify the signature using message.Verify, assuming it returns (bool, error)
		// For "anyone can verify" signatures, forWhom is nil.
		brc77IsValid, err := message.Verify(payloadToVerifyBytes, signatureEnvelopeBytes, nil)
		if err != nil {
			verificationError = fmt.Errorf("BRC-77: message.Verify call failed: %w", err)
			isValid = false
		} else {
			isValid = brc77IsValid
			if !isValid {
				verificationError = errors.New("BRC-77: message.Verify returned false")
			}
		}
	} else if parsedToken.Scheme == SchemeBSM {
		addressForBSM, addrErr := scripts.NewAddressFromPublicKey(originalSignerPubKeyToVerify, true)
		if addrErr != nil {
			return false, fmt.Errorf("BSM: failed to create address: %w", addrErr)
		}
		bsmVerifyErr := bsm.VerifyMessage(addressForBSM.AddressString, signatureEnvelopeBytes, payloadToVerifyBytes)
		isValid = bsmVerifyErr == nil
		if !isValid {
			if bsmVerifyErr != nil {
				verificationError = fmt.Errorf("BSM: verification failed: %w", bsmVerifyErr)
			} else {
				verificationError = errors.New("BSM: verification failed")
			}
		}
	} else {
		return false, fmt.Errorf("unknown scheme for verification: %s", parsedToken.Scheme)
	}

	if !isValid && verificationError != nil {
		return false, verificationError
	}
	if !isValid {
		return false, nil
	}

	return isValid, nil
}
