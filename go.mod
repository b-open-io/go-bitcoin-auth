module github.com/b-open-io/go-bitcoin-auth

go 1.24.3

require github.com/bsv-blockchain/go-sdk v0.0.0-00010101000000-000000000000

require (
	github.com/pkg/errors v0.9.1 // indirect
	golang.org/x/crypto v0.37.0 // indirect
)

// commit hash 7e58f8dcb8326e09408d6bdf635590d86bf96f58
replace github.com/bsv-blockchain/go-sdk => github.com/b-open-io/go-sdk v1.1.25-0.20250514235255-7e58f8dcb832
