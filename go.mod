module github.com/b-open-io/go-bitcoin-auth

go 1.24.3

require github.com/bsv-blockchain/go-sdk v0.0.0-00010101000000-000000000000

require (
	github.com/pkg/errors v0.9.1 // indirect
	golang.org/x/crypto v0.37.0 // indirect
)

// commit hash 5fe49978cd057edf41293e2871f9c99d495d905d
replace github.com/bsv-blockchain/go-sdk => github.com/b-open-io/go-sdk v1.1.25-0.20250514205758-a0c215bb2eaa
