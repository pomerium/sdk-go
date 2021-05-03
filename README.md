[![Build Status](https://github.com/pomerium/sdk-go/workflows/build/badge.svg)](https://github.com/pomerium/sdk-go/actions?workflow=build)
[![codecov](https://img.shields.io/codecov/c/github/pomerium/sdk-go.svg?style=flat)](https://codecov.io/gh/pomerium/sdk-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/pomerium/sdk-go)](https://goreportcard.com/report/github.com/pomerium/sdk-go)
[![GoDoc](https://godoc.org/github.com/pomerium/sdk-go?status.svg)](https://godoc.org/github.com/pomerium/sdk-go)
[![LICENSE](https://img.shields.io/github/license/pomerium/sdk-go.svg)](https://github.com/pomerium/sdk-go/blob/master/LICENSE)
[![pomerium chat](https://img.shields.io/badge/chat-on%20slack-blue.svg?style=flat&logo=slack)](http://slack.pomerium.io)

# Pomerium's Go (Golang) SDK

In addition to being able centralize identity-aware access, [Pomerium](https://pomerium.com/) can be used to pass request, and user context to upstream applications as JSON Web Tokens (JWT). 

This packges aims to make verifying that attestation token easier and includes:

- http middleware (works with any `http.Handler` compatible router)
- SDK
- An example web app ( live @ https://verify.pomerium.com)

For more details, see the docs on [Getting the user's identity](https://www.pomerium.com/docs/topics/getting-users-identity.html#prerequisites). 

## TL;DR show me 

![screenshot](https://github.com/pomerium/sdk-go/blob/master/.github/screenshot.png)
