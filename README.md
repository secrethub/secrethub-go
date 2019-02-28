# Go SecretHub

[![GoDoc](http://img.shields.io/badge/godoc-reference-blue.svg)][godoc]

The official [SecretHub][secrethub] Go client library.

> SecretHub is a developer tool to help you keep database passwords, API tokens, and other secrets out of IT automation scripts. 

## Installation

Install secrethub-go with:

```sh
go get -u github.com/secretub/secrethub-go
```

Then, import it using:

``` go
import (
    "github.com/secrethub/secrethub-go/pkg/secrethub"
)
```

## Documentation

For details on all functionality of this library, see the [GoDoc][godoc] documentation.

Below are a few simple examples:

```go
import (
	"github.com/keylockerbv/secrethub-go/internals/api"
	"github.com/keylockerbv/secrethub-go/pkg/randchar"
	"github.com/keylockerbv/secrethub-go/pkg/secrethub"
)

// Setup
credential, err := secrethub.NewCredential("<your credential>", "<passphrase>")
client := secrethub.NewClient(credential, nil)

// Write
secret, err := client.Secrets().Write(api.SecretPath("path/to/secret"), []byte("password123"))

// Read
secret, err = client.Secrets().Versions().GetWithData(api.SecretPath("path/to/secret:latest"))
fmt.Println(secret.Data) // prints password123

// Generate
data, err := randchar.NewGenerator(false).Generate(32) // Generate a slice of 32 alphanumeric characters.
secret, err = client.Secrets().Write(api.SecretPath("path/to/secret"), data)
```

Note that only packages inside the `/pkg` directory should be considered library code that you can use in your projects. All other code is not guaranteed to be backwards compatible and may change in the future.  

## Development

Pull requests from the community are welcome.
If you'd like to contribute, please checkout [the contributing guidelines](./CONTRIBUTING.md).

## Test

Run all tests:

    make test

Run tests for one package:

    go test ./pkg/secrethub

Run a single test:

    go test ./pkg/secrethub -run TestSignup

For any requests, bug or comments, please [open an issue][issues] or [submit a
pull request][pulls].

[secrethub]: https://secrethub.io
[issues]: https://github.com/secrethub/secrethub-go/issues/new
[pulls]: https://github.com/secrethub/secrethub-go/pulls
[godoc]: http://godoc.org/github.com/secrethub/secrethub-go
