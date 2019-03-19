# Go SecretHub

[![GoDoc](http://img.shields.io/badge/godoc-reference-blue.svg)][godoc]
[![Travis CI](https://travis-ci.org/secrethub/secrethub-go.svg?branch=master)][travis-ci]
[![GolangCI](https://golangci.com/badges/github.com/secrethub/secrethub-go.svg)][golang-ci]
[![Go Report Card](https://goreportcard.com/badge/github.com/secrethub/secrethub-go)][goreportcard] ![Licence](https://img.shields.io/hexpm/l/plug.svg)



The official [SecretHub][secrethub] Go client library.

> SecretHub is a developer tool to help you keep database passwords, API tokens, and other secrets out of IT automation scripts.

<img src="https://secrethub.io/img/secrethub-gopher.png" alt="Gopher" width="200px"/>

## Getting started

### Prerequisites

In order to use the Go client library, you need a __SecretHub account__. You can do this by following the first instructions [here](https://secrethub.io/docs/getting-started/) (*Installing the CLI* and *signing up for a SecretHub account*).

### Installation

Install secrethub-go with:

```sh
go get -u github.com/secrethub/secrethub-go
```

Or install a specific version with:

```sh
go get -u github.com/secrethub/secrethub-go@vX.Y.Z
```

Then, import it using:

``` go
import (
    "github.com/secrethub/secrethub-go/pkg/secrethub"
)
```


## Examples

For details on all functionality of this library, see the [GoDoc][godoc] documentation.

Below are a few simple examples:

```go
import (
	"github.com/secrethub/secrethub-go/pkg/randchar"
	"github.com/secrethub/secrethub-go/pkg/secrethub"
)

// Setup
credential, err := secrethub.NewCredential("<your credential>", "<passphrase>")
client := secrethub.NewClient(credential, nil)

// Write
secret, err := client.Secrets().Write("path/to/secret", []byte("password123"))

// Read
secret, err = client.Secrets().Versions().GetWithData("path/to/secret:latest")
fmt.Println(secret.Data) // prints password123

// Generate a slice of 32 alphanumeric characters.
data, err := randchar.NewGenerator(false).Generate(32)
secret, err = client.Secrets().Write("path/to/secret", data)
```

Note that only packages inside the `/pkg` directory should be considered library code that you can use in your projects. All other code is not guaranteed to be backwards compatible and may change in the future.  

## Development

Pull requests from the community are welcome.
If you'd like to contribute, please checkout [the contributing guidelines](./CONTRIBUTING.md).

## Testing

Run all tests:

    make test

Run tests for one package:

    go test ./pkg/secrethub

Run a single test:

    go test ./pkg/secrethub -run TestSignup

For any requests, bug or comments, please [open an issue][issues] or [submit a
pull request][pulls].

## License

This project is licensed under the Apache License 2.0 - see the LICENSE.md file for details

## Attributions

["gopher.png"][original-gopher] by [Takuya Ueda][tenntenn] is licensed under [CC BY 3.0][creative-commons-3.0]

[original-gopher]: https://camo.githubusercontent.com/98ed65187a84ecf897273d9fa18118ce45845057/68747470733a2f2f7261772e6769746875622e636f6d2f676f6c616e672d73616d706c65732f676f706865722d766563746f722f6d61737465722f676f706865722e706e67
[creative-commons-3.0]: https://creativecommons.org/licenses/by/3.0/
[tenntenn]: https://twitter.com/tenntenn

[secrethub]: https://secrethub.io
[issues]: https://github.com/secrethub/secrethub-go/issues/new
[pulls]: https://github.com/secrethub/secrethub-go/pulls
[godoc]: http://godoc.org/github.com/secrethub/secrethub-go
[golang-ci]: https://golangci.com/r/github.com/secrethub/secrethub-go
[goreportcard]: https://goreportcard.com/report/github.com/secrethub/secrethub-go
[travis-ci]: https://travis-ci.org/secrethub/secrethub-go
