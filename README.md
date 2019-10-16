<p align="center">
  <a name="secrethub">
    <img src="https://secrethub.io/img/secrethub-logo.svg" alt="SecretHub" width="380px"/>
  </a>
</p>
<h1 align="center">
  <i>Go Client</i>
</h1>

[![GoDoc](http://img.shields.io/badge/godoc-reference-blue.svg)][godoc]
[![CircleCI](https://circleci.com/gh/secrethub/secrethub-go.svg?style=shield)][circle-ci]
[![GolangCI](https://golangci.com/badges/github.com/secrethub/secrethub-go.svg)][golang-ci]
[![Go Report Card](https://goreportcard.com/badge/github.com/secrethub/secrethub-go)][goreportcard]
[![Version]( https://img.shields.io/github/release/secrethub/secrethub-go.svg)][latest-version]
[![Discord](https://img.shields.io/badge/chat-on%20discord-7289da.svg?logo=discord)][discord]

`secrethub-go` provides a client for various SecretHub APIs.

> [SecretHub][secrethub] is an end-to-end encrypted secret management service that helps developers keep database passwords, API keys, and other secrets out of source code.

<img src="https://secrethub.io/img/secrethub-gopher.png" alt="Gopher" width="160px"/>

## Getting started

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

> **Note:** only packages inside the `/pkg` directory should be considered library code that you can use in your projects. 
> All other code is not guaranteed to be backwards compatible and may change in the future.

## Examples

For details on all functionality of this library, see the [GoDoc][godoc] documentation.

Below are a few simple examples:

### Read Secrets
```go
package main

import (
    "fmt"

    "github.com/secrethub/secrethub-go/pkg/secrethub"
)

func main() {
    client, _ := secrethub.NewClient()
    secret, _ := client.Secrets().ReadString("path/to/db/pass")
    fmt.Println(secret)
    // Output: wFc16W#96N1$
}
```

### Write Secrets
```go
package main

import (
    "fmt"

    "github.com/secrethub/secrethub-go/pkg/secrethub"
)

func main() {
    client, _ := secrethub.NewClient()
    _, _ = client.Secrets().Write("path/to/secret", []byte("password123"))
}
```

### Generate Secrets
```go
package main

import (
    "fmt"

    "github.com/secrethub/secrethub-go/pkg/randchar"
    "github.com/secrethub/secrethub-go/pkg/secrethub"
)

func main() {
    client, _ := secrethub.NewClient()
    rand, _ := randchar.NewRand(randchar.Alphanumeric)
    data, _ := rand.Generate(30)
    _, _ = client.Secrets().Write("path/to/secret", data)
}
```

> **Note:** to use the SecretHub Go client, you need to provide a credential for your __SecretHub__ account. 
> You can create a free developer account by [signing up through the CLI](https://secrethub.io/docs/getting-started/). 
> 
> After signup, the credential is located at `$HOME/.secrethub/credential` by default.

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

## Getting help

If you get stuck or just want advice, come chat with the engineers on [Discord][discord] or send an email to [support@secrethub.io](mailto:support@secrethub.io)

## Attributions

["gopher.png"][original-gopher] by [Takuya Ueda][tenntenn] is licensed under [CC BY 3.0][creative-commons-3.0]

[original-gopher]: https://camo.githubusercontent.com/98ed65187a84ecf897273d9fa18118ce45845057/68747470733a2f2f7261772e6769746875622e636f6d2f676f6c616e672d73616d706c65732f676f706865722d766563746f722f6d61737465722f676f706865722e706e67
[creative-commons-3.0]: https://creativecommons.org/licenses/by/3.0/
[tenntenn]: https://twitter.com/tenntenn

[secrethub]: https://secrethub.io
[latest-version]: https://github.com/secrethub/secrethub-go/releases/latest
[issues]: https://github.com/secrethub/secrethub-go/issues/new
[pulls]: https://github.com/secrethub/secrethub-go/pulls
[godoc]: http://godoc.org/github.com/secrethub/secrethub-go
[golang-ci]: https://golangci.com/r/github.com/secrethub/secrethub-go
[goreportcard]: https://goreportcard.com/report/github.com/secrethub/secrethub-go
[circle-ci]: https://circleci.com/gh/secrethub/secrethub-go
[discord]: https://discord.gg/EQcE87s
