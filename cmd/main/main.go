package main

import (
	"crypto/ed25519"
	"fmt"
	"github.com/memori-dev/auth"
)

type Auth struct {
	Key string
}

func example[T any](secret *T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}

	authenticator := &auth.Authenticator[T]{
		Public:        pub,
		Private:       priv,
		EncryptionKey: auth.NewEncryptionKey(),
	}

	fmt.Printf("secret: %v\n", *secret)

	token, err := authenticator.GenerateStr(secret)
	if err != nil {
		panic(err)
	}
	fmt.Printf("token: %s\n", token)

	out, err := authenticator.Decode([]byte(token), 100)
	if err != nil {
		panic(err)
	}

	fmt.Printf("in: %v, out: %v\n", *secret, *out)
}

func main() {
	// String
	str := "secret"
	example(&str)

	// Auth
	example(&Auth{Key: "secret"})
}
