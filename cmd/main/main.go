package main

import (
	"crypto/ed25519"
	"fmt"
	"github.com/memori-dev/auth"
)

func main() {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}

	authenticator := &auth.Authenticator{
		Public:  pub,
		Private: priv,
		//EncryptionKey: jwt.NewEncryptionKey(),
	}

	message := "data"
	fmt.Println(message)

	token, err := authenticator.Generate(message)
	if err != nil {
		panic(err)
	}
	fmt.Println(token)

	//token = "1647322999" + token[strings.Index(token, "."):]
	//fmt.Println(token)

	data := ""
	if err := authenticator.Parse([]byte(token), &data, 0); err != nil {
		panic(err)
	}

	fmt.Println(data)
}
