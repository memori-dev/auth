package auth

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/shamaton/msgpack"
	"strconv"
	"time"
)

var encoding = base64.RawURLEncoding

var (
	ErrExpired  = errors.New("authentication expired")
	ErrModified = errors.New("payload or signature was modified")
)

func encode(src []byte) []byte {
	dst := make([]byte, encoding.EncodedLen(len(src)))
	encoding.Encode(dst, src)

	return dst
}

func decode(src []byte) ([]byte, error) {
	dst := make([]byte, encoding.DecodedLen(len(src)))
	_, err := encoding.Decode(dst, src)
	if err != nil {
		return nil, err
	}

	return dst, nil
}

type Authenticator[A any] struct {
	// Required
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey

	// Optional
	EncryptionKey *[32]byte
}

func (this *Authenticator[A]) Parse(token []byte, dst *A, ttl int64) error {
	// Check for correct number of sections
	split := bytes.Split(token, []byte{'.'})
	if len(split) != 3 {
		return errors.New(fmt.Sprintf("expected 3 sections in token, but received %d", len(split)))
	}

	// Pull timestamp
	ts, err := strconv.ParseInt(string(split[0]), 10, 64)
	if err != nil {
		return err
	}

	// Check if expired
	if time.Now().Unix()-ttl > ts {
		return ErrExpired
	}

	// Pull signature
	sig, err := decode(split[2])
	if err != nil {
		return err
	}

	// Check signature
	if !ed25519.Verify(this.Public, token[:bytes.LastIndex(token, []byte{'.'})], sig) {
		return ErrModified
	}

	// Decode data
	data, err := decode(split[1])
	if err != nil {
		return err
	}

	// Decrypt data
	if this.EncryptionKey != nil {
		var err error
		data, err = decrypt(data, this.EncryptionKey)
		if err != nil {
			return err
		}
	}

	// Unmarshal data
	if err := msgpack.Unmarshal(data, dst); err != nil {
		return err
	}

	return nil
}

func (this *Authenticator[A]) Decode(token []byte, ttl int64) (*A, error) {
	dst := new(A)
	if err := this.Parse(token, dst, ttl); err != nil {
		return nil, err
	}

	return dst, nil
}

func (this *Authenticator[A]) Generate(src *A) ([]byte, error) {
	// Marshal data
	data, err := msgpack.Marshal(src)
	if err != nil {
		return nil, err
	}

	// Encrypt data
	if this.EncryptionKey != nil {
		var err error
		data, err = encrypt(data, this.EncryptionKey)
		if err != nil {
			return nil, err
		}
	}

	// Encode data
	data = encode(data)

	// Add a timestamp to the data
	data = bytes.Join([][]byte{[]byte(strconv.FormatInt(time.Now().Unix(), 10)), data}, []byte{'.'})

	// Generate the signature and then the token
	sig := encode(ed25519.Sign(this.Private, data))
	return bytes.Join([][]byte{data, sig}, []byte{'.'}), nil
}

func (this *Authenticator[A]) GenerateStr(src *A) (string, error) {
	b, err := this.Generate(src)
	if err != nil {
		return "", err
	}

	return string(b), nil
}
