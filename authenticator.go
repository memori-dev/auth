package auth

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"github.com/shamaton/msgpack"
	"strconv"
	"time"
)

var encoding = base64.RawURLEncoding

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

type Authenticator struct {
	// Required
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey

	// Optional
	EncryptionKey *[32]byte
}

func (self *Authenticator) Parse(token []byte, dst interface{}, ttl int64) error {
	// Check for correct number of sections
	split := bytes.Split(token, []byte{'.'})
	if len(split) != 3 {
		return errors.New("token is missing section(s)")
	}

	// Pull timestamp
	ts, err := strconv.ParseInt(string(split[0]), 10, 64)
	if err != nil {
		return err
	}

	// Check if expired
	if time.Now().Unix()-ttl > ts {
		return errors.New("expired")
	}

	// Pull signature
	sig, err := decode(split[2])
	if err != nil {
		return err
	}

	// Check signature
	if !ed25519.Verify(self.Public, token[:bytes.LastIndex(token, []byte{'.'})], sig) {
		return errors.New("payload or signature was modified")
	}

	// Decode data
	data, err := decode(split[1])
	if err != nil {
		return err
	}

	// Decrypt data
	if self.EncryptionKey != nil {
		var err error
		data, err = decrypt(data, self.EncryptionKey)
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

func (self *Authenticator) Generate(src interface{}) (string, error) {
	// Marshal data
	data, err := msgpack.Marshal(src)
	if err != nil {
		return "", err
	}

	// Encrypt data
	if self.EncryptionKey != nil {
		var err error
		data, err = encrypt(data, self.EncryptionKey)
		if err != nil {
			return "", err
		}
	}

	// Encode data
	data = encode(data)

	// Add a timestamp to the data
	data = bytes.Join([][]byte{[]byte(strconv.FormatInt(time.Now().Unix(), 10)), data}, []byte{'.'})

	// Generate the signature and then the token
	sig := encode(ed25519.Sign(self.Private, data))
	return string(bytes.Join([][]byte{data, sig}, []byte{'.'})), nil
}
