<h1>Gencrypt: even easier AES256 encryption for Go</h1>

**Gencrypt** is a Go package that acts as a wrapper around portions of the
standard libraries crypto package.  It depends on only the standard library and
is very small at only 40 lines (uncommented, not including tests):

<pre>
package gencrypt

import (
  "crypto/aes"
  "crypto/cipher"
  "crypto/rand"
)

type Galois struct {
  GCM cipher.AEAD
}

func NewGCM(key []byte) (*Galois, error) {
  g := &Galois{}
  block, err := aes.NewCipher(key[:])
  if err != nil {
    return g, err
  }

  g.GCM, err = cipher.NewGCM(block)
  if err != nil {
    return g, err
  }

  return g, nil
}

func (g *Galois) AESEncrypt(data []byte) ([]byte, error) {
  nonce := make([]byte, g.GCM.NonceSize())
  _, err := rand.Read(nonce)
  if err != nil {
    return nil, err
  }

  return g.GCM.Seal(nonce, nonce, data, nil), nil
}

func (g *Galois) AESDecrypt(data []byte) ([]byte, error) {
  return g.GCM.Open(nil, data[:g.GCM.NonceSize()], data[g.GCM.NonceSize():], nil)
}

</pre>

<h1>Example Usage:</h1>

<pre>
package main

import (
  "fmt"

  "gitlab.com/zfeldt/gencrypt"
)

// NOTE: Error checking not handled in this example but should be in
// production.

var (
  // Data you want to encrypt
  data = []byte("test data")
  // Secret key
  key = []byte("12345678901234561234567890123456")
)

func main() {
  // Get the GCM
  gcm, _ := gencrypt.NewGCM(key)

  // Encrypt data
  enc, _ := gcm.AESEncrypt(data)

  // Decrypt data
  dec, _ := gcm.AESDecrypt(enc)
  fmt.Println(string(dec))
}
</pre>
