<h1>Gencrypt: even easier AES256 encryption for Go</h1>

**Gencrypt** is a Go package that acts as a wrapper around portions of the
standard libraries crypto package.  It depends on only the standard library and
is very small at only 40 lines (uncommented, not including tests).

<h1>Example Usage:</h1>

```go
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
  // Secret key. A 32-byte key is used to indicate AES-256. 16 and 24-byte keys
  // are accepted for AES-128 and AES-192 respectively, but are not
  // recommended.
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
```

<h1>NOTE:</h1> For those deploying on systems not equipped with CPUs supporting
AES-NI [0], you should be aware of possible bottle-necks when it comes to
the AES encryption process [1].
> Final caveat, all these recommendations apply only to the amd64
> architecture, for which fast, constant time implementations of the crypto
> primitives (AES-GCM, ChaCha20-Poly1305, P256) are available. Other
> architectures are probably not fit for production use. [1]

[0] https://en.wikipedia.org/wiki/AES_instruction_set#New_instructions

[1] https://blog.gopheracademy.com/advent-2016/exposing-go-on-the-internet/
