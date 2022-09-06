##Go AES template, laravel’s encrypt and decrypt methods

```
go get github.com/pilotpirks/aes_go_template
```

Example
```
package main

import (
	agt "github.com/pilotpirks/aes_go_template"
	log
)

const (
	// Two key formats are supported
	key := "ffew3ds7um86jcvfructka43gnpfjtuf" // key len = 32
	// key = "base64:UXn0F1XSd2peV2M6mPtEWfeKPVlf5p+j5NqCd3+4/AA="
	
	// key := agt.GetKey()
	test_data = "test_string"
)

func main() {

	enc, err := agt.Encrypt(test_data, key)
	if err != nil {
		log.Fatal("Encrypt Error: %s\n", err)
	}

	dec, err := agt.Decrypt(enc, key)
	if err != nil {
		log.Fatal("Decrypt Error: %s\n", err)
	}

	log.Printf("Enc: %s\n", enc)
	log.Printf("Dec: %s\n", dec)
}

```
