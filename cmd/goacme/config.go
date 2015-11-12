package main

type userConfig struct {
}

//func readKey() (*rsa.PrivateKey, error) {
//	b, err := ioutil.ReadFile(*keyPath)
//	if err != nil {
//		return nil, err
//	}
//	d, _ := pem.Decode(b)
//	if d == nil {
//		return nil, fmt.Errorf("no block found in %q", *keyPath)
//	}
//	if d.Type != "RSA PRIVATE KEY" {
//		return nil, fmt.Errorf("%q is unsupported", d.Type)
//	}
//	return x509.ParsePKCS1PrivateKey(d.Bytes)
//}
