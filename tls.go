package main

import (
    "errors"
    "strings"
    "io/ioutil"
    "encoding/pem"
    "crypto"
    "crypto/tls"
    "crypto/x509"
    "crypto/rsa"
    "crypto/ecdsa"
)

func loadX509KeyPair(certFile, keyFile, password string) (cert tls.Certificate, err error) {
    certPEMBlock, err := ioutil.ReadFile(certFile)
    if err != nil {
        return
    }
    keyPEMBlock, err := ioutil.ReadFile(keyFile)
    if err != nil {
        return
    }
    return X509KeyPair(certPEMBlock, keyPEMBlock, []byte(password))
}

func X509KeyPair(certPEMBlock, keyPEMBlock, pw []byte) (cert tls.Certificate, err error) {
    var certDERBlock *pem.Block
    for {
        certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
        if certDERBlock == nil {
            break
        }
        if certDERBlock.Type == "CERTIFICATE" {
            cert.Certificate = append(cert.Certificate, certDERBlock.Bytes)
        }
    }

    if len(cert.Certificate) == 0 {
        err = errors.New("crypto/tls: failed to parse certificate PEM data")
        return
    }
    var keyDERBlock *pem.Block
    for {
        keyDERBlock, keyPEMBlock = pem.Decode(keyPEMBlock)
        if keyDERBlock == nil {
            err = errors.New("crypto/tls: failed to parse key PEM data")
            return
        }
        if x509.IsEncryptedPEMBlock(keyDERBlock) {
            out, err2 := x509.DecryptPEMBlock(keyDERBlock, pw)
            if err2 != nil {
                err = err2
                return
            }
            keyDERBlock.Bytes = out
            break
        }
        if keyDERBlock.Type == "PRIVATE KEY" || strings.HasSuffix(keyDERBlock.Type, " PRIVATE KEY") {
            break
        }
    }

    cert.PrivateKey, err = parsePrivateKey(keyDERBlock.Bytes)
    if err != nil {
        return
    }
    // We don't need to parse the public key for TLS, but we so do anyway
    // to check that it looks sane and matches the private key.
    x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
    if err != nil {
        return
    }

    switch pub := x509Cert.PublicKey.(type) {
    case *rsa.PublicKey:
        priv, ok := cert.PrivateKey.(*rsa.PrivateKey)
        if !ok {
            err = errors.New("crypto/tls: private key type does not match public key type")
            return
        }
        if pub.N.Cmp(priv.N) != 0 {
            err = errors.New("crypto/tls: private key does not match public key")
            return
        }
    case *ecdsa.PublicKey:
        priv, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
        if !ok {
            err = errors.New("crypto/tls: private key type does not match public key type")
            return

        }
        if pub.X.Cmp(priv.X) != 0 || pub.Y.Cmp(priv.Y) != 0 {
            err = errors.New("crypto/tls: private key does not match public key")
            return
        }
    default:
        err = errors.New("crypto/tls: unknown public key algorithm")
        return
    }
return
}

// Attempt to parse the given private key DER block. OpenSSL 0.9.8 generates
// PKCS#1 private keys by default, while OpenSSL 1.0.0 generates PKCS#8 keys.
// OpenSSL ecparam generates SEC1 EC private keys for ECDSA. We try all three.
func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
    if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
        return key, nil
    }
    if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
        switch key := key.(type) {
        case *rsa.PrivateKey, *ecdsa.PrivateKey:
            return key, nil
        default:
            return nil, errors.New("crypto/tls: found unknown private key type in PKCS#8 wrapping")
        }
    }
    if key, err := x509.ParseECPrivateKey(der); err == nil {
        return key, nil
    }

    return nil, errors.New("crypto/tls: failed to parse private key")
}
