package main

import (
    "log"
    _ "net"
    "io/ioutil"
    "crypto/tls"
    "crypto/x509"
    "time"
    "math/rand"
)

func main() {
    var conn *tls.Conn

    cert, err := loadX509KeyPair("certs/client.crt", "certs/client.key", "Zog1Ri6AWEV9Oe45")

    if err != nil {
        log.Fatalf("server: loadkeys: %s", err)
    }

    rootCACert, err := ioutil.ReadFile("certs/ca.crt")

    if err != nil {
        log.Fatal("Unable to open cert", err)
    }

    rootCertPool := x509.NewCertPool()
    rootCertPool.AppendCertsFromPEM(rootCACert)

    config := &tls.Config{
        Certificates: []tls.Certificate{cert},
        RootCAs: rootCertPool,
        //ClientCAs: rootCertPool,
        InsecureSkipVerify: true,
    }

    for {
        if conn, err = tls.Dial("tcp", "bakery.mufibot.net:6555", config); err != nil {
        //if conn, err = tls.Dial("tcp", "127.0.0.1:6555", config); err != nil {
            log.Fatalf("server: fail: %s", err)
            return;
        }

        defer conn.Close()

        log.Print("server: listening")

        buffer := make([]byte, 512)

        n, err := conn.Read(buffer)

        if err != nil {
            log.Printf("server: error read: %s", err)
            return
        }

        log.Printf("server: conn: echo %q (%d bytes)\n", string(buffer[:n]), n)

        ident := []byte{0x00,0x00,0x00,0x00,0xFA,0x11,0x65,0x01,0x0D,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0B,0x44,0x6F,0x66,0x75,0x73,0x42,0x6F,0x74,0x37,0x37,0x37,0x00,0x09,0x61,0x7A,0x65,0x72,0x74,0x79,0x30,0x30,0x30,0x00,0x40,0x30,0x33,0x39,0x63,0x35,0x62,0x36,0x33,0x63,0x31,0x39,0x31,0x39,0x30,0x38,0x36,0x61,0x36,0x62,0x62,0x37,0x37,0x39,0x66,0x37,0x62,0x38,0x37,0x30,0x39,0x36,0x63,0x66,0x66,0x33,0x65,0x61,0x66,0x66,0x65,0x37,0x31,0x61,0x32,0x35,0x35,0x64,0x34,0x30,0x31,0x64,0x35,0x32,0x34,0x38,0x31,0x38,0x37,0x30,0x38,0x63,0x39,0x32,0x66,0x01,0x00}
        conn.Write(ident)

        n, err = conn.Read(buffer)

        if err != nil {
            log.Printf("server: error read: %s", err)
            return
        }

        log.Printf("server: conn: echo %q (%d bytes)\n", string(buffer[:n]), n)

        i := 1

        for {
            ban := []byte{0x00,0x00,0x00,0x00,0xFA,0x39,0x02,0x00,byte(random(200,225))}
            conn.Write(ban)
            /*acc := []byte{0x00,0x00,0x00,0x00,0xFA,0x1D,0x11,0xC2,0x6E,0x68,0x81,0x00,0x0A,0x62,0x6F,0x74,0x74,0x65,0x73,byte(i),0x37,0x37,0x37,0x00}
            conn.Write(acc)*/
            i++

            n, err = conn.Read(buffer)

            if err != nil {
                log.Printf("server: error read: %s", err)
                break
            }

            log.Printf("server: conn: echo %q (%d bytes)\n", string(buffer[:n]), n)

            time.Sleep(100 * time.Millisecond)
        }
    }
}

func random(min, max int) int {
    return rand.Intn(max-min) + min
}
