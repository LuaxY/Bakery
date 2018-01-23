package main

import (
    "log"
    _ "net"
    "io/ioutil"
    "crypto/tls"
    "crypto/x509"
    _ "time"
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
        //RootCAs: rootCertPool,
        ClientCAs: rootCertPool,
        InsecureSkipVerify: true,
    }

    //if conn, err = tls.Dial("tcp", "bakery.mufibot.net:6555", config); err != nil {
    if conn, err = tls.Dial("tcp", "127.0.0.1:6555", config); err != nil {
        log.Fatalf("server: fail: %s", err)
        return;
    }

    defer conn.Close()

    log.Print("server: listening")

    buffer := make([]byte, 512)

    for {
        n, err := conn.Read(buffer)

        if err != nil {
            log.Printf("server: error read: %s", err)
            break
        }

        log.Printf("server: conn: echo %q (%d bytes)\n", string(buffer[:n]), n)
        //time.Sleep(1 * time.Second)
    }
}
