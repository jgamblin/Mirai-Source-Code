package main

import (
    "fmt"
    "net"
    "encoding/binary"
    "errors"
    "time"
)

func main() {
    l, err := net.Listen("tcp", "0.0.0.0:48101")
    if err != nil {
        fmt.Println(err)
        return
    }

    for {
        conn, err := l.Accept()
        if err != nil {
            break
        }
        go handleConnection(conn)
    }
}

func handleConnection(conn net.Conn) {
    defer conn.Close()
    conn.SetDeadline(time.Now().Add(10 * time.Second))

    bufChk, err := readXBytes(conn, 1)
    if err != nil {
        return
    }

    var ipInt uint32
    var portInt uint16

    if bufChk[0] == 0 {
        ipBuf, err := readXBytes(conn, 4)
        if err != nil {
            return
        }
        ipInt = binary.BigEndian.Uint32(ipBuf)

        portBuf, err := readXBytes(conn, 2)
        if err != nil {
            return;
        }

        portInt = binary.BigEndian.Uint16(portBuf)
    } else {
        ipBuf, err := readXBytes(conn, 3)
        if err != nil {
            return;
        }
        ipBuf = append(bufChk, ipBuf...)

        ipInt = binary.BigEndian.Uint32(ipBuf)

        portInt = 23
    }

    uLenBuf, err := readXBytes(conn, 1)
    if err != nil {
        return
    }
    usernameBuf, err := readXBytes(conn, int(byte(uLenBuf[0])))

    pLenBuf, err := readXBytes(conn, 1)
    if err != nil {
        return
    }
    passwordBuf, err := readXBytes(conn, int(byte(pLenBuf[0])))
    if err != nil {
        return
    }

    fmt.Printf("%d.%d.%d.%d:%d %s:%s\n", (ipInt >> 24) & 0xff, (ipInt >> 16) & 0xff, (ipInt >> 8) & 0xff, ipInt & 0xff, portInt, string(usernameBuf), string(passwordBuf))
}

func readXBytes(conn net.Conn, amount int) ([]byte, error) {
    buf := make([]byte, amount)
    tl := 0

    for tl < amount {
        rd, err := conn.Read(buf[tl:])
        if err != nil || rd <= 0 {
            return nil, errors.New("Failed to read")
        }
        tl += rd
    }

    return buf, nil
}
