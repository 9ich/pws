package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"sort"

	"code.google.com/p/go.crypto/pbkdf2"
)

const (
	SaltLen         = 16     // Salt length, bytes
	KeyLen          = 16     // Derived key length (16 for AES-128), bytes
	NonceLen        = 12     // Nonce length (12 for GCM), bytes
	NIters          = 100000 // Current number of key derivation iterations
	DefaultFile     = ".pws" // Default db file name
	FieldsPerRecord = 5      // CSV fields per record
	Comma           = '|'    // CSV comma
)

var Magic = []byte{'p', 'w', 's', '2'}

var stdin = bufio.NewReader(os.Stdin)

func main() {
	log.SetFlags(0)
	log.SetPrefix("pws: ")

	path := flag.String("f", "", "path to password store file")
	flag.Parse()

	if *path == "" {
		u, err := user.Current()
		if err != nil {
			log.Fatal(err)
		}
		*path = u.HomeDir + string(os.PathSeparator) + DefaultFile
	}

	// Create the db file if it doesn't exist
	if f, _ := os.Open(*path); f == nil {
		if err := create(*path); err != nil {
			log.Fatal(err)
		}
		if flag.Arg(0) != "a" && flag.Arg(0) != "A" {
			return // Don't list if db was just created
		}
	} else {
		f.Close()
	}

	switch flag.Arg(0) {
	case "a":
		addEntry(*path)
	case "del":
		delEntry(*path, flag.Arg(1), flag.Arg(2))
	case "p":
		setMaster(*path)
	default:
		listEntries(*path)
	}
}

type Entry struct {
	srv   string
	user  string
	email string
	pass  string
	notes string
}

func (e Entry) String() string {
	return fmt.Sprintf("%s / %s / %s / %s / %s",
		e.srv, e.user, e.email, e.pass, e.notes)
}

type Entries []Entry // sort.Interface

func (e Entries) Len() int           { return len(e) }
func (e Entries) Swap(i, j int)      { e[i], e[j] = e[j], e[i] }
func (e Entries) Less(i, j int) bool { return e[i].srv+e[i].user < e[j].srv+e[j].user }

type DB struct {
	ents Entries
}

func (db *DB) lookup(srv, user string) *Entry {
	i := sort.Search(len(db.ents), func(i int) bool {
		return db.ents[i].srv+db.ents[i].user >= srv+user
	})
	if i < len(db.ents) && db.ents[i].srv == srv && db.ents[i].user == user {
		return &db.ents[i]
	} else if i < len(db.ents) {
		// Insert at i
		tail := make([]Entry, len(db.ents)-i)
		copy(tail, db.ents[i:])
		db.ents[i] = Entry{srv: srv, user: user}
		db.ents = append(db.ents[:i+1], tail...)
		return &db.ents[i]
	} else {
		// Insert at end
		db.ents = append(db.ents, Entry{srv: srv, user: user})
		return &db.ents[i]
	}
}

func loadDB(f *os.File, pw []byte) (*DB, error) {
	db := new(DB)
	b := bufio.NewReader(f)

	//
	// Read
	//
	var err error
	var magic = make([]byte, len(Magic))
	var salt = make([]byte, SaltLen)
	var iters int32
	var nonce = make([]byte, NonceLen)
	var ciphtxt []byte

	b.Read(magic)
	if !bytes.Equal(magic, Magic) {
		return nil, errors.New("bad magic number")
	}
	if _, err = b.Read(salt); err != nil {
		return nil, err
	}
	if err = binary.Read(b, binary.LittleEndian, &iters); err != nil {
		return nil, err
	}
	if _, err = b.Read(nonce); err != nil {
		return nil, err
	}
	ciphtxt, err = ioutil.ReadAll(b)
	if err != nil {
		return nil, err
	}

	//
	// Decrypt
	//
	key := pbkdf2.Key(pw, salt, int(iters), KeyLen, sha512.New)
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	plaintxt, err := aesgcm.Open(nil, nonce, ciphtxt, nil)
	if err != nil {
		return nil, err
	}

	//
	// Parse
	//
	r := csv.NewReader(bytes.NewBuffer(plaintxt))
	r.FieldsPerRecord = FieldsPerRecord
	r.Comma = Comma
	records, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	for _, rec := range records {
		e := Entry{
			srv:   rec[0],
			user:  rec[1],
			email: rec[2],
			pass:  rec[3],
			notes: rec[4],
		}
		db.ents = append(db.ents, e)
	}
	return db, nil
}

func (db *DB) save(f *os.File, pw []byte) error {
	//
	// To CSV
	//
	bb := bytes.NewBuffer([]byte{})
	w := csv.NewWriter(bb)
	w.Comma = Comma
	for _, e := range db.ents {
		rec := make([]string, FieldsPerRecord)
		rec = []string{
			e.srv,
			e.user,
			e.email,
			e.pass,
			e.notes,
		}
		if err := w.Write(rec); err != nil {
			return err
		}
	}
	w.Flush()
	plaintxt := bb.Bytes()

	//
	// Encrypt
	//
	var salt = make([]byte, SaltLen)   // Fresh salt
	var nonce = make([]byte, NonceLen) // Fresh nonce
	var ciphtxt []byte

	if _, err := rand.Read(salt); err != nil {
		return err
	}
	key := pbkdf2.Key(pw, salt, NIters, KeyLen, sha512.New)
	blk, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	aesgcm, err := cipher.NewGCM(blk)
	if err != nil {
		return err
	}
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	ciphtxt = aesgcm.Seal(nil, nonce, plaintxt, nil)

	//
	// Write
	//
	f.Seek(0, os.SEEK_SET)
	f.Truncate(0)
	b := bufio.NewWriter(f)
	b.Write(Magic)
	b.Write(salt)
	binary.Write(b, binary.LittleEndian, int32(NIters))
	b.Write(nonce)
	b.Write(ciphtxt)
	if b.Flush() != nil {
		return b.Flush()
	}
	return f.Sync()
}

func create(path string) error {
ask:
	resp := prompt("new master password: ", true)
	again := prompt("again: ", true)
	if !bytes.Equal(resp, again) {
		fmt.Println("passwords differ, try again")
		goto ask
	}
	if len(resp) == 0 {
		fmt.Println("that's not a password, try again")
		goto ask
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	db := new(DB)
	if err = db.save(f, resp); err != nil {
		log.Fatal(err)
	}
	f.Close()
	fmt.Printf("created password store at %s\n", path)
	return nil
}

// Interactively add a user entry, or change an existing one.
func addEntry(path string) {
	f, err := os.OpenFile(path, os.O_RDWR, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	pw := prompt("master password: ", true)
	db, err := loadDB(f, pw)
	if err != nil {
		log.Fatal(err)
	}
	e := promptEntry()
	ep := db.lookup(e.srv, e.user)
	*ep = *e
	if err = db.save(f, pw); err != nil {
		log.Fatal(err)
	}
}

func delEntry(path, server, username string) {
	f, err := os.OpenFile(path, os.O_RDWR, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	pw := prompt("master password: ", true)
	db, err := loadDB(f, pw)
	if err != nil {
		log.Fatal(err)
	}

	var ents []Entry
	for _, e := range db.ents {
		if e.srv == server && e.user == username {
			continue // Delete the entry
		}
		ents = append(ents, e)
	}
	db.ents = ents

	if err = db.save(f, pw); err != nil {
		log.Fatal(err)
	}
}

func setMaster(path string) {
	f, err := os.OpenFile(path, os.O_RDWR, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	pw := prompt("master password: ", true)
	db, err := loadDB(f, pw)
	if err != nil {
		log.Fatal(err)
	}

asknew:
	newpw := prompt("new master password: ", true)
	again := prompt("again: ", true)
	if !bytes.Equal(newpw, again) {
		fmt.Println("passwords differ, try again")
		goto asknew
	}

	if err = db.save(f, newpw); err != nil {
		log.Fatal(err)
	}
}

func listEntries(path string) {
	f, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	pw := prompt("master password: ", true)
	db, err := loadDB(f, pw)
	if err != nil {
		log.Fatal(err)
	}
	for _, e := range db.ents {
		fmt.Println(e)
	}
}

// If !allowempty, prompt the user again if they enter nothing.
func prompt(msg string, allowempty bool) []byte {
	fmt.Fprint(os.Stderr, msg)
	line, err := stdin.ReadString('\n')
	if err == io.EOF {
		os.Exit(0)
	}
	for line[len(line)-1] == '\n' || line[len(line)-1] == '\r' {
		line = line[:len(line)-1]
		if len(line) == 0 {
			break
		}
	}
	if !allowempty && line == "" {
		return prompt(msg, allowempty)
	}
	return []byte(line)
}

func promptEntry() *Entry {
	var e Entry
	e.srv = string(prompt("server: ", false))
	e.user = string(prompt("user name: ", true))
	e.email = string(prompt("email address: ", true))
	e.pass = string(prompt("password: ", true))
	e.notes = string(prompt("notes: ", true))
	return &e
}
