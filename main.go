package main

import (
	"bytes"
	"flag"
	"fmt"
	"golang.org/x/crypto/sha3"
	"golang.org/x/crypto/ssh/terminal"
	"math/big"
	"os"
)

var verbose bool

func verbosln(a ...interface{}) {
	if verbose {
		fmt.Fprintln(os.Stderr, a...)
	}
}

const (
	base62s = "0123456789" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "abcdefghijklmnopqrstuvwxyz"
)

func reverse(src []byte) []byte {
	n := len(src)
	dst := make([]byte, n)
	for i := n; i > 0; i-- {
		dst[n-i] = src[i-1]
	}
	return dst
}

func base62(b []byte) string {
	buf := new(bytes.Buffer)

	bi := big.NewInt(0)
	b62 := big.NewInt(62)
	bm := big.NewInt(0)
	b0 := big.NewInt(0)

	bi.SetBytes(b)

	for bi.Cmp(b0) != 0 {
		bi.DivMod(bi, b62, bm)
		buf.WriteByte(base62s[bm.Uint64()])
		verbosln(bi, b62, bm)
	}

	return string(reverse(buf.Bytes()))
}

func shake(h sha3.ShakeHash, b []byte, n int) []byte {
	d := make([]byte, n)

	h.Reset()

	if _, err := h.Write(b); err != nil {
		fmt.Fprintln(os.Stderr, "Shake256.Write() error", err)
		os.Exit(1)
	}

	if _, err := h.Read(d); err != nil {
		fmt.Fprintln(os.Stderr, "Shake256.Read() error", err)
		os.Exit(1)
	}

	return d
}

const outn int = 32
const shaken int = 32 * 256

func round(h sha3.ShakeHash, b []byte) []byte {
	b = shake(h, b, shaken)
	for n := shaken; n >= outn; n = n / 2 {
		verbosln("shake :", n)
		b = shake(h, b, n)
	}
	return b
}

func genpass(n int, tag string, secret string) string {
	block := []byte(tag + secret)

	h := sha3.NewShake256()
	for i := 0; i < shaken; i++ {
		verbosln("round :", i)
		block = round(h, block)
	}

	s := base62(block)

	if n > 0 && n < len(s) {
		return s[:n]
	}
	return s
}

func readsecret(s *string) error {
	b, err := terminal.ReadPassword(0)
	if err != nil {
		return err
	}
	*s = string(b)
	return nil
}

func main() {
	usage := func() {
		fmt.Fprintf(os.Stderr, "usage: lxpass [-length n] tag")
		fmt.Fprintln(os.Stderr)
		flag.PrintDefaults()
	}

	var (
		nchar int
		tag   string
	)

	flag.IntVar(&nchar, "nchar", 0, "output n char")
	flag.BoolVar(&verbose, "verbose", false, "verbose output")
	flag.Usage = usage
	flag.Parse()

	if flag.NArg() != 1 {
		usage()
		return
	}

	tag = flag.Arg(0)

	var secret string
	if err := readsecret(&secret); err != nil {
		fmt.Fprintln(os.Stderr, "readsecret() error:", err)
	}

	pass := genpass(nchar, tag, secret)

	fmt.Fprintln(os.Stdout, pass)
}
