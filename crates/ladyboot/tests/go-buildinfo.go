// Test-only ELF reader. Go 1.26's buildinfo.DataReader mishandles an early
// zero-sized GNU_STACK segment produced by patchelf (Filesz-1 underflows).
// Read the named section using debug/elf, then parse with runtime/debug.
package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime/debug"
)

func inlineString(data []byte) ([]byte, []byte, error) {
	size, n := binary.Uvarint(data)
	if n <= 0 || size > uint64(len(data)-n) {
		return nil, nil, fmt.Errorf("truncated inline string")
	}
	return data[n : n+int(size)], data[n+int(size):], nil
}

func readInfo(path string) (*debug.BuildInfo, error) {
	file, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	section := file.Section(".go.buildinfo")
	if section == nil || section.Size < 32 || section.Size > 1024*1024 || section.Flags&elf.SHF_COMPRESSED != 0 {
		return nil, fmt.Errorf("missing, compressed or oversized Go build info")
	}
	data, err := io.ReadAll(io.LimitReader(section.Open(), 1024*1024+1))
	if err != nil || uint64(len(data)) != section.Size {
		return nil, fmt.Errorf("truncated Go section: %v", err)
	}
	if !bytes.Equal(data[:14], []byte("\xff Go buildinf:")) || data[14] != 8 || data[15] != 2 {
		return nil, fmt.Errorf("unsupported Go build info format")
	}
	version, rest, err := inlineString(data[32:])
	if err != nil {
		return nil, err
	}
	modules, _, err := inlineString(rest)
	if err != nil {
		return nil, err
	}
	start, _ := hex.DecodeString("3077af0c9274080241e1c107e6d618e6")
	end, _ := hex.DecodeString("f932433186182072008242104116d8f2")
	if len(modules) < 32 || !bytes.HasPrefix(modules, start) || !bytes.HasSuffix(modules, end) {
		return nil, fmt.Errorf("invalid module framing")
	}
	info, err := debug.ParseBuildInfo(string(modules[16 : len(modules)-16]))
	if err != nil {
		return nil, err
	}
	info.GoVersion = string(version)
	return info, nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "expected one ELF path")
		os.Exit(2)
	}
	info, err := readInfo(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(info); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
