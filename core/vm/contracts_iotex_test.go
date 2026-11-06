// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package vm

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/params"
)

// Tests for the IoTeX specific precompiles (secp256r1 @ 0x8001, scrypt @ 0x8002)
// and their coexistence with EIP-7951 P256VERIFY @ 0x100.

var (
	iotexSecp256r1Addr = common.BytesToAddress([]byte{0x80, 0x01})
	iotexScryptAddr    = common.BytesToAddress([]byte{0x80, 0x02})
	p256VerifyAddr     = common.BytesToAddress([]byte{0x01, 0x00})

	rulesIstanbul = params.Rules{IsHomestead: true, IsEIP150: true, IsEIP155: true, IsEIP158: true, IsByzantium: true, IsConstantinople: true, IsPetersburg: true, IsIstanbul: true}
	rulesBerlin   = withRules(rulesIstanbul, func(r *params.Rules) { r.IsBerlin, r.IsEIP2929 = true, true })
	rulesLondon   = withRules(rulesBerlin, func(r *params.Rules) { r.IsLondon = true })
	rulesShanghai = withRules(rulesLondon, func(r *params.Rules) { r.IsMerge, r.IsShanghai = true, true })
	rulesCancun   = withRules(rulesShanghai, func(r *params.Rules) { r.IsCancun = true })
	rulesPrague   = withRules(rulesCancun, func(r *params.Rules) { r.IsPrague = true })
	rulesOsaka    = withRules(rulesPrague, func(r *params.Rules) { r.IsOsaka = true })
)

func withRules(base params.Rules, f func(*params.Rules)) params.Rules {
	f(&base)
	return base
}

func TestIotexPrecompileSets(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		rules                params.Rules
		wantIotex, wantP256V bool
	}{
		{"istanbul", rulesIstanbul, false, false},
		{"berlin", rulesBerlin, true, false},
		{"london", rulesLondon, true, false},
		{"shanghai", rulesShanghai, true, false},
		{"cancun", rulesCancun, true, false},
		{"prague", rulesPrague, true, false},
		{"osaka", rulesOsaka, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			contracts := ActivePrecompiledContracts(tc.rules)
			addrs := ActivePrecompiles(tc.rules)
			if len(contracts) != len(addrs) {
				t.Fatalf("contracts/addresses mismatch: %d vs %d", len(contracts), len(addrs))
			}
			check := func(addr common.Address, want bool) {
				_, inMap := contracts[addr]
				inList := slices.Contains(addrs, addr)
				if inMap != want || inList != want {
					t.Errorf("%x: in contracts=%v in addresses=%v, want %v", addr, inMap, inList, want)
				}
			}
			// secp256r1 (0x8001) has been active since Berlin, scrypt (0x8002) since Cancun.
			check(iotexSecp256r1Addr, tc.wantIotex)
			check(iotexScryptAddr, tc.wantIotex && tc.rules.IsCancun)
			check(p256VerifyAddr, tc.wantP256V)
		})
	}
	// The implementations behind 0x8001/0x8002 must be exactly the same type in
	// every fork set they appear in.
	for _, set := range []PrecompiledContracts{PrecompiledContractsBerlin, PrecompiledContractsCancun, PrecompiledContractsPrague, PrecompiledContractsOsaka} {
		if reflect.TypeOf(set[iotexSecp256r1Addr]) != reflect.TypeOf(&iotexSecp256r1{}) {
			t.Errorf("unexpected 0x8001 implementation %T", set[iotexSecp256r1Addr])
		}
	}
	for _, set := range []PrecompiledContracts{PrecompiledContractsCancun, PrecompiledContractsPrague, PrecompiledContractsOsaka} {
		if reflect.TypeOf(set[iotexScryptAddr]) != reflect.TypeOf(&scryptHash{}) {
			t.Errorf("unexpected 0x8002 implementation %T", set[iotexScryptAddr])
		}
	}
	if reflect.TypeOf(PrecompiledContractsOsaka[p256VerifyAddr]) != reflect.TypeOf(&p256Verify{}) {
		t.Errorf("unexpected 0x100 implementation %T", PrecompiledContractsOsaka[p256VerifyAddr])
	}
}

type p256Sample struct {
	hash, r, s []byte
	pub        *ecdsa.PublicKey
}

func newP256Sample(t testing.TB) p256Sample {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte("iotex"))
	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		t.Fatal(err)
	}
	return p256Sample{hash: h[:], r: common.LeftPadBytes(r.Bytes(), 32), s: common.LeftPadBytes(s.Bytes(), 32), pub: &key.PublicKey}
}

// iotexInput encodes hash || r || s || SEC1-uncompressed(pub) (0x8001 format).
func (p p256Sample) iotexInput() []byte {
	//nolint:staticcheck // elliptic.Marshal is what the precompile parses
	pub := elliptic.Marshal(elliptic.P256(), p.pub.X, p.pub.Y)
	return slices.Concat(p.hash, p.r, p.s, pub)
}

// eip7951Input encodes hash || r || s || x || y (0x100 format).
func (p p256Sample) eip7951Input() []byte {
	return slices.Concat(p.hash, p.r, p.s, common.LeftPadBytes(p.pub.X.Bytes(), 32), common.LeftPadBytes(p.pub.Y.Bytes(), 32))
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// iotexSecp256r1Corpus returns inputs for 0x8001 together with the expected
// output/error of the IoTeX implementation (unchanged since 2022).
func iotexSecp256r1Corpus(t *testing.T) []struct {
	name   string
	input  []byte
	output []byte
	err    string
} {
	type tc = struct {
		name   string
		input  []byte
		output []byte
		err    string
	}
	var corpus []tc
	ok, err := loadJson("secp256r1")
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range ok {
		corpus = append(corpus, tc{"json/" + v.Name, mustHex(v.Input), mustHex(v.Expected), ""})
	}
	fail, err := loadJsonFail("secp256r1")
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range fail {
		corpus = append(corpus, tc{"json-fail/" + v.Name, mustHex(v.Input), nil, v.ExpectedError})
	}
	smp := newP256Sample(t)
	valid := smp.iotexInput()
	badHash := slices.Clone(valid)
	badHash[0] ^= 0xff
	sGtN := slices.Clone(valid)
	copy(sGtN[64:96], bytes.Repeat([]byte{0xff}, 32))
	zeroR := slices.Clone(valid)
	copy(zeroR[32:64], make([]byte, 32))
	offCurve := slices.Clone(valid)
	offCurve[len(offCurve)-1] ^= 0x01
	//nolint:staticcheck
	compressed := slices.Concat(smp.hash, smp.r, smp.s, elliptic.MarshalCompressed(elliptic.P256(), smp.pub.X, smp.pub.Y))
	corpus = append(corpus,
		tc{"gen/valid", valid, []byte{1}, ""},
		tc{"gen/bad-hash", badHash, []byte{0}, ""},
		tc{"gen/s>=n", sGtN, []byte{0}, ""},
		tc{"gen/r=0", zeroR, []byte{0}, ""},
		tc{"gen/off-curve", offCurve, nil, "invalid curve point"},
		tc{"gen/compressed-pubkey", compressed, nil, "invalid curve point"},
		tc{"gen/trailing-byte", append(slices.Clone(valid), 0x00), nil, "invalid curve point"},
		tc{"gen/eip7951-format", smp.eip7951Input(), nil, "invalid curve point"},
		tc{"gen/empty", nil, nil, "invalid input length"},
		tc{"gen/96-bytes", valid[:96], nil, "invalid input length"},
		tc{"gen/97-bytes", valid[:97], nil, "invalid curve point"},
	)
	return corpus
}

// TestIotexSecp256r1Behavior pins the exact behavior of 0x8001: gas 3000,
// output 0x01 / 0x00, errors (which consume all gas at the EVM level).
func TestIotexSecp256r1Behavior(t *testing.T) {
	p := PrecompiledContractsOsaka[iotexSecp256r1Addr]
	for _, c := range iotexSecp256r1Corpus(t) {
		if g := p.RequiredGas(c.input); g != 3000 {
			t.Errorf("%s: gas %d, want 3000", c.name, g)
		}
		out, err := p.Run(c.input)
		if c.err != "" {
			if err == nil || err.Error() != c.err {
				t.Errorf("%s: err %v, want %q", c.name, err, c.err)
			}
			continue
		}
		if err != nil || !bytes.Equal(out, c.output) {
			t.Errorf("%s: got (%x, %v), want (%x, nil)", c.name, out, err, c.output)
		}
	}
}

type precompileResult struct {
	out       []byte
	remaining uint64
	err       error
}

func runAt(rules params.Rules, addr common.Address, input []byte, gas uint64) (precompileResult, bool) {
	p, ok := ActivePrecompiledContracts(rules)[addr]
	if !ok {
		return precompileResult{}, false
	}
	out, remaining, err := RunPrecompiledContract(p, input, gas, nil)
	return precompileResult{out, remaining, err}, true
}

func scryptCorpus(t *testing.T) map[string][]byte {
	corpus := make(map[string][]byte)
	ok, err := loadJson("scrypthash")
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range ok {
		corpus["json/"+v.Name] = mustHex(v.Input)
	}
	fail, err := loadJsonFail("scrypthash")
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range fail {
		corpus["json-fail/"+v.Name] = mustHex(v.Input)
	}
	corpus["empty"] = nil
	corpus["short"] = []byte{1, 2, 3}
	// N=16, r=1, p=1, keyLen=32, mode in {0,1,2}, using the ABI encoding.
	for mode := uint32(0); mode < 3; mode++ {
		in, err := scryptArguments.Pack([]byte("password"), []byte("salt"), uint64(16), uint32(1), uint32(1), uint32(32), mode)
		if err != nil {
			t.Fatal(err)
		}
		corpus[fmt.Sprintf("gen/mode%d", mode)] = in
	}
	return corpus
}

// TestIotexPrecompilesOsakaEqualsPrague checks that 0x8001 and 0x8002 behave
// identically (output, remaining gas, error) under Prague and Osaka rules.
func TestIotexPrecompilesOsakaEqualsPrague(t *testing.T) {
	type input struct {
		name string
		addr common.Address
		data []byte
	}
	var inputs []input
	for _, c := range iotexSecp256r1Corpus(t) {
		inputs = append(inputs, input{"8001/" + c.name, iotexSecp256r1Addr, c.input})
	}
	for name, data := range scryptCorpus(t) {
		inputs = append(inputs, input{"8002/" + name, iotexScryptAddr, data})
	}
	for _, in := range inputs {
		required := ActivePrecompiledContracts(rulesPrague)[in.addr].RequiredGas(in.data)
		for _, gas := range []uint64{0, required - 1, required, required + 12345} {
			prague, ok1 := runAt(rulesPrague, in.addr, in.data, gas)
			osaka, ok2 := runAt(rulesOsaka, in.addr, in.data, gas)
			if !ok1 || !ok2 {
				t.Fatalf("%s: precompile missing (prague=%v osaka=%v)", in.name, ok1, ok2)
			}
			if !bytes.Equal(prague.out, osaka.out) || prague.remaining != osaka.remaining || fmt.Sprint(prague.err) != fmt.Sprint(osaka.err) {
				t.Errorf("%s gas=%d: prague=(%x,%d,%v) osaka=(%x,%d,%v)", in.name, gas,
					prague.out, prague.remaining, prague.err, osaka.out, osaka.remaining, osaka.err)
			}
		}
	}
}

// TestP256VerifyOnlyInOsaka checks that EIP-7951 P256VERIFY (0x100) exists only
// in Osaka, uses the upstream semantics, and is independent from 0x8001.
func TestP256VerifyOnlyInOsaka(t *testing.T) {
	smp := newP256Sample(t)
	if _, ok := runAt(rulesPrague, p256VerifyAddr, smp.eip7951Input(), 1_000_000); ok {
		t.Fatal("0x100 must not be a precompile in Prague")
	}
	res, ok := runAt(rulesOsaka, p256VerifyAddr, smp.eip7951Input(), 1_000_000)
	if !ok {
		t.Fatal("0x100 must be a precompile in Osaka")
	}
	if res.err != nil || !bytes.Equal(res.out, common.LeftPadBytes([]byte{1}, 32)) || res.remaining != 1_000_000-params.P256VerifyGas {
		t.Fatalf("0x100 valid: got (%x, %d, %v)", res.out, res.remaining, res.err)
	}
	// 0x8001-formatted input is not valid for 0x100: empty output, no error.
	res, _ = runAt(rulesOsaka, p256VerifyAddr, smp.iotexInput(), 1_000_000)
	if res.err != nil || len(res.out) != 0 {
		t.Fatalf("0x100 with 0x8001 input: got (%x, %v)", res.out, res.err)
	}
	// Same key/signature through 0x8001 in Osaka keeps the IoTeX semantics.
	res, _ = runAt(rulesOsaka, iotexSecp256r1Addr, smp.iotexInput(), 1_000_000)
	if res.err != nil || !bytes.Equal(res.out, []byte{1}) || res.remaining != 1_000_000-3000 {
		t.Fatalf("0x8001 valid: got (%x, %d, %v)", res.out, res.remaining, res.err)
	}
	// Names must be unique (used by eth_config).
	names := make(map[string]common.Address)
	for addr, p := range PrecompiledContractsOsaka {
		if prev, dup := names[p.Name()]; dup {
			t.Errorf("duplicate precompile name %q at %x and %x", p.Name(), prev, addr)
		}
		names[p.Name()] = addr
	}
}
