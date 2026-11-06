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

package runtime

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"slices"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
)

// staticCallProxy returns code that STATICCALLs target with all available gas,
// forwarding the calldata, and returns success (32 bytes) || returndata.
func staticCallProxy(target common.Address) []byte {
	t := target.Bytes()[18:]
	return []byte{
		0x36, 0x5f, 0x5f, 0x37, // calldatacopy(0, 0, calldatasize)
		0x5f, 0x5f, 0x36, 0x5f, 0x61, t[0], t[1], 0x5a, 0xfa, // staticcall(gas, target, 0, cds, 0, 0)
		0x60, 0x00, 0x52, // mstore(0, success)
		0x3d, 0x5f, 0x60, 0x20, 0x3e, // returndatacopy(0x20, 0, rds)
		0x3d, 0x60, 0x20, 0x01, 0x5f, 0xf3, // return(0, rds+0x20)
	}
}

func iotexForkConfig(osaka bool) *params.ChainConfig {
	cfg := *params.MergedTestChainConfig
	if !osaka {
		cfg.OsakaTime = nil
		cfg.BlobScheduleConfig = &params.BlobScheduleConfig{
			Cancun: params.DefaultCancunBlobConfig,
			Prague: params.DefaultPragueBlobConfig,
		}
	}
	return &cfg
}

type callResult struct {
	ret      []byte
	leftover uint64
	err      string
}

func callAt(t *testing.T, osaka bool, to common.Address, code []byte, input []byte) callResult {
	t.Helper()
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	if code != nil {
		statedb.SetCode(to, code, tracing.CodeChangeUnspecified)
	}
	cfg := &Config{
		ChainConfig: iotexForkConfig(osaka),
		State:       statedb,
		GasLimit:    1_000_000,
		BlockNumber: common.Big1,
		Time:        1,
	}
	ret, leftover, err := Call(to, input, cfg)
	rules := cfg.ChainConfig.Rules(cfg.BlockNumber, true, cfg.Time)
	if rules.IsOsaka != osaka || !rules.IsPrague {
		t.Fatalf("unexpected rules: prague=%v osaka=%v", rules.IsPrague, rules.IsOsaka)
	}
	return callResult{ret, leftover, fmt.Sprint(err)}
}

func p256Inputs(t *testing.T) (iotexFmt, eip7951Fmt []byte) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte("iotex"))
	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		t.Fatal(err)
	}
	rb, sb := common.LeftPadBytes(r.Bytes(), 32), common.LeftPadBytes(s.Bytes(), 32)
	//nolint:staticcheck
	iotexFmt = slices.Concat(h[:], rb, sb, elliptic.Marshal(elliptic.P256(), key.X, key.Y))
	eip7951Fmt = slices.Concat(h[:], rb, sb, common.LeftPadBytes(key.X.Bytes(), 32), common.LeftPadBytes(key.Y.Bytes(), 32))
	return
}

// TestIotexPrecompilesEVMOsakaEqualsPrague runs 0x8001/0x8002 through the EVM
// (direct call and STATICCALL from a contract) under Prague and Osaka rules and
// requires identical results, and checks 0x100 is only a precompile in Osaka.
func TestIotexPrecompilesEVMOsakaEqualsPrague(t *testing.T) {
	var (
		r1    = common.BytesToAddress([]byte{0x80, 0x01})
		sc    = common.BytesToAddress([]byte{0x80, 0x02})
		p256v = common.BytesToAddress([]byte{0x01, 0x00})
		proxy = common.HexToAddress("0x1000000000000000000000000000000000000001")
	)
	valid, valid7951 := p256Inputs(t)
	badSig := slices.Clone(valid)
	badSig[0] ^= 0xff
	scryptIn := common.FromHex("00000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000160000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000050000000020000000000000000000000000000000000000000000000000000000000000000ab04ea90eb7d931cbbaa94a11cb3907809c13262dd37acc526e4b4a628e43b111c7fffff00000089929df805000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000050000000020000000000000000000000000000000000000000000000000000000000000000ab04ea90eb7d931cbbaa94a11cb3907809c13262dd37acc526e4b4a628e43b111c7fffff00000089929df80500000000000000000000000000000000")

	cases := []struct {
		name  string
		to    common.Address
		input []byte
	}{
		{"8001/valid", r1, valid},
		{"8001/bad-sig", r1, badSig},
		{"8001/short", r1, valid[:96]},
		{"8001/bad-point", r1, valid7951},
		{"8002/valid", sc, scryptIn},
		{"8002/garbage", sc, []byte{1, 2, 3}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Direct call (tx-level).
			prague := callAt(t, false, c.to, nil, c.input)
			osaka := callAt(t, true, c.to, nil, c.input)
			if !bytes.Equal(prague.ret, osaka.ret) || prague.leftover != osaka.leftover || prague.err != osaka.err {
				t.Errorf("direct: prague=%+v osaka=%+v", prague, osaka)
			}
			// Via STATICCALL from a contract.
			prague = callAt(t, false, proxy, staticCallProxy(c.to), c.input)
			osaka = callAt(t, true, proxy, staticCallProxy(c.to), c.input)
			if !bytes.Equal(prague.ret, osaka.ret) || prague.leftover != osaka.leftover || prague.err != osaka.err {
				t.Errorf("staticcall: prague=%+v osaka=%+v", prague, osaka)
			}
		})
	}

	// Pin the 0x8001 semantics at EVM level.
	res := callAt(t, true, r1, nil, valid)
	if !bytes.Equal(res.ret, []byte{1}) || res.leftover != 1_000_000-3000 || res.err != "<nil>" {
		t.Errorf("8001 valid: %+v", res)
	}
	res = callAt(t, true, r1, nil, badSig)
	if !bytes.Equal(res.ret, []byte{0}) || res.leftover != 1_000_000-3000 || res.err != "<nil>" {
		t.Errorf("8001 bad sig: %+v", res)
	}
	res = callAt(t, true, r1, nil, valid[:96])
	if len(res.ret) != 0 || res.leftover != 0 || res.err != "invalid input length" {
		t.Errorf("8001 short input must fail and consume all gas: %+v", res)
	}

	// 0x100: plain (empty) account in Prague, P256VERIFY in Osaka.
	res = callAt(t, false, p256v, nil, valid7951)
	if len(res.ret) != 0 || res.leftover != 1_000_000 || res.err != "<nil>" {
		t.Errorf("0x100 in prague: %+v", res)
	}
	res = callAt(t, true, p256v, nil, valid7951)
	if !bytes.Equal(res.ret, common.LeftPadBytes([]byte{1}, 32)) || res.leftover != 1_000_000-params.P256VerifyGas || res.err != "<nil>" {
		t.Errorf("0x100 in osaka: %+v", res)
	}
	res = callAt(t, true, proxy, staticCallProxy(p256v), valid7951)
	if !bytes.Equal(res.ret, slices.Concat(common.LeftPadBytes([]byte{1}, 32), common.LeftPadBytes([]byte{1}, 32))) {
		t.Errorf("0x100 via staticcall in osaka: %x", res.ret)
	}
}
