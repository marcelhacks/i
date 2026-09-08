package accountkey

import (
    "crypto/ecdsa"
    "encoding/hex"
    "testing"

    "github.com/kaiachain/kaia/crypto"
    "github.com/kaiachain/kaia/fork"
    "github.com/kaiachain/kaia/params"
    "github.com/kaiachain/kaia/rlp"
)

const roleTestBlock = uint64(200_000_000)

func initializeForkRules(t *testing.T) {
    t.Helper()
    if err := fork.SetHardForkBlockNumberConfig(params.MainnetChainConfig); err != nil {
        t.Fatalf("initialize fork rules: %v", err)
    }
    t.Cleanup(fork.ClearHardForkBlockNumberConfig)
}

func mustKey(t *testing.T, raw string) *ecdsa.PrivateKey {
    t.Helper()
    k, err := crypto.HexToECDSA(raw)
    if err != nil {
        t.Fatalf("HexToECDSA: %v", err)
    }
    return k
}

func recovered(t *testing.T, key *ecdsa.PrivateKey, digest []byte) *ecdsa.PublicKey {
    t.Helper()
    sig, err := crypto.Sign(digest, key)
    if err != nil {
        t.Fatalf("Sign: %v", err)
    }
    pub, err := crypto.SigToPub(digest, sig)
    if err != nil {
        t.Fatalf("SigToPub: %v", err)
    }
    return pub
}

func TestSeaportCrossRoleCollapse_AccountKeyFailTransaction_LegacyFeePayer(t *testing.T) {
    initializeForkRules(t)

    feeKey := mustKey(t, "00000000000000000000000000000000000000000000000000000000000a11ce")
    updateKey := mustKey(t, "00000000000000000000000000000000000000000000000000000000000c0ffe")
    from := crypto.PubkeyToAddress(feeKey.PublicKey)
    digest := crypto.Keccak256([]byte("same-seaport-order-digest"))

    roleKey := NewAccountKeyRoleBasedWithValues([]AccountKey{
        NewAccountKeyFail(),
        NewAccountKeyPublicWithValue(&updateKey.PublicKey),
        NewAccountKeyLegacy(),
    })
    if err := roleKey.CheckInstallable(roleTestBlock); err != nil {
        t.Fatalf("role key is not installable: %v", err)
    }

    feePub := recovered(t, feeKey, digest)
    updatePub := recovered(t, updateKey, digest)

    if err := ValidateAccountKey(roleTestBlock, from, roleKey, []*ecdsa.PublicKey{feePub}, RoleTransaction); err == nil {
        t.Fatal("fee-payer-only key unexpectedly passed RoleTransaction")
    }
    if err := ValidateAccountKey(roleTestBlock, from, roleKey, []*ecdsa.PublicKey{feePub}, RoleAccountUpdate); err == nil {
        t.Fatal("fee-payer-only key unexpectedly passed RoleAccountUpdate")
    }
    if err := ValidateAccountKey(roleTestBlock, from, roleKey, []*ecdsa.PublicKey{feePub}, RoleFeePayer); err != nil {
        t.Fatalf("fee-payer-only key failed RoleFeePayer: %v", err)
    }
    if err := ValidateAccountKey(roleTestBlock, from, roleKey, []*ecdsa.PublicKey{updatePub}, RoleAccountUpdate); err != nil {
        t.Fatalf("dedicated update key failed RoleAccountUpdate: %v", err)
    }
    if err := ValidateAccountKey(roleTestBlock, from, roleKey, []*ecdsa.PublicKey{updatePub}, RoleTransaction); err == nil {
        t.Fatal("update-only key unexpectedly passed RoleTransaction")
    }

    encoded, err := rlp.EncodeToBytes(NewAccountKeySerializerWithAccountKey(roleKey))
    if err != nil {
        t.Fatalf("RLP encode: %v", err)
    }
    t.Logf("KAIA_FAIL_ROLE_MATRIX from=%s roleKeyRLP=%s transaction=false accountUpdate(feeKey)=false feePayer=true", from.Hex(), hex.EncodeToString(encoded))
}

func TestSeaportCrossRoleCollapse_ThresholdTransaction_LegacyFeePayer(t *testing.T) {
    initializeForkRules(t)

    feeKey := mustKey(t, "00000000000000000000000000000000000000000000000000000000000a11ce")
    txKey1 := mustKey(t, "00000000000000000000000000000000000000000000000000000000000b0b01")
    txKey2 := mustKey(t, "00000000000000000000000000000000000000000000000000000000000b0b02")
    updateKey := mustKey(t, "00000000000000000000000000000000000000000000000000000000000c0ffe")
    from := crypto.PubkeyToAddress(feeKey.PublicKey)
    digest := crypto.Keccak256([]byte("same-seaport-order-digest"))

    threshold := NewAccountKeyWeightedMultiSigWithValues(
        2,
        WeightedPublicKeys{
            NewWeightedPublicKey(1, (*PublicKeySerializable)(&txKey1.PublicKey)),
            NewWeightedPublicKey(1, (*PublicKeySerializable)(&txKey2.PublicKey)),
        },
    )
    roleKey := NewAccountKeyRoleBasedWithValues([]AccountKey{
        threshold,
        NewAccountKeyPublicWithValue(&updateKey.PublicKey),
        NewAccountKeyLegacy(),
    })
    if err := roleKey.CheckInstallable(roleTestBlock); err != nil {
        t.Fatalf("role key is not installable: %v", err)
    }

    feePub := recovered(t, feeKey, digest)
    txPub1 := recovered(t, txKey1, digest)
    txPub2 := recovered(t, txKey2, digest)

    if err := ValidateAccountKey(roleTestBlock, from, roleKey, []*ecdsa.PublicKey{feePub}, RoleTransaction); err == nil {
        t.Fatal("fee-payer-only key unexpectedly passed threshold RoleTransaction")
    }
    if err := ValidateAccountKey(roleTestBlock, from, roleKey, []*ecdsa.PublicKey{feePub}, RoleFeePayer); err != nil {
        t.Fatalf("fee-payer-only key failed RoleFeePayer: %v", err)
    }
    if err := ValidateAccountKey(roleTestBlock, from, roleKey, []*ecdsa.PublicKey{txPub1}, RoleTransaction); err == nil {
        t.Fatal("one weight-1 transaction key unexpectedly met threshold 2")
    }
    if err := ValidateAccountKey(roleTestBlock, from, roleKey, []*ecdsa.PublicKey{txPub2}, RoleTransaction); err == nil {
        t.Fatal("second weight-1 transaction key unexpectedly met threshold 2")
    }
    if err := ValidateAccountKey(roleTestBlock, from, roleKey, []*ecdsa.PublicKey{txPub1, txPub2}, RoleTransaction); err != nil {
        t.Fatalf("both transaction keys failed threshold 2: %v", err)
    }

    encoded, err := rlp.EncodeToBytes(NewAccountKeySerializerWithAccountKey(roleKey))
    if err != nil {
        t.Fatalf("RLP encode: %v", err)
    }
    t.Logf("KAIA_THRESHOLD_ROLE_MATRIX from=%s roleKeyRLP=%s feeKeyTransaction=false feeKeyFeePayer=true txKey1=false txKey2=false txKeysTogether=true", from.Hex(), hex.EncodeToString(encoded))
}
