package contract

import (
	. "Elastos.ELA/common"
	pg "Elastos.ELA/core/contract/program"
	"Elastos.ELA/crypto"
	"Elastos.ELA/vm/opcode"
	"errors"
	"fmt"
	"math/big"
	"sort"
)

type CrossContractType byte

const (
	Deposit CrossContractType = iota
	Withdraw
	WithdrawUnlock
)

//create a Single Singature contract for owner
func CreateSignatureContract(ownerPubKey *crypto.PubKey) (*Contract, error) {
	temp, err := ownerPubKey.EncodePoint(true)
	if err != nil {
		return nil, errors.New("[Contract],CreateSignatureContract failed.")
	}
	signatureRedeemScript, err := CreateSignatureRedeemScript(ownerPubKey)
	if err != nil {
		return nil, errors.New("[Contract],CreateSignatureContract failed.")
	}
	hash, err := ToCodeHash(temp, 1)
	if err != nil {
		return nil, errors.New("[Contract],CreateSignatureContract failed.")
	}
	signatureRedeemScriptHashToCodeHash, err := ToCodeHash(signatureRedeemScript, 1)
	if err != nil {
		return nil, errors.New("[Contract],CreateSignatureContract failed.")
	}
	return &Contract{
		Code:            signatureRedeemScript,
		Parameters:      []ContractParameterType{Signature},
		ProgramHash:     signatureRedeemScriptHashToCodeHash,
		OwnerPubkeyHash: hash,
	}, nil
}

func CreateSignatureRedeemScript(pubkey *crypto.PubKey) ([]byte, error) {
	temp, err := pubkey.EncodePoint(true)
	if err != nil {
		return nil, errors.New("[Contract],CreateSignatureRedeemScript failed.")
	}
	sb := pg.NewProgramBuilder()
	sb.PushData(temp)
	sb.AddOp(opcode.CHECKSIG)
	return sb.ToArray(), nil
}

//create a Multi Singature contract for owner  。
func CreateMultiSigContract(publicKeyHash Uint168, m int, publicKeys []*crypto.PubKey) (*Contract, error) {

	params := make([]ContractParameterType, m)
	for i := range params {
		params[i] = Signature
	}
	MultiSigRedeemScript, err := CreateMultiSigRedeemScript(m, publicKeys)
	if err != nil {
		return nil, errors.New("[Contract],CreateSignatureRedeemScript failed.")
	}
	signatureRedeemScriptHashToCodeHash, err := ToCodeHash(MultiSigRedeemScript, 2)
	if err != nil {
		return nil, errors.New("[Contract],CreateSignatureContract failed.")
	}
	return &Contract{
		Code:            MultiSigRedeemScript,
		Parameters:      params,
		ProgramHash:     signatureRedeemScriptHashToCodeHash,
		OwnerPubkeyHash: publicKeyHash,
	}, nil
}

func CreateMultiSigRedeemScript(m int, pubkeys []*crypto.PubKey) ([]byte, error) {
	if !(m >= 1 && m <= len(pubkeys) && len(pubkeys) <= 24) {
		return nil, nil //TODO: add panic
	}

	sb := pg.NewProgramBuilder()
	sb.PushNumber(big.NewInt(int64(m)))

	//sort pubkey
	sort.Sort(crypto.PubKeySlice(pubkeys))

	for _, pubkey := range pubkeys {
		temp, err := pubkey.EncodePoint(true)
		if err != nil {
			return nil, errors.New("[Contract],CreateSignatureContract failed.")
		}
		sb.PushData(temp)
	}

	sb.PushNumber(big.NewInt(int64(len(pubkeys))))
	sb.AddOp(opcode.CHECKMULTISIG)
	return sb.ToArray(), nil
}

//create a if/else script contract for owner  。
func CreateScriptContract(publicKeyHash Uint168, secrethash []byte, ifKey *crypto.PubKey, elseKey *crypto.PubKey, crosstype CrossContractType) (*Contract, error) {
	params := make([]ContractParameterType, 3)
	params[0] = Signature
	params[1] = ByteArray
	params[2] = Boolean
	var script []byte
	var err error
	switch crosstype {
	case Deposit:
		script, err = CreateDepositScriptRedeemScript(secrethash, ifKey, elseKey, 1000)
		if err != nil {
			return nil, err
		}
	case Withdraw:
		script, err = CreateWithdrawScriptRedeemScript(secrethash, ifKey, elseKey, 100)
		if err != nil {
			return nil, err
		}
	case WithdrawUnlock:
		script, err = CreateWithdrawUnlockScriptRedeemScript(secrethash, ifKey, elseKey, 1000)
		if err != nil {
			return nil, err
		}
	}
	fmt.Printf("script: %s\n", BytesToHexString(script))
	scriptHashToCodeHash, err := ToCodeHash(script, 3)
	if err != nil {
		return nil, errors.New("[Contract],CreateSignatureContract failed.")
	}
	return &Contract{
		Code:            script,
		Parameters:      params,
		ProgramHash:     scriptHashToCodeHash,
		OwnerPubkeyHash: publicKeyHash,
	}, nil
}

func CreateDepositScriptRedeemScript(secrethash []byte, ifkey *crypto.PubKey, elsekey *crypto.PubKey, height uint32) ([]byte, error) {
	sb := pg.NewProgramBuilder()

	sbelse := pg.NewProgramBuilder()
	sbelse.PushNumber(big.NewInt(int64(height)))
	sbelse.AddOp(opcode.CHECKAFTER)
	temp, err := elsekey.EncodePoint(true)
	if err != nil {
		return nil, errors.New("[Contract],CreateDepositScriptRedeemScript failed.")
	}
	sbelse.PushData(temp)
	sbelse.AddOp(opcode.CHECKSIG)
	byelse := sbelse.ToArray()

	sb.AddOp(opcode.JMPIF)
	sb.AddCodes(BytesReverse(Int16ToBytes(len(byelse) + 6)))
	sb.AddCodes(byelse)
	sb.AddOp(opcode.SHA256)
	sb.PushData(secrethash)
	sb.AddOp(opcode.EQUAL)
	sb.AddOp(opcode.VERIFY)
	temp, err = ifkey.EncodePoint(true)
	if err != nil {
		return nil, errors.New("[Contract],CreateDepositScriptRedeemScript failed.")
	}
	sb.PushData(temp)

	sb.AddOp(opcode.CHECKSIG)
	return sb.ToArray(), nil
}

func CreateWithdrawScriptRedeemScript(secrethash []byte, ifkey *crypto.PubKey, elsekey *crypto.PubKey, height uint32) ([]byte, error) {
	sb := pg.NewProgramBuilder()
	sbelse := pg.NewProgramBuilder()
	sbelse.PushNumber(big.NewInt(int64(height)))
	sbelse.AddOp(opcode.CHECKAFTER)
	temp, err := elsekey.EncodePoint(true)
	if err != nil {
		return nil, errors.New("[Contract],CreateDepositScriptRedeemScript failed.")
	}
	sbelse.PushData(temp)
	sbelse.AddOp(opcode.CHECKSIG)
	byelse := sbelse.ToArray()

	sb.AddOp(opcode.JMPIF)
	sb.AddCodes(BytesReverse(Int16ToBytes(len(byelse) + 6)))
	sb.AddCodes(byelse)
	sb.PushNumber(big.NewInt(int64(height)))
	sb.AddOp(opcode.CHECKBEFORE)
	sb.AddOp(opcode.SHA256)
	sb.PushData(secrethash)
	sb.AddOp(opcode.EQUAL)
	sb.AddOp(opcode.VERIFY)
	temp, err = ifkey.EncodePoint(true)
	if err != nil {
		return nil, errors.New("[Contract],CreateWithdrawScriptRedeemScript failed.")
	}
	sb.PushData(temp)

	sb.AddOp(opcode.CHECKSIG)
	return sb.ToArray(), nil
}

//destroy token or refund token
func CreateWithdrawUnlockScriptRedeemScript(secrethash []byte, ifkey *crypto.PubKey, elsekey *crypto.PubKey, height uint32) ([]byte, error) {
	sb := pg.NewProgramBuilder()
	sbelse := pg.NewProgramBuilder()
	sbelse.PushNumber(big.NewInt(int64(height)))
	sbelse.AddOp(opcode.CHECKAFTER)
	temp, err := elsekey.EncodePoint(true)
	if err != nil {
		return nil, errors.New("[Contract],CreateDepositScriptRedeemScript failed.")
	}
	sbelse.PushData(temp)
	sbelse.AddOp(opcode.CHECKSIG)
	byelse := sbelse.ToArray()

	sb.AddOp(opcode.JMPIF)
	sb.AddCodes(BytesReverse(Int16ToBytes(len(byelse) + 6)))
	sb.AddCodes(byelse)

	sb.AddOp(opcode.SHA256)
	sb.PushData(secrethash)
	sb.AddOp(opcode.EQUAL)
	sb.AddOp(opcode.VERIFY)
	sb.AddOp(opcode.INVALIDVOUTVERIFY)
	temp, err = ifkey.EncodePoint(true)
	if err != nil {
		return nil, errors.New("[Contract],CreateWithdrawUnlockScriptRedeemScript failed.")
	}
	sb.PushData(temp)

	sb.AddOp(opcode.CHECKSIG)
	return sb.ToArray(), nil
}

//create a unlock script contract for owner  。
func CreateUnlockScriptContract(publicKeyHash Uint168, secrethash []byte, publicKey *crypto.PubKey, height uint32) (*Contract, error) {
	params := make([]ContractParameterType, 2)
	params[0] = Signature
	params[1] = ByteArray

	script, err := CreateUnlockScriptRedeemScript(secrethash, publicKey, height)
	if err != nil {
		return nil, err
	}
	fmt.Printf("script: %s\n", BytesToHexString(script))
	scriptHashToCodeHash, err := ToCodeHash(script, 3)
	if err != nil {
		return nil, errors.New("[Contract],CreateSignatureContract failed.")
	}
	return &Contract{
		Code:            script,
		Parameters:      params,
		ProgramHash:     scriptHashToCodeHash,
		OwnerPubkeyHash: publicKeyHash,
	}, nil
}

func CreateUnlockScriptRedeemScript(secrethash []byte, pubkey *crypto.PubKey, height uint32) ([]byte, error) {
	sb := pg.NewProgramBuilder()
	sb.PushNumber(big.NewInt(int64(height)))
	sb.AddOp(opcode.CHECKBEFORE)
	sb.AddOp(opcode.SHA256)
	sb.PushData(secrethash)
	sb.AddOp(opcode.EQUAL)
	sb.AddOp(opcode.VERIFY)
	temp, err := pubkey.EncodePoint(true)
	if err != nil {
		return nil, errors.New("[Contract],CreateUnlockScriptRedeemScript failed.")
	}
	sb.PushData(temp)

	sb.AddOp(opcode.CHECKSIG)
	return sb.ToArray(), nil
}
