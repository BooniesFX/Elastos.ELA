package contract

import (
	. "Elastos.ELA/common"
	pg "Elastos.ELA/core/contract/program"
	"Elastos.ELA/crypto"
	"Elastos.ELA/vm/opcode"
	"errors"
	"math/big"
	"sort"
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

//create a script contract for owner  。
func CreateScriptContract(publicKeyHash Uint168, secret []byte, publicKey *crypto.PubKey) (*Contract, error) {
	params := make([]ContractParameterType, 2)
	params[0] = Signature
	params[1] = ByteArray

	script, err := CreateScriptRedeemScript(secret, publicKey)
	if err != nil {
		return nil, errors.New("[Contract],CreateScriptRedeemScript failed.")
	}
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

func CreateScriptRedeemScript(secret []byte, pubkey *crypto.PubKey) ([]byte, error) {
	sb := pg.NewProgramBuilder()
	//b.PushNumber(big.NewInt(int64(m)))

	temp, err := pubkey.EncodePoint(true)
	if err != nil {
		return nil, errors.New("[Contract],CreateSignatureContract failed.")
	}
	sb.PushData(temp)

	sb.AddOp(opcode.CHECKMULTISIG)
	return sb.ToArray(), nil
}
