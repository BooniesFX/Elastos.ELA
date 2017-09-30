package account

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	. "DNA_POW/common"
	"DNA_POW/common/serialization"
	ct "DNA_POW/core/contract"
	"DNA_POW/core/transaction"
	. "DNA_POW/errors"
)

type WalletData struct {
	PasswordHash string
	IV           string
	MasterKey    string
	Height       uint32
}

type AccountData struct {
	Address             string
	ProgramHash         string
	PrivateKeyEncrypted string
	Type                string
}

type ContractData struct {
	ProgramHash string //TODO: owner in contract ?
	RawData     string
}

type FileStore struct {
	data FileData
	file *os.File
	path string
}

type CoinData string

type FileData struct {
	WalletData
	Account  []AccountData
	Contract []ContractData
	Coins    CoinData
}

func (cs *FileStore) readDB() ([]byte, error) {
	var err error
	cs.file, err = os.OpenFile(cs.path, os.O_RDONLY|os.O_SYNC, 0666)
	if err != nil {
		return nil, err
	}
	defer cs.closeDB()

	if cs.file != nil {
		data, err := ioutil.ReadAll(cs.file)
		if err != nil {
			return nil, err
		}
		return data, nil

	} else {
		return nil, NewDetailErr(errors.New("[readDB] file handle is nil"), ErrNoCode, "")
	}
}

func (cs *FileStore) writeDB(data []byte) error {
	var err error
	cs.file, err = os.OpenFile(cs.path, os.O_CREATE|os.O_WRONLY|os.O_SYNC|os.O_TRUNC, 0666)
	if err != nil {
		return err
	}
	defer cs.closeDB()

	if cs.file != nil {
		cs.file.Write(data)
	}

	return nil
}

func (cs *FileStore) closeDB() {
	if cs.file != nil {
		cs.file.Close()
		cs.file = nil
	}
}

func (cs *FileStore) BuildDatabase(path string) {
	os.Remove(path)
	jsonBlob, err := json.Marshal(cs.data)
	if err != nil {
		fmt.Println("Build DataBase Error")
		os.Exit(1)
	}
	cs.writeDB(jsonBlob)
}

func (cs *FileStore) SaveAccountData(programHash []byte, encryptedPrivateKey []byte) error {
	JSONData, err := cs.readDB()
	if err != nil {
		return errors.New("error: reading db")
	}
	if err := json.Unmarshal(JSONData, &cs.data); err != nil {
		return errors.New("error: unmarshal db")
	}

	var accountType string
	if len(cs.data.Account) == 0 {
		accountType = MAINACCOUNT
	} else {
		accountType = SUBACCOUNT
	}

	a := AccountData{
		Address:             "",
		ProgramHash:         ToHexString(programHash),
		PrivateKeyEncrypted: ToHexString(encryptedPrivateKey),
		Type:                accountType,
	}
	cs.data.Account = append(cs.data.Account, a)

	JSONBlob, err := json.Marshal(cs.data)
	if err != nil {
		return errors.New("error: marshal db")
	}
	cs.writeDB(JSONBlob)

	return nil
}

func (cs *FileStore) DeleteAccountData(programHash string) error {
	JSONData, err := cs.readDB()
	if err != nil {
		return errors.New("error: reading db")
	}
	if err := json.Unmarshal(JSONData, &cs.data); err != nil {
		return errors.New("error: unmarshal db")
	}

	for i, v := range cs.data.Account {
		if programHash == v.ProgramHash {
			if v.Type == MAINACCOUNT {
				return errors.New("Can't remove main account")
			}
			cs.data.Account = append(cs.data.Account[:i], cs.data.Account[i+1:]...)
		}
	}

	JSONBlob, err := json.Marshal(cs.data)
	if err != nil {
		return errors.New("error: marshal db")
	}
	cs.writeDB(JSONBlob)

	return nil
}

func (cs *FileStore) LoadAccountData() ([]AccountData, error) {
	JSONData, err := cs.readDB()
	if err != nil {
		return nil, errors.New("error: reading db")
	}
	if err := json.Unmarshal(JSONData, &cs.data); err != nil {
		return nil, errors.New("error: unmarshal db")
	}
	return cs.data.Account, nil
}

func (cs *FileStore) SaveContractData(ct *ct.Contract) error {
	JSONData, err := cs.readDB()
	if err != nil {
		return errors.New("error: reading db")
	}
	if err := json.Unmarshal(JSONData, &cs.data); err != nil {
		return errors.New("error: unmarshal db")
	}
	c := ContractData{
		ProgramHash: ToHexString(ct.ProgramHash.ToArray()),
		RawData:     ToHexString(ct.ToArray()),
	}
	cs.data.Contract = append(cs.data.Contract, c)

	JSONBlob, err := json.Marshal(cs.data)
	if err != nil {
		return errors.New("error: marshal db")
	}
	cs.writeDB(JSONBlob)

	return nil
}

func (cs *FileStore) DeleteContractData(programHash string) error {
	JSONData, err := cs.readDB()
	if err != nil {
		return errors.New("error: reading db")
	}
	if err := json.Unmarshal(JSONData, &cs.data); err != nil {
		return errors.New("error: unmarshal db")
	}

	for i, v := range cs.data.Contract {
		if programHash == v.ProgramHash {
			cs.data.Contract = append(cs.data.Contract[:i], cs.data.Contract[i+1:]...)
		}
	}

	JSONBlob, err := json.Marshal(cs.data)
	if err != nil {
		return errors.New("error: marshal db")
	}
	cs.writeDB(JSONBlob)

	return nil
}

func (cs *FileStore) LoadContractData() ([]ContractData, error) {
	JSONData, err := cs.readDB()
	if err != nil {
		return nil, errors.New("error: reading db")
	}
	if err := json.Unmarshal(JSONData, &cs.data); err != nil {
		return nil, errors.New("error: unmarshal db")
	}

	return cs.data.Contract, nil
}

func (cs *FileStore) SaveCoinsData(coins map[*transaction.UTXOTxInput]*Coin) error {
	JSONData, err := cs.readDB()
	if err != nil {
		return errors.New("error: reading db")
	}
	if err := json.Unmarshal(JSONData, &cs.data); err != nil {
		return errors.New("error: unmarshal db")
	}

	length := uint32(len(coins))
	if length == 0 {
		cs.data.Coins = ""
	} else {
		w := new(bytes.Buffer)
		serialization.WriteUint32(w, uint32(len(coins)))
		for k, v := range coins {
			k.Serialize(w)
			v.Serialize(w)
		}
		cs.data.Coins = CoinData(ToHexString(w.Bytes()))
	}

	JSONBlob, err := json.Marshal(cs.data)
	if err != nil {
		return errors.New("error: marshal db")
	}
	cs.writeDB(JSONBlob)

	return nil
}

func (cs *FileStore) DeleteCoinsData(programHash Uint160) error {
	JSONData, err := cs.readDB()
	if err != nil {
		return errors.New("error: reading db")
	}
	if err := json.Unmarshal(JSONData, &cs.data); err != nil {
		return errors.New("error: unmarshal db")
	}
	if cs.data.Coins == "" {
		return nil
	}

	coins := make(map[*transaction.UTXOTxInput]*Coin)
	rawCoins, _ := HexToBytes(string(cs.data.Coins))
	r := bytes.NewReader(rawCoins)
	num, _ := serialization.ReadUint32(r)
	for i := 0; i < int(num); i++ {
		input := new(transaction.UTXOTxInput)
		if err := input.Deserialize(r); err != nil {
			return err
		}
		coin := new(Coin)
		if err := coin.Deserialize(r); err != nil {
			return err
		}
		if coin.Output.ProgramHash != programHash {
			coins[input] = coin
		}
	}
	if err := cs.SaveCoinsData(coins); err != nil {
		return err
	}

	return nil
}

func (cs *FileStore) LoadCoinsData() (map[*transaction.UTXOTxInput]*Coin, error) {
	JSONData, err := cs.readDB()
	if err != nil {
		return nil, errors.New("error: reading db")
	}
	if err := json.Unmarshal(JSONData, &cs.data); err != nil {
		return nil, errors.New("error: unmarshal db")
	}
	coins := make(map[*transaction.UTXOTxInput]*Coin)
	rawCoins, _ := HexToBytes(string(cs.data.Coins))
	r := bytes.NewReader(rawCoins)
	num, _ := serialization.ReadUint32(r)
	for i := 0; i < int(num); i++ {
		input := new(transaction.UTXOTxInput)
		if err := input.Deserialize(r); err != nil {
			return nil, err
		}
		coin := new(Coin)
		if err := coin.Deserialize(r); err != nil {
			return nil, err
		}
		coins[input] = coin
	}

	return coins, nil
}

func (cs *FileStore) SaveStoredData(name string, value []byte) error {
	JSONData, err := cs.readDB()
	if err != nil {
		return errors.New("error: reading db")
	}
	if err := json.Unmarshal(JSONData, &cs.data); err != nil {
		return errors.New("error: unmarshal db")
	}

	hexValue := ToHexString(value)
	switch name {
	case "IV":
		cs.data.IV = hexValue
	case "MasterKey":
		cs.data.MasterKey = hexValue
	case "PasswordHash":
		cs.data.PasswordHash = hexValue
	case "Height":
		var height uint32
		bytesBuffer := bytes.NewBuffer(value)
		binary.Read(bytesBuffer, binary.LittleEndian, &height)
		cs.data.Height = height
	}
	JSONBlob, err := json.Marshal(cs.data)
	if err != nil {
		return errors.New("error: marshal db")
	}
	cs.writeDB(JSONBlob)

	return nil
}

func (cs *FileStore) LoadStoredData(name string) ([]byte, error) {
	JSONData, err := cs.readDB()
	if err != nil {
		return nil, errors.New("error: reading db")
	}
	if err := json.Unmarshal(JSONData, &cs.data); err != nil {
		return nil, errors.New("error: unmarshal db")
	}
	switch name {
	case "IV":
		return HexToBytes(cs.data.IV)
	case "MasterKey":
		return HexToBytes(cs.data.MasterKey)
	case "PasswordHash":
		return HexToBytes(cs.data.PasswordHash)
	case "Height":
		bytesBuffer := bytes.NewBuffer([]byte{})
		binary.Write(bytesBuffer, binary.LittleEndian, cs.data.Height)
		return bytesBuffer.Bytes(), nil
	}

	return nil, errors.New("Can't find the key: " + name)
}
