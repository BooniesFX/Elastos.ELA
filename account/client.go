package account

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	. "DNA_POW/common"
	"DNA_POW/common/config"
	"DNA_POW/common/log"
	"DNA_POW/common/password"
	"DNA_POW/core/contract"
	ct "DNA_POW/core/contract"
	"DNA_POW/core/ledger"
	sig "DNA_POW/core/signature"
	"DNA_POW/core/transaction"
	"DNA_POW/crypto"
	. "DNA_POW/errors"
	"DNA_POW/events/signalset"
	"DNA_POW/net/protocol"
)

const (
	DefaultBookKeeperCount = 4
	WalletFileName         = "wallet.dat"
	MAINACCOUNT            = "main-account"
	SUBACCOUNT             = "sub-account"
	MaxSignalQueueLen      = 5
)

type Client interface {
	Sign(context *ct.ContractContext) bool

	ContainsAccount(pubKey *crypto.PubKey) bool
	CreateAccount() (*Account, error)
	DeleteAccount(programHash Uint160) error
	GetAccount(pubKey *crypto.PubKey) (*Account, error)
	GetDefaultAccount() (*Account, error)
	GetAccountByProgramHash(programHash Uint160) *Account
	GetAccounts() []*Account

	CreateContract(account *Account) error
	DeleteContract(programHash Uint160) error

	GetCoins() map[*transaction.UTXOTxInput]*Coin
	DeleteCoinsData(programHash Uint160) error
}

type ClientImpl struct {
	mu sync.Mutex

	path      string
	iv        []byte
	masterKey []byte

	mainAccount Uint160
	accounts    map[Uint160]*Account
	contracts   map[Uint160]*ct.Contract
	coins       map[*transaction.UTXOTxInput]*Coin

	watchOnly     []Uint160
	currentHeight int32

	FileStore
	isRunning bool
}

func Create(path string, passwordKey []byte) (*ClientImpl, error) {
	client := NewClient(path, passwordKey, true)
	if client == nil {
		return nil, errors.New("client nil")
	}
	account, err := client.CreateAccount()
	if err != nil {
		return nil, err
	}
	if err := client.CreateContract(account); err != nil {
		return nil, err
	}
	client.mainAccount = account.ProgramHash

	return client, nil
}

func Open(path string, passwordKey []byte) (*ClientImpl, error) {
	client := NewClient(path, passwordKey, false)
	if client == nil {
		return nil, errors.New("client nil")
	}
	if err := client.LoadAccounts(); err != nil {
		return nil, errors.New("Load accounts failure")
	}
	if err := client.LoadContracts(); err != nil {
		return nil, errors.New("Load contracts failure")
	}
	if err := client.LoadCoins(); err != nil {
		return nil, errors.New("Load coins failure")
	}

	return client, nil
}

func Recover(path string, password []byte, privateKeyHex string) (*ClientImpl, error) {
	client := NewClient(path, password, true)
	if client == nil {
		return nil, errors.New("client nil")
	}

	privateKeyBytes, err := HexStringToBytes(privateKeyHex)
	if err != nil {
		return nil, err
	}

	// recover Account
	account, err := client.CreateAccountByPrivateKey(privateKeyBytes)
	if err != nil {
		return nil, err
	}

	// recover contract
	if err := client.CreateContract(account); err != nil {
		return nil, err
	}

	return client, nil
}

func (client *ClientImpl) ProcessBlocks() {
	time.Sleep(time.Second)
	for client.isRunning {
		for true {
			blockHeight := ledger.DefaultLedger.GetLocalBlockChainHeight()
			if client.currentHeight >= int32(blockHeight) {
				break
			}
			block, err := ledger.DefaultLedger.GetBlockWithHeight(uint32(client.currentHeight) + 1)
			if err != nil {
				fmt.Fprintf(os.Stderr, "fatal error: syncing failed, block missing, height %d\n", client.currentHeight)
				break
			}
			client.ProcessOneBlock(block)
		}
		time.Sleep(1 * time.Second)
	}
}

func (client *ClientImpl) ProcessOneBlock(block *ledger.Block) {
	client.mu.Lock()
	defer client.mu.Unlock()

	var needUpdate bool
	// received coins
	for _, tx := range block.Transactions {
		for index, output := range tx.Outputs {
			if _, ok := client.contracts[output.ProgramHash]; ok {
				input := &transaction.UTXOTxInput{ReferTxID: tx.Hash(), ReferTxOutputIndex: uint16(index)}
				if _, ok := client.coins[input]; !ok {
					// If it's not Coinbase transaction, the new created utxos could be spent in next block height.
					// Otherwise, could be spent when block height reaches to current height + SpendCoinbaseSpan
					h := uint32(0)
					if tx.IsCoinBaseTx(){
						h = block.Blockdata.Height + config.Parameters.PowConfiguration.SpendCoinbaseSpan
					}
					newCoin := &Coin{Output: output,AddressType: SingleSign, Height: h}
					client.coins[input] = newCoin
					needUpdate = true
				}
			}
		}
	}

	// spent coins
	for _, tx := range block.Transactions {
		for _, input := range tx.UTXOInputs {
			for k := range client.coins {
				if k.ReferTxOutputIndex == input.ReferTxOutputIndex && k.ReferTxID == input.ReferTxID {
					delete(client.coins, k)
					needUpdate = true
				}
			}
		}
	}

	// update wallet store
	if needUpdate {
		if err := client.SaveCoins(); err != nil {
			fmt.Fprintf(os.Stderr, "saving coins error: %v\n", err)
		}
	}

	// update height
	client.currentHeight++
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.LittleEndian, &client.currentHeight)
	client.SaveStoredData("Height", bytesBuffer.Bytes())
}

func (client *ClientImpl) ProcessSignals() {
	clientSignalHandler := func(signal os.Signal, v interface{}) {
		switch signal {
		case syscall.SIGINT:
			log.Trace("Caught interrupt signal, program exits.")
		case syscall.SIGTERM:
			log.Trace("Caught termination signal, program exits.")
		}
		// hold the mutex lock to prevent any wallet db changes
		client.FileStore.Lock()
		os.Exit(0)
	}
	signalSet := signalset.New()
	signalSet.Register(syscall.SIGINT, clientSignalHandler)
	signalSet.Register(syscall.SIGTERM, clientSignalHandler)
	sigChan := make(chan os.Signal, MaxSignalQueueLen)
	signal.Notify(sigChan)
	for {
		select {
		case sig := <-sigChan:
			signalSet.Handle(sig, nil)
		default:
			time.Sleep(time.Second)
		}
	}
}

func NewClient(path string, password []byte, create bool) *ClientImpl {
	client := &ClientImpl{
		path:          path,
		accounts:      map[Uint160]*Account{},
		contracts:     map[Uint160]*ct.Contract{},
		coins:         map[*transaction.UTXOTxInput]*Coin{},
		currentHeight: -1,
		FileStore:     FileStore{path: path},
		isRunning:     true,
	}

	go client.ProcessSignals()

	passwordKey := crypto.ToAesKey(password)
	if create {
		//create new client
		client.iv = make([]byte, 16)
		client.masterKey = make([]byte, 32)
		client.watchOnly = []Uint160{}

		//generate random number for iv/masterkey
		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		for i := 0; i < 16; i++ {
			client.iv[i] = byte(r.Intn(256))
		}
		for i := 0; i < 32; i++ {
			client.masterKey[i] = byte(r.Intn(256))
		}

		//new client store (build DB)
		client.BuildDatabase(path)

		if err := client.SaveStoredData("Version", []byte(WalletStoreVersion)); err != nil {
			log.Error(err)
			return nil
		}

		pwdhash := sha256.Sum256(passwordKey)
		if err := client.SaveStoredData("PasswordHash", pwdhash[:]); err != nil {
			log.Error(err)
			return nil
		}
		if err := client.SaveStoredData("IV", client.iv[:]); err != nil {
			log.Error(err)
			return nil
		}

		aesmk, err := crypto.AesEncrypt(client.masterKey[:], passwordKey, client.iv)
		if err != nil {
			log.Error(err)
			return nil
		}
		if err := client.SaveStoredData("MasterKey", aesmk); err != nil {
			log.Error(err)
			return nil
		}

		// if has local blockchain database, then update wallet block height. Otherwise, wallet block height is 0 by default
		if ledger.DefaultLedger != nil && ledger.DefaultLedger.Blockchain != nil {
			client.currentHeight = int32(ledger.DefaultLedger.GetLocalBlockChainHeight())
		}
		bytesBuffer := bytes.NewBuffer([]byte{})
		binary.Write(bytesBuffer, binary.LittleEndian, &client.currentHeight)
		if err := client.SaveStoredData("Height", bytesBuffer.Bytes()); err != nil {
			return nil
		}

	} else {
		if ok := client.verifyPasswordKey(passwordKey); !ok {
			return nil
		}
		var err error
		client.iv, err = client.LoadStoredData("IV")
		if err != nil {
			fmt.Println("error: failed to load iv")
			return nil
		}
		encryptedMasterKey, err := client.LoadStoredData("MasterKey")
		if err != nil {
			fmt.Println("error: failed to load master key")
			return nil
		}
		client.masterKey, err = crypto.AesDecrypt(encryptedMasterKey, passwordKey, client.iv)
		if err != nil {
			fmt.Println("error: failed to decrypt master key")
			return nil
		}
		tmp, err := client.LoadStoredData("Height")
		if err != nil {
			return nil
		}
		bytesBuffer := bytes.NewBuffer(tmp)
		var height int32
		binary.Read(bytesBuffer, binary.LittleEndian, &height)
		client.currentHeight = height
	}
	ClearBytes(passwordKey, len(passwordKey))

	// if has local blockchain database and running flag is set, then sync wallet data
	if ledger.DefaultLedger != nil && ledger.DefaultLedger.Blockchain != nil && client.isRunning {
		go client.ProcessBlocks()
	}

	return client
}

func (cl *ClientImpl) GetDefaultAccount() (*Account, error) {
	return cl.GetAccountByProgramHash(cl.mainAccount), nil
}

func (cl *ClientImpl) GetAccount(pubKey *crypto.PubKey) (*Account, error) {
	signatureRedeemScript, err := contract.CreateSignatureRedeemScript(pubKey)
	if err != nil {
		return nil, NewDetailErr(err, ErrNoCode, "CreateSignatureRedeemScript failed")
	}
	programHash, err := ToCodeHash(signatureRedeemScript)
	if err != nil {
		return nil, NewDetailErr(err, ErrNoCode, "ToCodeHash failed")
	}
	return cl.GetAccountByProgramHash(programHash), nil
}

func (cl *ClientImpl) GetAccountByProgramHash(programHash Uint160) *Account {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	if account, ok := cl.accounts[programHash]; ok {
		return account
	}
	return nil
}

func (cl *ClientImpl) GetContract(programHash Uint160) *ct.Contract {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	if contract, ok := cl.contracts[programHash]; ok {
		return contract
	}
	return nil
}

func (cl *ClientImpl) ChangePassword(oldPassword []byte, newPassword []byte) bool {
	// check password
	oldPasswordKey := crypto.ToAesKey(oldPassword)
	if !cl.verifyPasswordKey(oldPasswordKey) {
		fmt.Println("error: password verification failed")
		return false
	}

	// encrypt master key with new password
	newPasswordKey := crypto.ToAesKey(newPassword)
	newMasterKey, err := crypto.AesEncrypt(cl.masterKey, newPasswordKey, cl.iv)
	if err != nil {
		fmt.Println("error: set new password failed")
		return false
	}

	// update wallet file
	newPasswordHash := sha256.Sum256(newPasswordKey)
	if err := cl.SaveStoredData("PasswordHash", newPasswordHash[:]); err != nil {
		fmt.Println("error: wallet update failed(password hash)")
		return false
	}
	if err := cl.SaveStoredData("MasterKey", newMasterKey); err != nil {
		fmt.Println("error: wallet update failed (encrypted master key)")
		return false
	}
	ClearBytes(newPasswordKey, len(newPasswordKey))

	return true
}

func (cl *ClientImpl) ContainsAccount(pubKey *crypto.PubKey) bool {
	signatureRedeemScript, err := contract.CreateSignatureRedeemScript(pubKey)
	if err != nil {
		return false
	}
	programHash, err := ToCodeHash(signatureRedeemScript)
	if err != nil {
		return false
	}
	if cl.GetAccountByProgramHash(programHash) != nil {
		return true
	} else {
		return false
	}
}

func (cl *ClientImpl) Sign(context *ct.ContractContext) bool {
	log.Debug()
	fSuccess := false
	for i, hash := range context.ProgramHashes {
		contract := cl.GetContract(hash)
		if contract == nil {
			continue
		}
		account := cl.GetAccountByProgramHash(hash)
		if account == nil {
			continue
		}

		signature, err := sig.SignBySigner(context.Data, account)
		if err != nil {
			return fSuccess
		}
		err = context.AddContract(contract, account.PublicKey, signature)

		if err != nil {
			fSuccess = false
		} else {
			if i == 0 {
				fSuccess = true
			}
		}
	}
	return fSuccess
}

func (cl *ClientImpl) verifyPasswordKey(passwordKey []byte) bool {
	savedPasswordHash, err := cl.LoadStoredData("PasswordHash")
	if err != nil {
		fmt.Println("error: failed to load password hash")
		return false
	}
	if savedPasswordHash == nil {
		fmt.Println("error: saved password hash is nil")
		return false
	}
	passwordHash := sha256.Sum256(passwordKey)
	///ClearBytes(passwordKey, len(passwordKey))
	if !IsEqualBytes(savedPasswordHash, passwordHash[:]) {
		fmt.Println("error: password wrong")
		return false
	}
	return true
}

func (cl *ClientImpl) EncryptPrivateKey(prikey []byte) ([]byte, error) {
	enc, err := crypto.AesEncrypt(prikey, cl.masterKey, cl.iv)
	if err != nil {
		return nil, err
	}

	return enc, nil
}

func (cl *ClientImpl) DecryptPrivateKey(prikey []byte) ([]byte, error) {
	if prikey == nil {
		return nil, NewDetailErr(errors.New("The PriKey is nil"), ErrNoCode, "")
	}
	if len(prikey) != 96 {
		return nil, NewDetailErr(errors.New("The len of PriKeyEnc is not 96bytes"), ErrNoCode, "")
	}

	dec, err := crypto.AesDecrypt(prikey, cl.masterKey, cl.iv)
	if err != nil {
		return nil, err
	}

	return dec, nil
}

// CreateAccount create a new Account then save it
func (cl *ClientImpl) CreateAccount() (*Account, error) {
	account, err := NewAccount()
	if err != nil {
		return nil, err
	}
	if err := cl.SaveAccount(account); err != nil {
		return nil, err
	}

	return account, nil
}

func (cl *ClientImpl) DeleteAccount(programHash Uint160) error {
	// remove from memory
	delete(cl.accounts, programHash)
	// remove from db
	return cl.DeleteAccountData(BytesToHexString(programHash.ToArray()))
}

func (cl *ClientImpl) CreateAccountByPrivateKey(privateKey []byte) (*Account, error) {
	account, err := NewAccountWithPrivatekey(privateKey)
	if err != nil {
		return nil, err
	}

	if err := cl.SaveAccount(account); err != nil {
		return nil, err
	}

	return account, nil
}

// SaveAccount saves a Account to memory and db
func (cl *ClientImpl) SaveAccount(ac *Account) error {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	// save Account to memory
	programHash := ac.ProgramHash
	cl.accounts[programHash] = ac

	decryptedPrivateKey := make([]byte, 96)
	temp, err := ac.PublicKey.EncodePoint(false)
	if err != nil {
		return err
	}
	for i := 1; i <= 64; i++ {
		decryptedPrivateKey[i-1] = temp[i]
	}
	for i := len(ac.PrivateKey) - 1; i >= 0; i-- {
		decryptedPrivateKey[96+i-len(ac.PrivateKey)] = ac.PrivateKey[i]
	}
	encryptedPrivateKey, err := cl.EncryptPrivateKey(decryptedPrivateKey)
	if err != nil {
		return err
	}
	ClearBytes(decryptedPrivateKey, 96)

	// save Account keys to db
	err = cl.SaveAccountData(programHash.ToArray(), encryptedPrivateKey)
	if err != nil {
		return err
	}

	return nil
}

// LoadAccounts loads all accounts from db to memory
func (cl *ClientImpl) LoadAccounts() error {
	accounts := map[Uint160]*Account{}

	account, err := cl.LoadAccountData()
	if err != nil {
		return err
	}
	for _, a := range account {
		if a.Type == MAINACCOUNT {
			p, _ := HexStringToBytes(a.ProgramHash)
			cl.mainAccount, _ = Uint160ParseFromBytes(p)
		}
		encryptedKeyPair, _ := HexStringToBytes(a.PrivateKeyEncrypted)
		keyPair, err := cl.DecryptPrivateKey(encryptedKeyPair)
		if err != nil {
			log.Error(err)
			continue
		}
		privateKey := keyPair[64:96]
		ac, err := NewAccountWithPrivatekey(privateKey)
		accounts[ac.ProgramHash] = ac
	}

	cl.accounts = accounts
	return nil
}

// CreateContract create a new contract then save it
func (cl *ClientImpl) CreateContract(account *Account) error {
	contract, err := contract.CreateSignatureContract(account.PubKey())
	if err != nil {
		return err
	}
	if err := cl.SaveContract(contract); err != nil {
		return err
	}
	return nil
}

func (cl *ClientImpl) DeleteContract(programHash Uint160) error {
	delete(cl.contracts, programHash)
	return cl.DeleteContractData(BytesToHexString(programHash.ToArray()))
}

// SaveContract saves a contract to memory and db
func (cl *ClientImpl) SaveContract(ct *contract.Contract) error {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	if cl.accounts[ct.ProgramHash] == nil {
		return NewDetailErr(errors.New("SaveContract(): contract.OwnerPubkeyHash not in []accounts"), ErrNoCode, "")
	}

	// save contract to memory
	cl.contracts[ct.ProgramHash] = ct

	// save contract to db
	return cl.SaveContractData(ct)
}

// LoadContracts loads all contracts from db to memory
func (cl *ClientImpl) LoadContracts() error {
	contracts := map[Uint160]*ct.Contract{}

	contract, err := cl.LoadContractData()
	if err != nil {
		return err
	}
	for _, c := range contract {
		rawdata, _ := HexStringToBytes(c.RawData)
		rdreader := bytes.NewReader(rawdata)
		ct := new(ct.Contract)
		ct.Deserialize(rdreader)

		programHash, _ := HexStringToBytes(c.ProgramHash)
		programhash, _ := Uint160ParseFromBytes(programHash)
		ct.ProgramHash = programhash
		contracts[ct.ProgramHash] = ct
	}

	cl.contracts = contracts
	return nil
}

func (client *ClientImpl) LoadCoins() error {
	loadedCoin, err := client.LoadCoinsData()
	if err != nil {
		return err
	}
	for input, coin := range loadedCoin {
		client.coins[input] = coin
	}

	return nil
}
func (client *ClientImpl) SaveCoins() error {
	if err := client.SaveCoinsData(client.coins); err != nil {
		return err
	}
	return nil
}

func (client *ClientImpl) DeleteCoins() error {
	for in, coin := range client.coins {
		// remove from memory
		delete(client.coins, in)
		// remove from db
		if err := client.DeleteCoinsData(coin.Output.ProgramHash); err != nil {
			fmt.Fprintf(os.Stderr, "delete coin error: %v\n", err)
			continue
		}
	}
	return nil
}

func clientIsDefaultBookKeeper(publicKey string) bool {
	for _, bookKeeper := range config.Parameters.BookKeepers {
		if strings.Compare(bookKeeper, publicKey) == 0 {
			return true
		}
	}
	return false
}

func nodeType(typeName string) int {
	if "service" == config.Parameters.NodeType {
		return protocol.SERVICENODE
	} else {
		return protocol.VERIFYNODE
	}
}

func GetClient() Client {
	if !FileExisted(WalletFileName) {
		log.Fatal(fmt.Sprintf("No %s detected, please create a wallet by using command line.", WalletFileName))
		os.Exit(1)
	}
	passwd, err := password.GetAccountPassword()
	if err != nil {
		log.Fatal("Get password error.")
		os.Exit(1)
	}
	c, err := Open(WalletFileName, passwd)
	if err != nil {
		return nil
	}
	return c
}

func GetBookKeepers() []*crypto.PubKey {
	var pubKeys = []*crypto.PubKey{}
	sort.Strings(config.Parameters.BookKeepers)
	for _, key := range config.Parameters.BookKeepers {
		pubKey := []byte(key)
		pubKey, err := hex.DecodeString(key)
		// TODO Convert the key string to byte
		k, err := crypto.DecodePoint(pubKey)
		if err != nil {
			log.Error("Incorrectly book keepers key")
			return nil
		}
		pubKeys = append(pubKeys, k)
	}

	return pubKeys
}

func (client *ClientImpl) GetCoins() map[*transaction.UTXOTxInput]*Coin {
	client.mu.Lock()
	defer client.mu.Unlock()

	return client.coins
}

func (client *ClientImpl) GetAccounts() []*Account {
	client.mu.Lock()
	defer client.mu.Unlock()

	accounts := []*Account{}
	for _, v := range client.accounts {
		accounts = append(accounts, v)
	}
	return accounts
}

func (client *ClientImpl) Rebuild() error {
	// reset wallet block height
	client.currentHeight = -1
	var height int32 = -1
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.LittleEndian, &height)
	if err := client.SaveStoredData("Height", bytesBuffer.Bytes()); err != nil {
		return err
	}

	// reset coins
	if err := client.DeleteCoins(); err != nil {
		return err
	}

	return nil
}
