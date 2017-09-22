package main

import (
	"DNA_POW/account"
	"DNA_POW/common/config"
	"DNA_POW/common/log"
	"DNA_POW/consensus/dbft"
	"DNA_POW/consensus/pow"
	"DNA_POW/core/ledger"
	"DNA_POW/core/store/ChainStore"
	"DNA_POW/core/transaction"
	"DNA_POW/crypto"
	"DNA_POW/net"
	"DNA_POW/net/httpjsonrpc"
	"DNA_POW/net/httprestful"
	"DNA_POW/net/httpwebsocket"
	"DNA_POW/net/protocol"
	"os"
	"runtime"
	"time"
)

const (
	DefaultMultiCoreNum = 4
)

func init() {
	log.Init(log.Path, log.Stdout)
	var coreNum int
	if config.Parameters.MultiCoreNum > DefaultMultiCoreNum {
		coreNum = int(config.Parameters.MultiCoreNum)
	} else {
		coreNum = DefaultMultiCoreNum
	}
	log.Debug("The Core number is ", coreNum)
	runtime.GOMAXPROCS(coreNum)
}

func handleLogFile(consensus string) {
	switch consensus {

	case "pow":
		/* TODO */

	case "dbft":
		go func() {
			for {
				time.Sleep(dbft.GenBlockTime)
				log.Trace("BlockHeight = ", ledger.DefaultLedger.Blockchain.BlockHeight)
				isNeedNewFile := log.CheckIfNeedNewFile()
				if isNeedNewFile == true {
					log.ClosePrintLog()
					log.Init(log.Path, os.Stdout)
				}
			} //for end
		}()
	}
}

func startConsensus(client account.Client, noder protocol.Noder) bool {
	if protocol.SERVICENODENAME != config.Parameters.NodeType {
		if config.Parameters.ConsensusType == "pow" &&
			config.Parameters.PowConfiguration.Switch == "enable" {
			log.Info("Start POW Services")
			powServices := pow.NewPowService(client, "logPow", noder)
			//httpjsonrpc.RegistDbftService(powServices)
			go powServices.Start()
			handleLogFile("pow")
			time.Sleep(5 * time.Second)
			return true
		} else if config.Parameters.ConsensusType == "dbft" {
			log.Info("5. Start DBFT Services")
			dbftServices := dbft.NewDbftService(client, "logdbft", noder)
			httpjsonrpc.RegistDbftService(dbftServices)
			go dbftServices.Start()
			handleLogFile("dbft")
			time.Sleep(5 * time.Second)
			return true
		} else {
			log.Fatal("Start consensus ERROR,consensusType is: ", config.Parameters.ConsensusType)
			return false
		}
	}
	return true
}

func main() {
	var acct *account.Account
	var blockChain *ledger.Blockchain
	var err error
	var noder protocol.Noder
	log.Trace("Node version: ", config.Version)

	if len(config.Parameters.BookKeepers) < account.DefaultBookKeeperCount {
		log.Fatal("At least ", account.DefaultBookKeeperCount, " BookKeepers should be set at config.json")
		os.Exit(1)
	}

	log.Info("0. Loading the Ledger")
	ledger.DefaultLedger = new(ledger.Ledger)
	ledger.DefaultLedger.Store, err = ChainStore.NewLedgerStore()
	defer ledger.DefaultLedger.Store.Close()
	if err != nil {
		log.Fatal("open LedgerStore err:", err)
		os.Exit(1)
	}
	ledger.DefaultLedger.Store.InitLedgerStore(ledger.DefaultLedger)
	transaction.TxStore = ledger.DefaultLedger.Store
	crypto.SetAlg(config.Parameters.EncryptAlg)

	log.Info("1. Open the account")
	client := account.GetClient()
	if client == nil {
		log.Fatal("Can't get local account.")
		goto ERROR
	}
	acct, err = client.GetDefaultAccount()
	if err != nil {
		log.Fatal(err)
		goto ERROR
	}
	log.Debug("The Node's PublicKey ", acct.PublicKey)
	ledger.StandbyBookKeepers = account.GetBookKeepers()

	log.Info("3. BlockChain init")
	blockChain, err = ledger.NewBlockchainWithGenesisBlock(ledger.StandbyBookKeepers)
	if err != nil {
		log.Fatal(err, "  BlockChain generate failed")
		goto ERROR
	}
	ledger.DefaultLedger.Blockchain = blockChain

	log.Info("4. Start the P2P networks")
	// Don't need two return value.
	noder = net.StartProtocol(acct.PublicKey)
	httpjsonrpc.RegistRpcNode(noder)
	time.Sleep(20 * time.Second)
	noder.SyncNodeHeight()
	noder.WaitForFourPeersStart()
	noder.WaitForSyncBlkFinish()
	if !startConsensus(client, noder) {
		goto ERROR
	}

	log.Info("--Start the RPC interface")
	go httpjsonrpc.StartRPCServer()
	go httpjsonrpc.StartLocalServer()
	go httprestful.StartServer(noder)
	go httpwebsocket.StartServer(noder)
	select {}
ERROR:
	os.Exit(1)
}
