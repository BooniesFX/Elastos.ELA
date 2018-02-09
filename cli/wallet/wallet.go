package wallet

import (
	"Elastos.ELA/account"
	. "Elastos.ELA/cli/common"
	. "Elastos.ELA/common"
	"Elastos.ELA/common/password"
	ct "Elastos.ELA/core/contract"
	"Elastos.ELA/crypto"
	"fmt"
	"github.com/urfave/cli"
	"os"
	"strconv"
	"strings"
)

const (
	MinMultiSignKey int = 3
)

func showAccountsInfo(wallet account.Client) {
	accounts := wallet.GetAccounts()
	fmt.Println(" ID   Address\t\t\t\t Public Key")
	fmt.Println("----  -------\t\t\t\t ----------")
	for i, account := range accounts {
		address, _ := account.ProgramHash.ToAddress()
		publicKey, _ := account.PublicKey.EncodePoint(true)
		fmt.Printf("%4s  %s %s\n", strconv.Itoa(i), address, BytesToHexString(publicKey))
	}
}
func showScriptInfo(wallet account.Client) {
	contracts := wallet.GetContracts()
	accounts := wallet.GetAccounts()
	coins := wallet.GetCoins()

	script := []Uint168{}
	// find script address
	for _, contract := range contracts {
		if contract.GetType() == ct.CustomContract {
			found := false
			for _, account := range accounts {
				if contract.ProgramHash == account.ProgramHash {
					found = true
					break
				}
			}
			if !found {
				script = append(script, contract.ProgramHash)
			}
		}
	}

	for _, programHash := range script {
		assets := make(map[Uint256]Fixed64)
		for _, out := range coins {
			if out.Output.ProgramHash == programHash {
				if _, ok := assets[out.Output.AssetID]; !ok {
					assets[out.Output.AssetID] = out.Output.Value
				} else {
					assets[out.Output.AssetID] += out.Output.Value
				}
			}
		}
		address, _ := programHash.ToAddress()
		fmt.Println("-----------------------------------------------------------------------------------")
		fmt.Printf("Address: %s\n", address)
		if len(assets) != 0 {
			fmt.Println(" ID   Asset ID\t\t\t\t\t\t\t\tAmount")
			fmt.Println("----  --------\t\t\t\t\t\t\t\t------")
			i := 0
			for id, value := range assets {
				fmt.Printf("%4s  %s  %v\n", strconv.Itoa(i), BytesToHexString(id.ToArrayReverse()), value)
				i++
			}
		}
		fmt.Println("-----------------------------------------------------------------------------------\n")
	}
}
func showMultisigInfo(wallet account.Client) {
	contracts := wallet.GetContracts()
	accounts := wallet.GetAccounts()
	coins := wallet.GetCoins()

	multisign := []Uint168{}
	// find multisign address
	for _, contract := range contracts {
		if contract.GetType() == ct.MultiSigContract {
			found := false
			for _, account := range accounts {
				if contract.ProgramHash == account.ProgramHash {
					found = true
					break
				}
			}
			if !found {
				multisign = append(multisign, contract.ProgramHash)
			}
		}
	}

	for _, programHash := range multisign {
		assets := make(map[Uint256]Fixed64)
		for _, out := range coins {
			if out.Output.ProgramHash == programHash {
				if _, ok := assets[out.Output.AssetID]; !ok {
					assets[out.Output.AssetID] = out.Output.Value
				} else {
					assets[out.Output.AssetID] += out.Output.Value
				}
			}
		}
		address, _ := programHash.ToAddress()
		fmt.Println("-----------------------------------------------------------------------------------")
		fmt.Printf("Address: %s\n", address)
		if len(assets) != 0 {
			fmt.Println(" ID   Asset ID\t\t\t\t\t\t\t\tAmount")
			fmt.Println("----  --------\t\t\t\t\t\t\t\t------")
			i := 0
			for id, value := range assets {
				fmt.Printf("%4s  %s  %v\n", strconv.Itoa(i), BytesToHexString(id.ToArrayReverse()), value)
				i++
			}
		}
		fmt.Println("-----------------------------------------------------------------------------------\n")
	}
}

func showBalancesInfo(wallet account.Client) {
	coins := wallet.GetCoins()
	assets := make(map[Uint256]Fixed64)
	for _, out := range coins {
		if out.AddressType == account.SingleSign {
			if _, ok := assets[out.Output.AssetID]; !ok {
				assets[out.Output.AssetID] = out.Output.Value
			} else {
				assets[out.Output.AssetID] += out.Output.Value
			}
		}
	}
	if len(assets) == 0 {
		fmt.Println("no assets")
		return
	}
	fmt.Println(" ID   Asset ID\t\t\t\t\t\t\t\tAmount")
	fmt.Println("----  --------\t\t\t\t\t\t\t\t------")
	i := 0
	for id, amount := range assets {
		fmt.Printf("%4s  %s  %v\n", strconv.Itoa(i), BytesToHexString(id.ToArrayReverse()), amount)
		i++
	}
}

func showVerboseInfo(wallet account.Client) {
	accounts := wallet.GetAccounts()
	coins := wallet.GetCoins()

	for _, account := range accounts {
		programHash := account.ProgramHash
		assets := make(map[Uint256]Fixed64)
		address, _ := programHash.ToAddress()
		for _, out := range coins {
			if out.Output.ProgramHash == programHash {
				if _, ok := assets[out.Output.AssetID]; !ok {
					assets[out.Output.AssetID] = out.Output.Value
				} else {
					assets[out.Output.AssetID] += out.Output.Value
				}
			}
		}
		fmt.Println("---------------------------------------------------------------------------------------------------")
		fmt.Printf("Address: %s  ProgramHash: %s\n", address, BytesToHexString(programHash.ToArrayReverse()))
		if len(assets) == 0 {
			continue
		}
		fmt.Println(" ID   Asset ID\t\t\t\t\t\t\t\tAmount")
		fmt.Println("----  --------\t\t\t\t\t\t\t\t------")
		i := 0
		for id, amount := range assets {
			fmt.Printf("%4s  %s  %v\n", strconv.Itoa(i), BytesToHexString(id.ToArrayReverse()), amount)
			i++
		}
	}
}

func getPassword(passwd string) []byte {
	var tmp []byte
	var err error
	if passwd != "" {
		tmp = []byte(passwd)
	} else {
		tmp, err = password.GetPassword()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	return tmp
}

func getConfirmedPassword(passwd string) []byte {
	var tmp []byte
	var err error
	if passwd != "" {
		tmp = []byte(passwd)
	} else {
		tmp, err = password.GetConfirmedPassword()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	return tmp
}

func walletAction(c *cli.Context) error {
	if c.NumFlags() == 0 {
		cli.ShowSubcommandHelp(c)
		return nil
	}
	// wallet name is wallet.dat by default
	name := c.String("name")
	if name == "" {
		os.Exit(1)
	}
	passwd := c.String("password")

	// create wallet
	if c.Bool("create") {
		if FileExisted(name) {
			fmt.Printf("CAUTION: '%s' already exists!\n", name)
			os.Exit(1)
		} else {
			wallet, err := account.Create(name, getConfirmedPassword(passwd))
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			showAccountsInfo(wallet)
		}
		return nil
	}

	// list wallet info
	if item := c.String("list"); item != "" {
		if item != "account" && item != "balance" && item != "verbose" && item != "multisig" && item != "script" {
			fmt.Fprintln(os.Stderr, "--list [account | balance | verbose | multisig | script]")
			os.Exit(1)
		} else {
			wallet, err := account.Open(name, getPassword(passwd))
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			switch item {
			case "account":
				showAccountsInfo(wallet)
			case "balance":
				showBalancesInfo(wallet)
			case "verbose":
				showVerboseInfo(wallet)
			case "multisig":
				showMultisigInfo(wallet)
			case "script":
				showScriptInfo(wallet)
			}
		}
		return nil
	}
	// add multisig account
	multikeys := c.String("addmultisigaccount")
	if multikeys != "" {
		publicKeys := strings.Split(multikeys, ":")
		if len(publicKeys) < MinMultiSignKey {
			fmt.Print("error: public keys is not enough")
			return nil
		}
		var keys []*crypto.PubKey
		for _, v := range publicKeys {
			byteKey, err := HexStringToBytes(v)
			if err != nil {
				fmt.Print("error: invalid public key")
				return nil
			}
			rawKey, err := crypto.DecodePoint(byteKey)
			if err != nil {
				fmt.Print("error: invalid encoded public key")
				return nil
			}
			keys = append(keys, rawKey)
		}
		wallet, err := account.Open(name, getPassword(passwd))
		if err != nil {
			fmt.Print("error: can not open wallet,", err)
			return nil
		}
		mainAccount, err := wallet.GetDefaultAccount()
		if err != nil {
			fmt.Print("error: wallet is broken, main account missing")
			return nil
		}
		// generate M/N multsig contract
		// M = N/2+1
		// M/N could be 2/3, 3/4, 3/5, 4/6, 4/7 ...
		var M = len(keys)/2 + 1
		ct, err := wallet.CreateMultiSignContract(mainAccount.ProgramHash, M, keys)
		if err != nil {
			fmt.Print("error: create multi sign contract failed,", err)
			return nil
		}
		address, err := ct.ProgramHash.ToAddress()
		fmt.Print(address)
		return nil
	}

	// add script account
	if accountitem := c.String("addscriptaccount"); accountitem != "" {
		if accountitem != "maindeposit" && accountitem != "sidedeposit" && accountitem != "mainwithdraw" && accountitem != "sidewithdraw" {
			fmt.Fprintln(os.Stderr, "--addscriptaccount [maindeposit, sidedeposit, mainwithdraw, sidewithdraw]")
			os.Exit(1)
		} else {
			wallet, err := account.Open(name, getPassword(passwd))
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			mainAccount, err := wallet.GetDefaultAccount()
			if err != nil {
				fmt.Print("error: wallet is broken, main account missing")
				return nil
			}
			abkeys := c.String("accounts")
			hash := c.String("hash")
			if abkeys == "" || hash == "" {
				fmt.Println("error: a:b keys and hash are needed")
				return nil
			}
			if abkeys != "" && hash != "" {
				publicKeys := strings.Split(abkeys, ":")
				var keys []*crypto.PubKey
				for _, v := range publicKeys {
					byteKey, err := HexStringToBytes(v)
					if err != nil {
						fmt.Print("error: invalid public key")
						return nil
					}
					rawKey, err := crypto.DecodePoint(byteKey)
					if err != nil {
						fmt.Print("error: invalid encoded public key")
						return nil
					}
					keys = append(keys, rawKey)
				}
				hashbyte, _ := HexStringToBytes(hash)
				switch accountitem {
				case "maindeposit":
					ct, err := wallet.Createmaindepositaccount(mainAccount.ProgramHash, keys, hashbyte)
					if err != nil {
						fmt.Print("error: create multi sign contract failed,", err)
						return nil
					}
					address, err := ct.ProgramHash.ToAddress()
					fmt.Println(address)
				case "sidedeposit":
					ct, err := wallet.Createsidedepositaccount(mainAccount.ProgramHash, keys, hashbyte)
					if err != nil {
						fmt.Print("error: create multi sign contract failed,", err)
						return nil
					}
					address, err := ct.ProgramHash.ToAddress()
					fmt.Println(address)
				case "mainwithdraw":
					ct, err := wallet.Createmainwithdrawaccount(mainAccount.ProgramHash, keys, hashbyte)
					if err != nil {
						fmt.Print("error: create multi sign contract failed,", err)
						return nil
					}
					address, err := ct.ProgramHash.ToAddress()
					fmt.Println(address)
				case "sidewithdraw":
					ct, err := wallet.Createsidewithdrawaccount(mainAccount.ProgramHash, keys, hashbyte)
					if err != nil {
						fmt.Print("error: create multi sign contract failed,", err)
						return nil
					}
					address, err := ct.ProgramHash.ToAddress()
					fmt.Println(address)
				}
			}
		}
		return nil
	}

	// change password
	if c.Bool("changepassword") {
		fmt.Printf("Wallet File: '%s'\n", name)
		passwd, _ := password.GetPassword()
		wallet, err := account.Open(name, passwd)
		if err != nil {
			os.Exit(1)
		}
		fmt.Println("# input new password #")
		newPassword, _ := password.GetConfirmedPassword()
		if ok := wallet.ChangePassword([]byte(passwd), newPassword); !ok {
			fmt.Fprintln(os.Stderr, "failed to change password")
			os.Exit(1)
		}
		fmt.Println("password changed")

		return nil
	}

	// rebuild index
	if c.Bool("reset") {
		wallet, err := account.Open(name, getPassword(passwd))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		if err := wallet.Rebuild(); err != nil {
			fmt.Fprintln(os.Stderr, "delete coins info from wallet file error")
			os.Exit(1)
		}
		fmt.Printf("%s was reset successfully\n", name)

		return nil
	}

	// add accounts
	if num := c.Int("addaccount"); num > 0 {
		wallet, err := account.Open(name, getPassword(passwd))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		for i := 0; i < num; i++ {
			account, err := wallet.CreateAccount()
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			if err := wallet.CreateContract(account); err != nil {
				wallet.DeleteAccount(account.ProgramHash)
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}
		fmt.Printf("%d accounts created\n", num)
		return nil
	}
	return nil
}

func NewCommand() *cli.Command {
	return &cli.Command{
		Name:        "wallet",
		Usage:       "user wallet operation",
		Description: "With nodectl wallet, you could control your asset.",
		ArgsUsage:   "[args]",
		Flags: []cli.Flag{
			cli.BoolFlag{
				Name:  "create, c",
				Usage: "create wallet",
			},
			cli.StringFlag{
				Name:  "list, l",
				Usage: "list wallet information [account, balance, verbose, multisig, script]",
			},
			cli.IntFlag{
				Name:  "addaccount",
				Usage: "add new account address",
			},
			cli.StringFlag{
				Name:  "addmultisigaccount",
				Usage: "add new multi-sign account address",
			},
			cli.StringFlag{
				Name:  "addscriptaccount",
				Usage: "add new script account[maindeposit, sidedeposit, mainwithdraw, sidewithdraw]",
			},
			cli.StringFlag{
				Name:  "accounts",
				Usage: "A : B pubkey of main chain or side chain",
			},
			cli.StringFlag{
				Name:  "hash",
				Usage: "customize secret hash",
			},
			cli.BoolFlag{
				Name:  "changepassword",
				Usage: "change wallet password",
			},
			cli.BoolFlag{
				Name:  "reset",
				Usage: "reset wallet",
			},
			cli.StringFlag{
				Name:  "name, n",
				Usage: "wallet name",
				Value: account.WalletFileName,
			},
			cli.StringFlag{
				Name:  "password, p",
				Usage: "wallet password",
			},
		},
		Action: walletAction,
		OnUsageError: func(c *cli.Context, err error, isSubcommand bool) error {
			PrintError(c, err, "wallet")
			return cli.NewExitError("", 1)
		},
	}
}
