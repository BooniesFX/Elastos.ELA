package crosschain

import (
	"Elastos.ELA/account"
	. "Elastos.ELA/cli/common"
	. "Elastos.ELA/common"
	"Elastos.ELA/common/password"
	"Elastos.ELA/core/signature"
	tx "Elastos.ELA/core/transaction"
	"Elastos.ELA/net/httpjsonrpc"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/urfave/cli"
	"os"
	"strings"
)

func shaTransaction(c *cli.Context) {
	s := c.String("secret")
	if s == "" {
		fmt.Println("secret is required with [--secret]")
		os.Exit(1)
	}

	b := []byte(s)
	sh := sha256.New()
	sh.Write(b)
	bt := sh.Sum(nil)

	fmt.Printf("sha256(s) = %s\n", BytesToHexString(bt))
}
func deposittosideTransaction(c *cli.Context) error {
	asset := c.String("asset")
	from := c.String("from")
	to := c.String("to")
	keys := c.String("keys")
	shash := c.String("hash")
	fee := c.String("fee")
	value := c.String("value")
	msg := ""
	switch {
	case asset == "":
		msg = "asset id is required with [--asset]"
	case from == "":
		msg = "sender address is required with [--from]"
	case to == "":
		msg = "to address is required with [--to]"
	case keys == "":
		msg = "keys is required with [--key]"
	case value == "":
		msg = "asset amount is required with [--value]"
	case shash == "":
		msg = "secrethash is required with [--hash]"
	case fee == "":
		fee = "0.001"
	}
	if msg != "" {
		fmt.Fprintln(os.Stderr, msg)
		os.Exit(1)
	}

	publicKeys := strings.Split(keys, ":")
	resp, err := httpjsonrpc.Call(Address(), "deposittosideTransaction", 0, []interface{}{asset, from, to, publicKeys[0], publicKeys[1], value, fee, shash})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return err
	}

	FormatOutput(resp)
	return nil

}
func refunddepositTransaction(c *cli.Context) error {
	asset := c.String("asset")
	from := c.String("from")
	to := c.String("to")
	keys := c.String("keys")
	s := c.String("hash")
	fee := c.String("fee")
	value := c.String("value")
	msg := ""
	switch {
	case asset == "":
		msg = "asset id is required with [--asset]"
	case from == "":
		msg = "sender address is required with [--from]"
	case to == "":
		msg = "to address is required with [--to]"
	case keys == "":
		msg = "keys is required with [--key]"
	case value == "":
		msg = "asset amount is required with [--value]"
	case s == "":
		msg = "secrethash is required with [--hash]"
	case fee == "":
		fee = "0.001"
	}
	if msg != "" {
		fmt.Fprintln(os.Stderr, msg)
		os.Exit(1)
	}
	publicKeys := strings.Split(keys, ":")
	resp, err := httpjsonrpc.Call(Address(), "deposittosideTransaction", 0, []interface{}{asset, from, to, publicKeys[0], publicKeys[1], value, fee, s})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return err
	}

	FormatOutput(resp)
	return nil
}
func depositunlockTransaction(c *cli.Context) error {
	asset := c.String("asset")
	from := c.String("from")
	to := c.String("to")
	keys := c.String("keys")
	s := c.String("hash")
	fee := c.String("fee")
	value := c.String("value")
	msg := ""
	switch {
	case asset == "":
		msg = "asset id is required with [--asset]"
	case from == "":
		msg = "sender address is required with [--from]"
	case to == "":
		msg = "to address is required with [--to]"
	case keys == "":
		msg = "keys is required with [--key]"
	case value == "":
		msg = "asset amount is required with [--value]"
	case s == "":
		msg = "secrethash is required with [--hash]"
	case fee == "":
		fee = "0.001"
	}
	if msg != "" {
		fmt.Fprintln(os.Stderr, msg)
		os.Exit(1)
	}
	publicKeys := strings.Split(keys, ":")
	resp, err := httpjsonrpc.Call(Address(), "depositunlockTransaction", 0, []interface{}{asset, from, to, publicKeys[0], value, fee, s})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return err
	}

	FormatOutput(resp)

	return nil
}

func withdrawTransaction(c *cli.Context) error {
	asset := c.String("asset")
	from := c.String("from")
	to := c.String("to")
	keys := c.String("keys")
	s := c.String("hash")
	fee := c.String("fee")
	value := c.String("value")
	msg := ""
	switch {
	case asset == "":
		msg = "asset id is required with [--asset]"
	case from == "":
		msg = "sender address is required with [--from]"
	case to == "":
		msg = "receiver address is required with [--to]"
	case keys == "":
		msg = "keys is required with [--key]"
	case value == "":
		msg = "asset amount is required with [--value]"
	case fee == "":
		fee = "0.001"
	}
	if msg != "" {
		fmt.Fprintln(os.Stderr, msg)
		os.Exit(1)
	}
	publicKeys := strings.Split(keys, ":")
	resp, err := httpjsonrpc.Call(Address(), "withdrawTransaction", 0, []interface{}{asset, from, to, publicKeys[0], publicKeys[1], value, fee, s})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return err
	}

	FormatOutput(resp)
	return nil
}

func refundtokenTransaction(c *cli.Context) error {
	asset := c.String("asset")
	from := c.String("from")
	to := c.String("to")
	keys := c.String("keys")
	s := c.String("hash")
	fee := c.String("fee")
	value := c.String("value")
	msg := ""
	switch {
	case asset == "":
		msg = "asset id is required with [--asset]"
	case from == "":
		msg = "sender address is required with [--from]"
	case to == "":
		msg = "to address is required with [--to]"
	case keys == "":
		msg = "keys is required with [--key]"
	case value == "":
		msg = "asset amount is required with [--value]"
	case s == "":
		msg = "secrethash is required with [--hash]"
	case fee == "":
		fee = "0.001"
	}
	if msg != "" {
		fmt.Fprintln(os.Stderr, msg)
		os.Exit(1)
	}
	publicKeys := strings.Split(keys, ":")
	resp, err := httpjsonrpc.Call(Address(), "withdrawunlockTransaction", 0, []interface{}{asset, from, to, publicKeys[0], publicKeys[1], value, fee, s})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return err
	}

	FormatOutput(resp)

	return nil
}

func refundtosideTransaction(c *cli.Context) error {
	asset := c.String("asset")
	from := c.String("from")
	to := c.String("to")
	keys := c.String("keys")
	s := c.String("hash")
	fee := c.String("fee")
	value := c.String("value")
	msg := ""
	switch {
	case asset == "":
		msg = "asset id is required with [--asset]"
	case from == "":
		msg = "sender address is required with [--from]"
	case to == "":
		msg = "to address is required with [--to]"
	case keys == "":
		msg = "keys is required with [--key]"
	case value == "":
		msg = "asset amount is required with [--value]"
	case s == "":
		msg = "secrethash is required with [--hash]"
	case fee == "":
		fee = "0.001"
	}
	if msg != "" {
		fmt.Fprintln(os.Stderr, msg)
		os.Exit(1)
	}
	publicKeys := strings.Split(keys, ":")
	resp, err := httpjsonrpc.Call(Address(), "withdrawTransaction", 0, []interface{}{asset, from, to, publicKeys[0], publicKeys[1], value, fee, s})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return err
	}

	FormatOutput(resp)

	return nil
}

func destroytokenTransaction(c *cli.Context) error {
	asset := c.String("asset")
	from := c.String("from")
	to := c.String("to")
	keys := c.String("keys")
	s := c.String("hash")
	fee := c.String("fee")
	value := c.String("value")
	msg := ""
	switch {
	case asset == "":
		msg = "asset id is required with [--asset]"
	case from == "":
		msg = "sender address is required with [--from]"
	case to == "":
		msg = "to address is required with [--to]"
	case keys == "":
		msg = "keys is required with [--key]"
	case value == "":
		msg = "asset amount is required with [--value]"
	case fee == "":
		fee = "0.001"
	case s == "":
		msg = "secrethash is required with [--hash]"
	}
	if msg != "" {
		fmt.Fprintln(os.Stderr, msg)
		os.Exit(1)
	}
	publicKeys := strings.Split(keys, ":")
	resp, err := httpjsonrpc.Call(Address(), "withdrawunlockTransaction", 0, []interface{}{asset, from, to, publicKeys[0], publicKeys[1], value, fee, s})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return err
	}

	FormatOutput(resp)

	return nil
}

func signTransaction(c *cli.Context, wallet account.Client) error {
	rawtxn := c.String("rawtxn")
	secret := c.String("secret")
	if rawtxn != "" && secret != "" {
		bytetxn, _ := HexStringToBytes(rawtxn)
		bytesecret := []byte(secret)
		var txn tx.Transaction
		txn.Deserialize(bytes.NewReader(bytetxn))
		mainAccount, _ := wallet.GetDefaultAccount()
		if mainAccount == nil {
			fmt.Println("error: no available account detected")
		} else {

			sig, _ := signature.SignBySigner(&txn, mainAccount)
			newsig := []byte{}
			newsig = append(newsig, byte(len(sig)))
			newsig = append(newsig, sig...)

			newsig = append(newsig, byte(len(bytesecret)))
			newsig = append(newsig, bytesecret...)

			newsig = append(newsig, 0x51)

			txn.Programs[0].Parameter = nil
			txn.Programs[0].Parameter = append(txn.Programs[0].Parameter, newsig...)

			fmt.Printf("sign code = %s\n", BytesToHexString(txn.Programs[0].Code))
			fmt.Printf("sign Parameter = %s\n", BytesToHexString(txn.Programs[0].Parameter))
			var buffer bytes.Buffer
			txn.Serialize(&buffer)
			txHex := hex.EncodeToString(buffer.Bytes())
			resp, err := httpjsonrpc.Call(Address(), "sendrawtransaction", 0, []interface{}{txHex})
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return err
			}

			FormatOutput(resp)
		}

	} else {
		fmt.Fprintln(os.Stderr, "raw transaction and secret is both required")
		os.Exit(1)
	}

	return nil
}
func unlocksignTransaction(c *cli.Context, wallet account.Client) error {
	rawtxn := c.String("rawtxn")
	secret := c.String("secret")
	if rawtxn != "" && secret != "" {
		bytetxn, _ := HexStringToBytes(rawtxn)
		bytesecret := []byte(secret)
		var txn tx.Transaction
		txn.Deserialize(bytes.NewReader(bytetxn))
		mainAccount, _ := wallet.GetDefaultAccount()
		if mainAccount == nil {
			fmt.Println("error: no available account detected")
		} else {

			sig, _ := signature.SignBySigner(&txn, mainAccount)
			newsig := []byte{}
			newsig = append(newsig, byte(len(sig)))
			newsig = append(newsig, sig...)

			newsig = append(newsig, byte(len(bytesecret)))
			newsig = append(newsig, bytesecret...)
			fmt.Printf("bytesecret = %v\n", bytesecret)
			txn.Programs[0].Parameter = nil
			txn.Programs[0].Parameter = append(txn.Programs[0].Parameter, newsig...)
			fmt.Printf("sign code = %s\n", BytesToHexString(txn.Programs[0].Code))
			fmt.Printf("sign Parameter =%v %s\n", txn.Programs[0].Parameter, BytesToHexString(txn.Programs[0].Parameter))
			var buffer bytes.Buffer
			txn.Serialize(&buffer)
			txHex := hex.EncodeToString(buffer.Bytes())
			resp, err := httpjsonrpc.Call(Address(), "sendrawtransaction", 0, []interface{}{txHex})
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return err
			}

			FormatOutput(resp)
		}

	} else {
		fmt.Fprintln(os.Stderr, "raw transaction and secret is both required")
		os.Exit(1)
	}

	return nil
}
func refundsignTransaction(c *cli.Context, wallet account.Client) error {
	if rawtxn := c.String("rawtxn"); rawtxn != "" {

		bytetxn, _ := HexStringToBytes(rawtxn)

		var txn tx.Transaction
		txn.Deserialize(bytes.NewReader(bytetxn))
		mainAccount, _ := wallet.GetDefaultAccount()
		if mainAccount == nil {
			fmt.Println("error: no available account detected")
		} else {

			sig, _ := signature.SignBySigner(&txn, mainAccount)
			newsig := []byte{}
			newsig = append(newsig, byte(len(sig)))
			newsig = append(newsig, sig...)

			newsig = append(newsig, 0x00)

			txn.Programs[0].Parameter = nil
			txn.Programs[0].Parameter = append(txn.Programs[0].Parameter, newsig...)

			fmt.Printf("sign code = %s\n", BytesToHexString(txn.Programs[0].Code))
			fmt.Printf("sign Parameter = %s\n", BytesToHexString(txn.Programs[0].Parameter))
			var buffer bytes.Buffer
			txn.Serialize(&buffer)
			txHex := hex.EncodeToString(buffer.Bytes())
			resp, err := httpjsonrpc.Call(Address(), "sendrawtransaction", 0, []interface{}{txHex})
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return err
			}

			FormatOutput(resp)
		}

	} else {
		fmt.Fprintln(os.Stderr, "raw transaction is required")
		os.Exit(1)
	}

	return nil
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
func crosschainAction(c *cli.Context) error {
	if c.NumFlags() == 0 {
		cli.ShowSubcommandHelp(c)
		return nil
	}
	name := c.String("wallet")
	if name == "" {
		os.Exit(1)
	}
	passwd := c.String("password")
	wallet, err := account.Open(name, getPassword(passwd))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	switch {
	case c.Bool("sha"):
		shaTransaction(c)
	case c.Bool("deposittoside"):
		err = deposittosideTransaction(c)
	case c.Bool("refunddeposit"):
		err = refunddepositTransaction(c)
	case c.Bool("depositunlocktoken"):
		err = depositunlockTransaction(c)
	case c.Bool("withdraw"):
		err = withdrawTransaction(c)
	case c.Bool("refundtoside"):
		err = refundtosideTransaction(c)
	case c.Bool("refundtoken"):
		err = refundtokenTransaction(c)
	case c.Bool("destroytoken"):
		err = destroytokenTransaction(c)
	case c.Bool("sign"):
		err = signTransaction(c, wallet)
	case c.Bool("unlocksign"):
		err = unlocksignTransaction(c, wallet)
	case c.Bool("refundsign"):
		err = refundsignTransaction(c, wallet)
	default:
		cli.ShowSubcommandHelp(c)
		return nil
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	return nil
}
func NewCommand() *cli.Command {
	return &cli.Command{
		Name:        "crosschain",
		Usage:       "crosschain transaction deposit, withdraw and sign",
		Description: "With nodectl multisig, you use crosschain transation.",
		ArgsUsage:   "[args]",
		Flags: []cli.Flag{
			cli.BoolFlag{
				Name:  "deposittoside",
				Usage: "ela in script account to sidechain account on mainchain",
			},
			cli.BoolFlag{
				Name:  "refunddeposit",
				Usage: "refund ela to user account",
			},
			cli.BoolFlag{
				Name:  "depositunlocktoken",
				Usage: "unlock token to user`s side account",
			},
			cli.BoolFlag{
				Name:  "withdraw",
				Usage: "withdraw ela to user account",
			},
			cli.BoolFlag{
				Name:  "refundtoside",
				Usage: "refund ela to side account when withdraw",
			},
			cli.BoolFlag{
				Name:  "refundtoken",
				Usage: "refund token to user side account",
			},
			cli.BoolFlag{
				Name:  "destroytoken",
				Usage: "destroytoken token",
			},
			cli.BoolFlag{
				Name:  "sign",
				Usage: "sign transaction",
			},
			cli.BoolFlag{
				Name:  "unlocksign",
				Usage: "sign unlock transaction",
			},
			cli.BoolFlag{
				Name:  "refundsign",
				Usage: "sign refund transaction",
			},
			cli.BoolFlag{
				Name:  "sha",
				Usage: "sha256",
			},
			cli.StringFlag{
				Name:  "asset, a",
				Usage: "uniq id for asset",
			},
			cli.StringFlag{
				Name:  "from, f",
				Usage: "asset from which address",
			},
			cli.StringFlag{
				Name:  "to, t",
				Usage: "asset to which address",
			},
			cli.StringFlag{
				Name:  "keys, k",
				Usage: "pkA:pkS",
			},
			cli.StringFlag{
				Name:  "value, v",
				Usage: "asset amount",
				Value: "",
			},
			cli.StringFlag{
				Name:  "fee",
				Usage: "transfer fee",
				Value: "",
			},
			cli.StringFlag{
				Name:  "hash",
				Usage: "hash of secret",
				Value: "",
			},
			cli.StringFlag{
				Name:  "rawtxn",
				Usage: "raw transaction to sign",
			},
			cli.StringFlag{
				Name:  "secret, e",
				Usage: "user define secret",
			},
			cli.StringFlag{
				Name:  "wallet, w",
				Usage: "wallet name",
				Value: account.WalletFileName,
			},
			cli.StringFlag{
				Name:  "password, p",
				Usage: "wallet password",
			},
		},
		Action: crosschainAction,
		OnUsageError: func(c *cli.Context, err error, isSubcommand bool) error {
			PrintError(c, err, "crosschain")
			return cli.NewExitError("", 1)
		},
	}
}
