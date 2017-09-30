package asset

import (
	"DNA_POW/account"
	. "DNA_POW/cli/common"
	. "DNA_POW/common"
	"DNA_POW/net/httpjsonrpc"
	"DNA_POW/sdk"
	"fmt"
	"math/rand"
	"os"

	"DNA_POW/core/transaction"
	"bytes"
	"github.com/urfave/cli"
)

const (
	RANDBYTELEN = 4
)

func openWallet(name string, passwd []byte) account.Client {
	if name == account.WalletFileName {
		fmt.Println("Using default wallet: ", account.WalletFileName)
	}
	wallet, err := account.Open(name, passwd)
	if err != nil {
		fmt.Println("Failed to open wallet: ", name)
		os.Exit(1)
	}
	return wallet
}

func assetAction(c *cli.Context) error {
	if c.NumFlags() == 0 {
		cli.ShowSubcommandHelp(c)
		return nil
	}
	reg := c.Bool("reg")
	issue := c.Bool("issue")
	transfer := c.Bool("transfer")
	if !reg && !issue && !transfer {
		cli.ShowSubcommandHelp(c)
		return nil
	}

	wallet := openWallet(c.String("wallet"), WalletPassword(c.String("password")))
	value := c.Int64("value")
	if value == 0 {
		fmt.Println("invalid value [--value]")
		return nil
	}

	var txn *transaction.Transaction
	var buffer bytes.Buffer
	var err error

	if reg {
		name := c.String("name")
		if name == "" {
			rbuf := make([]byte, RANDBYTELEN)
			rand.Read(rbuf)
			name = "DNA-" + ToHexString(rbuf)
		}
		txn, err = sdk.MakeRegTransaction(wallet, name, Fixed64(value))
	} else {
		asset := c.String("asset")
		to := c.String("to")
		if asset == "" || to == "" {
			fmt.Println("missing flag [--asset] or [--to]")
			return nil
		}
		if issue {
			assetID, _ := StringToUint256(asset)
			programhash, _ := StringToUint160(to)
			txn, err = sdk.MakeIssueTransaction(wallet, assetID, programhash, Fixed64(value))
		} else if transfer {
			//txHex, err = sdk.MakeTransferTransaction(admin, to, asset, Fixed64(value))
		}
	}
	if err != nil {
		fmt.Println(err)
		return err
	}
	if err := txn.Serialize(&buffer); err != nil {
		fmt.Println("serialize transaction failed")
		return err
	}
	resp, err := httpjsonrpc.Call(Address(), "sendrawtransaction", 0, []interface{}{ToHexString(buffer.Bytes())})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return err
	}
	FormatOutput(resp)

	return nil
}

func NewCommand() *cli.Command {
	return &cli.Command{
		Name:        "asset",
		Usage:       "asset registration, issuance and transfer",
		Description: "With nodectl asset, you could control assert through transaction.",
		ArgsUsage:   "[args]",
		Flags: []cli.Flag{
			cli.BoolFlag{
				Name:  "reg, r",
				Usage: "regist a new kind of asset",
			},
			cli.BoolFlag{
				Name:  "issue, i",
				Usage: "issue asset that has been registered",
			},
			cli.BoolFlag{
				Name:  "transfer, t",
				Usage: "transfer asset",
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
			cli.StringFlag{
				Name:  "asset, a",
				Usage: "uniq id for asset",
			},
			cli.StringFlag{
				Name:  "name",
				Usage: "asset name",
			},
			cli.StringFlag{
				Name:  "to",
				Usage: "asset to whom",
			},
			cli.Int64Flag{
				Name:  "value, v",
				Usage: "asset ammount",
			},
		},
		Action: assetAction,
		OnUsageError: func(c *cli.Context, err error, isSubcommand bool) error {
			PrintError(c, err, "asset")
			return cli.NewExitError("", 1)
		},
	}
}
