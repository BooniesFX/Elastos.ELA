package vm

import (
	"Elastos.ELA/core/transaction"
	"Elastos.ELA/vm/errors"
	"fmt"
)

func opCheckAfter(e *ExecutionEngine) (VMState, error) {
	fmt.Println("call opCheckAfter")
	if e.scriptContainer == nil {
		return FAULT, errors.ErrBadValue
	}
	txn := e.scriptContainer.(*transaction.Transaction)
	if txn == nil {
		return FAULT, errors.ErrFault
	}
	for _, utxo := range txn.UTXOInputs {
		_, h, err := transaction.TxStore.GetTransaction(utxo.ReferTxID)
		if err != nil {
			return FAULT, errors.ErrFault
		}
		x := e.evaluationStack.Pop()
		i := AssertStackItem(x).GetBigInteger().Uint64()
		fmt.Printf("relative height = %d\n", i)
		fmt.Printf("txn height =  %d\n", transaction.TxStore.GetHeight())
		if transaction.TxStore.GetHeight() < h+uint32(i) {
			return FAULT, errors.ErrFault
		}
	}
	return NONE, nil
}

func opCheckBefore(e *ExecutionEngine) (VMState, error) {
	if e.scriptContainer == nil {
		return FAULT, errors.ErrBadValue
	}
	txn := e.scriptContainer.(*transaction.Transaction)
	if txn == nil {
		return FAULT, errors.ErrFault
	}
	for _, utxo := range txn.UTXOInputs {
		_, h, err := transaction.TxStore.GetTransaction(utxo.ReferTxID)
		if err != nil {
			return FAULT, errors.ErrFault
		}
		x := e.evaluationStack.Pop()
		i := AssertStackItem(x).GetBigInteger().Uint64()
		fmt.Printf("h = %d\n relative height = %d\n", h, i)
		fmt.Printf("txn height =  %d\n", transaction.TxStore.GetHeight())
		if transaction.TxStore.GetHeight() >= h+uint32(i) {
			return FAULT, errors.ErrFault
		}
	}
	return NONE, nil
}

func opInvalidVoutVerify(e *ExecutionEngine) (VMState, error) {
	if e.scriptContainer == nil {
		return FAULT, errors.ErrBadValue
	}
	txn := e.scriptContainer.(*transaction.Transaction)
	if txn == nil {
		return FAULT, errors.ErrFault
	}
	for _, utxo := range txn.Outputs {
		addr, _ := utxo.ProgramHash.ToAddress()
		fmt.Printf("addr = %s \n", addr)
		if addr != "XRtbQNeQ8Wwzexe86217iFtuwsx2JQMaQV" {
			return FAULT, errors.ErrBadValue
		}
	}
	return NONE, nil
}
