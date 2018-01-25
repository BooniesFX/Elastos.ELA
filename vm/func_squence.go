package vm

import (
	"Elastos.ELA/core/transaction"
	"Elastos.ELA/vm/errors"
)

func opCheckAfter(e *ExecutionEngine) (VMState, error) {
	if e.scriptContainer == nil {
		return FAULT, errors.ErrBadValue
	}
	txn := e.scriptContainer.(*transaction.Transaction)
	if txn == nil {
		return FAULT, errors.ErrFault
	}
	//transaction.TxStore.GetTransaction()
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
	return NONE, nil
}
