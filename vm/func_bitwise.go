package vm

import (
	"Elastos.ELA/common"
	"fmt"
)

func opInvert(e *ExecutionEngine) (VMState, error) {
	if e.evaluationStack.Count() < 1 {
		return FAULT, nil
	}
	x := e.evaluationStack.Pop()
	i := AssertStackItem(x).GetBigInteger()
	err := pushData(e, i.Not(i))
	if err != nil {
		return FAULT, err
	}
	return NONE, nil
}

func opEqual(e *ExecutionEngine) (VMState, error) {
	fmt.Println("call opEqual")
	if e.evaluationStack.Count() < 2 {
		return FAULT, nil
	}
	x2 := e.evaluationStack.Pop()
	x1 := e.evaluationStack.Pop()
	b1 := AssertStackItem(x1)
	b2 := AssertStackItem(x2)
	fmt.Printf("b1 = %s\n", common.BytesToHexString(b1.GetByteArray()))
	fmt.Printf("b2 = %s\n", common.BytesToHexString(b2.GetByteArray()))
	err := pushData(e, b1.Equals(b2))
	if err != nil {
		return FAULT, err
	}
	return NONE, nil
}
