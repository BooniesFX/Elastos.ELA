package program

import (
	. "Elastos.ELA/common"
	"Elastos.ELA/vm/opcode"
	"bytes"
	"math/big"
)

type ProgramBuilder struct {
	buffer bytes.Buffer
}

func NewProgramBuilder() *ProgramBuilder {
	return &ProgramBuilder{
	//TODO: add sync pool for create ProgramBuilder
	}
}

func (pb *ProgramBuilder) AddOp(op opcode.OpCode) {
	pb.buffer.WriteByte(byte(op))
}

func (pb *ProgramBuilder) AddCodes(codes []byte) {
	pb.buffer.Write(codes)
}

func (pb *ProgramBuilder) PushNumber(number *big.Int) {
	if number.Cmp(big.NewInt(-1)) == 0 {
		pb.AddOp(opcode.PUSHM1)
		return
	}
	if number.Cmp(big.NewInt(0)) == 0 {
		pb.AddOp(opcode.PUSH0)
		return
	}
	if number.Cmp(big.NewInt(0)) == 1 && number.Cmp(big.NewInt(16)) <= 0 {
		pb.AddOp(opcode.OpCode(byte(opcode.PUSH1) - 1 + number.Bytes()[0]))
		return
	}
	pb.PushData(number.Bytes())
}

func (pb *ProgramBuilder) PushData(data []byte) {
	if data == nil {
		return //TODO: add error
	}

	if len(data) <= int(opcode.PUSHBYTES75) {
		pb.buffer.WriteByte(byte(len(data)))
		pb.buffer.Write(data[0:])
	} else if len(data) < 0x100 {
		pb.AddOp(opcode.PUSHDATA1)
		pb.buffer.WriteByte(byte(len(data)))
		pb.buffer.Write(data[0:])
	} else if len(data) < 0x10000 {
		pb.AddOp(opcode.PUSHDATA2)
		dataByte := IntToBytes(len(data))
		pb.buffer.Write(dataByte[0:2])
		pb.buffer.Write(data[0:])
	} else {
		pb.AddOp(opcode.PUSHDATA4)
		dataByte := IntToBytes(len(data))
		pb.buffer.Write(dataByte[0:4])
		pb.buffer.Write(data[0:])
	}
}

func (pb *ProgramBuilder) ToArray() []byte {
	return pb.buffer.Bytes()
}
