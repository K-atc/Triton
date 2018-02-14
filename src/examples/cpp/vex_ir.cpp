
#include <iostream>
#include <triton/api.hpp>
// #include <triton/x86Specifications.hpp>

using namespace triton;
using namespace triton::arch;


struct op {
  unsigned int    addr;
  unsigned char*  inst;
  unsigned int    size;
};

struct op trace[] = {
  {0x400000, (unsigned char *)"\x48\x8b\x05\xb8\x13\x00\x00", 7}, /* mov        rax, QWORD PTR [rip+0x13b8] */
  {0x400007, (unsigned char *)"\x48\x8d\x34\xc3",             4}, /* lea        rsi, [rbx+rax*8]            */
  {0x40000b, (unsigned char *)"\x67\x48\x8D\x74\xC3\x0A",     6}, /* lea        rsi, [ebx+eax*8+0xa]        */
  {0x40000b, (unsigned char *)"\x67\x8D\x74\xC3\x0A",         5}, /* lea        esi, [ebx+eax*8+0xa]        */
  {0x40000b, (unsigned char *)"\x48\x8D\x74\xDB\x0A",         5}, /* lea        rsi, [rbx+rax*8+0xa]        */
  {0x40000b, (unsigned char *)"\x48\x8D\x74\xC3\x0A",         5}, /* lea        rsi, [rbx+rax*8+0xa]        */
  {0x40000b, (unsigned char *)"\x48\x8D\x73\x0A",             4}, /* lea        rsi, [rbx+0xa]              */
  //// {0x400011, (unsigned char *)"\x66\x0F\xD7\xD1",             4}, /* pmovmskb   edx, xmm1                   */ // see below
  {0x400015, (unsigned char *)"\x89\xd0",                     2}, /* mov        eax, edx                    */
  {0x400017, (unsigned char *)"\x80\xf4\x99",                 3}, /* xor        ah, 0x99                    */
  {0x40001a, (unsigned char *)"\x48\x31\xc0",                 3}, /* xor        rax, rax                    */
  {0x40001d, (unsigned char *)"\x80\x30\x99",                 3}, /* xor        byte ptr [rax], 0x99        */
  {0x400020, (unsigned char *)"\x80\x30\x99",                 3}, /* xor        byte ptr [rax], 0x99        */
  {0x400023, (unsigned char *)"\x0F\x87\x00\x00\x00\x00",     6}, /* ja         11                          */
  {0x0,      nullptr,                                         0}
};

int main(int ac, const char **av) {

  /* Set the arch */
  api.setArchitecture(ARCH_VEX_X86_64);

  for (unsigned int i = 0; trace[i].inst; i++) {
    /* Build an instruction */
    Instruction baseInst;

    /* Setup opcodes */
    baseInst.setOpcodes(trace[i].inst, trace[i].size);

    /* optional - Setup address */
    baseInst.setAddress(trace[i].addr);

    /* Process everything */
    api.processing(baseInst);

    std::cout << baseInst << std::endl;
    for (auto &inst : baseInst.ir) {
      std::cout << "(IR) " << inst << std::endl;
      std::cout << "~~~~~~~" << std::endl;
      for (unsigned int op_index = 0; op_index != inst.operands.size(); op_index++) {
        std::cout << "\tOperand " << op_index << ": " << inst.operands[op_index] << std::endl;
        if (inst.operands[op_index].getType() == OP_MEM) {
          std::cout << "\t   base  : " << inst.operands[op_index].getMemory().getBaseRegister() << std::endl;
          // std::cout << "\t   index : " << inst.operands[op_index].getMemory().getIndexRegister() << std::endl;
          // std::cout << "\t   disp  : " << inst.operands[op_index].getMemory().getDisplacement() << std::endl;
          // std::cout << "\t   scale : " << inst.operands[op_index].getMemory().getScale() << std::endl;
        }
      }

      std::cout << "\t-------" << std::endl;

      for (unsigned int exp_index = 0; exp_index != inst.symbolicExpressions.size(); exp_index++) {
        auto expr = inst.symbolicExpressions[exp_index];
        std::cout << "\tSymExpr " << exp_index << ": " << expr << std::endl;
      }

      std::cout << std::endl << std::endl;
    }
  }

  return 0;
}

/*
*** [address = 0x400011] ***
------ IMark(0x400011, 4, 0) ------
  type = Ist_IMark|Iex_Invalid|Iop_Invalid
  tag = Ist_IMark
  offset = 0
  tmp = 0
  disasm = pmovmskb edx, xmm1
  addr = 0x400011
  len = 4
t0 = GET:V128(offset=256)
  type = Ist_WrTmp|Iex_Get|Iop_Invalid
  tag = Ist_WrTmp
  offset = 0
  tmp = 0
  data.tag = Iex_Get
  data.con = 0x0
  data.tmp = 0
  data.offset = 0x100
  data.result_size = 128
  data.ty = Ity_V128
  data.addr.tag = Iex_Invalid
  data.op = Iop_Invalid
  data.nargs = 0
t3 = GetMSBs8x16(t0)
  type = Ist_WrTmp|Iex_Unop|Iop_Invalid
  tag = Ist_WrTmp
  offset = 0
  tmp = 3
  data.tag = Iex_Unop
  data.con = 0x0
  data.tmp = 0
  data.offset = 0x0
  data.result_size = 16
  data.ty = Ity_Invalid
  data.addr.tag = Iex_Invalid
  data.op = Iop_GetMSBs8x16
  data.nargs = 1
  data.args[0].tag = Iex_RdTmp
  data.args[0].con = 0x0
  data.args[0].tmp = 0
  data.args[0].offset = 0x0
  data.args[0].result_size = 128
  data.args[0].ty = Ity_Invalid
t2 = 16Uto32(t3)
  type = Ist_WrTmp|Iex_Unop|Iop_CastU
  tag = Ist_WrTmp
  offset = 0
  tmp = 2
  data.tag = Iex_Unop
  data.con = 0x0
  data.tmp = 0
  data.offset = 0x0
  data.result_size = 32
  data.ty = Ity_Invalid
  data.addr.tag = Iex_Invalid
  data.op = Iop_16Uto32
  data.nargs = 1
  data.args[0].tag = Iex_RdTmp
  data.args[0].con = 0x0
  data.args[0].tmp = 3
  data.args[0].offset = 0x0
  data.args[0].result_size = 16
  data.args[0].ty = Ity_Invalid
t4 = 32Uto64(t2)
  type = Ist_WrTmp|Iex_Unop|Iop_CastU
  tag = Ist_WrTmp
  offset = 0
  tmp = 4
  data.tag = Iex_Unop
  data.con = 0x0
  data.tmp = 0
  data.offset = 0x0
  data.result_size = 64
  data.ty = Ity_Invalid
  data.addr.tag = Iex_Invalid
  data.op = Iop_32Uto64
  data.nargs = 1
  data.args[0].tag = Iex_RdTmp
  data.args[0].con = 0x0
  data.args[0].tmp = 2
  data.args[0].offset = 0x0
  data.args[0].result_size = 32
  data.args[0].ty = Ity_Invalid
PUT(offset=32) = t4
  type = Ist_Put|Iex_RdTmp|Iop_Invalid
  tag = Ist_Put
  offset = 32
  tmp = 0
  data.tag = Iex_RdTmp
  data.con = 0x0
  data.tmp = 4
  data.offset = 0x0
  data.result_size = 64
  data.ty = Ity_Invalid
  data.addr.tag = Iex_Invalid
  data.op = Iop_Invalid
  data.nargs = 0
Boring
  type = Ist_Jump|Iex_Invalid|Iop_Invalid
  tag = Ist_Jump
  offset = 0
  tmp = 0
  jumpkind = Ijk_Boring
*/