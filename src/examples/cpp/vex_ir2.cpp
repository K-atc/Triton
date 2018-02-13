
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
  {0x400011, (unsigned char *)"\x48\x8D\x73\x0A",             4}, /* lea        rsi, [rbx+0xa]              */
  {0x400015, (unsigned char *)"\x89\xd0",                     2}, /* mov        eax, edx                    */
  {0x400017, (unsigned char *)"\x80\xf4\x99",                 3}, /* xor        ah, 0x99                    */
  {0x40001a, (unsigned char *)"\x48\x31\xc0",                 3}, /* xor        rax, rax                    */
  {0x40001d, (unsigned char *)"\x80\x30\x99",                 3}, /* xor        byte ptr [rax], 0x99        */
  {0x400020, (unsigned char *)"\x80\x30\x99",                 3}, /* xor        byte ptr [rax], 0x99        */
  {0x400023, (unsigned char *)"\x0F\x87\x00\x00\x00\x00",     6}, /* ja         11                          */
  {0x0,      nullptr,                                         0}
};


triton::uint8 opbytes[] =
  "\x48\x8b\x05\xb8\x13\x00\x00"  /* mov        rax, QWORD PTR [rip+0x13b8] */
  "\x48\x8d\x34\xc3"              /* lea        rsi, [rbx+rax*8]            */
  "\x67\x48\x8D\x74\xC3\x0A"      /* lea        rsi, [ebx+eax*8+0xa]        */
  "\x48\x8D\x73\x0A"              /* lea        rsi, [rbx+0xa]              */
  "\x89\xd0"                      /* mov        eax, edx                    */
  "\x80\xf4\x99"                  /* xor        ah, 0x99                    */
  "\x48\x31\xc0"                  /* xor        rax, rax                    */
  "\x80\x30\x99"                  /* xor        byte ptr [rax], 0x99        */
  "\x80\x30\x99"                  /* xor        byte ptr [rax], 0x99        */
  "\x0F\x87\x00\x00\x00\x00"      /* ja         11                          */
;

int main(int ac, const char **av) {

  /* Set the arch */
  api.setArchitecture(ARCH_VEX);

  triton::uint64 address = 0x400000;

  /* Disassemble bytes */
  api.disassembleBytes(opbytes, sizeof(opbytes), address);

  for (unsigned int i = 0; i < sizeof(trace); i++) {
    /* Build an instruction */
    Instruction baseInst;

    /* optional - Setup address */
    std::cout << "address = " << std::hex << address << std::endl;
    baseInst.setAddress(address);

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
    /* Next address */
    // std::cout << "baseInst.getSize() = " << baseInst.getSize() << std::endl;
    // address += baseInst.getSize();
    address += trace[i].size;
  }

  return 0;
}