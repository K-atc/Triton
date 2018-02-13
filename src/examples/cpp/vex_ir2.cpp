
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
/*
  4000a5: 55                    push   rbp
  4000a6: 48 89 e5              mov    rbp,rsp
  4000a9: 48 8b 44 24 18        mov    rax,QWORD PTR [rsp+0x18]
  4000ae: 48 85 c0              test   rax,rax
  4000b1: 74 34                 je     4000e7 <fail>
  4000b3: 81 38 66 6c 61 67     cmp    DWORD PTR [rax],0x67616c66
  4000b9: 75 2c                 jne    4000e7 <fail>
  4000bb: 81 78 04 7b 69 74 27  cmp    DWORD PTR [rax+0x4],0x2774697b
  4000c2: 75 23                 jne    4000e7 <fail>
  4000c4: 81 78 08 73 5f 65 61  cmp    DWORD PTR [rax+0x8],0x61655f73
  4000cb: 75 1a                 jne    4000e7 <fail>
  4000cd: 81 78 0c 73 79 21 7d  cmp    DWORD PTR [rax+0xc],0x7d217973
  4000d4: 75 11                 jne    4000e7 <fail>
*/

struct op trace[] = {
  {0x4000a5, (unsigned char *)"\x55",                         1}, /* push   rbp */
  {0x4000a6, (unsigned char *)"\x48\x89\xe5",                 3}, /* mov    rbp,rsp */
  {0x4000a9, (unsigned char *)"\x48\x8b\x44\x24\x18",         5}, /* mov    rax,QWORD PTR [rsp+0x18] */
  {0x4000ae, (unsigned char *)"\x48\x85\xc0",                 3}, /* test   rax,rax */
  {0x4000b1, (unsigned char *)"\x74\x34",                     2}, /* je     4000e7 <fail> */
  {0x4000b3, (unsigned char *)"\x81\x38\x66\x6c\x61\x67",     6}, /* cmp    DWORD PTR [rax],0x67616c66 */
  {0x4000b9, (unsigned char *)"\x75\x2c",                     2}, /* jne    4000e7 <fail> */
  {0x4000bb, (unsigned char *)"\x81\x78\x04\x7b\x69\x74\x27", 7}, /* cmp    DWORD PTR [rax+0x4],0x2774697b */
  {0x4000c2, (unsigned char *)"\x75\x23",                     2}, /* jne    4000e7 <fail> */
  {0x4000c4, (unsigned char *)"\x81\x78\x08\x73\x5f\x65\x61", 7}, /* cmp    DWORD PTR [rax+0x8],0x61655f73 */
  {0x4000cb, (unsigned char *)"\x75\x1a",                     2}, /* jne    4000e7 <fail> */
  {0x4000cd, (unsigned char *)"\x81\x78\x0c\x73\x79\x21\x7d", 7}, /* cmp    DWORD PTR [rax+0xc],0x7d217973 */
  {0x4000d4, (unsigned char *)"\x75\x11",                     2}, /* jne    4000e7 <fail> */
  {0x0,      nullptr,                                         0}
};

int main(int ac, const char **av) {

  /* Set the arch */
  api.setArchitecture(ARCH_VEX);

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
0000000000400080 <str_correct>:
  400080: 63 6f 72              movsxd ebp,DWORD PTR [rdi+0x72]
  400083: 72 65                 jb     4000ea <fail+0x3>
  400085: 63                    .byte 0x63
  400086: 74 0a                 je     400092 <print+0x2>

0000000000400088 <str_wrong>:
  400088: 77 72                 ja     4000fc <exit+0x6>
  40008a: 6f                    outs   dx,DWORD PTR ds:[rsi]
  40008b: 6e                    outs   dx,BYTE PTR ds:[rsi]
  40008c: 67 3b 28              cmp    ebp,DWORD PTR [eax]
  40008f: 0a                    .byte 0xa

0000000000400090 <print>:
  400090: b8 01 00 00 00        mov    eax,0x1
  400095: bf 01 00 00 00        mov    edi,0x1
  40009a: 48 89 ce              mov    rsi,rcx
  40009d: ba 08 00 00 00        mov    edx,0x8
  4000a2: 0f 05                 syscall 
  4000a4: c3                    ret    

00000000004000a5 <_start>:
  4000a5: 55                    push   rbp
  4000a6: 48 89 e5              mov    rbp,rsp
  4000a9: 48 8b 44 24 18        mov    rax,QWORD PTR [rsp+0x18]
  4000ae: 48 85 c0              test   rax,rax
  4000b1: 74 34                 je     4000e7 <fail>
  4000b3: 81 38 66 6c 61 67     cmp    DWORD PTR [rax],0x67616c66
  4000b9: 75 2c                 jne    4000e7 <fail>
  4000bb: 81 78 04 7b 69 74 27  cmp    DWORD PTR [rax+0x4],0x2774697b
  4000c2: 75 23                 jne    4000e7 <fail>
  4000c4: 81 78 08 73 5f 65 61  cmp    DWORD PTR [rax+0x8],0x61655f73
  4000cb: 75 1a                 jne    4000e7 <fail>
  4000cd: 81 78 0c 73 79 21 7d  cmp    DWORD PTR [rax+0xc],0x7d217973
  4000d4: 75 11                 jne    4000e7 <fail>

00000000004000d6 <clear>:
  4000d6: 48 b9 80 00 40 00 00  movabs rcx,0x400080
  4000dd: 00 00 00 
  4000e0: e8 ab ff ff ff        call   400090 <print>
  4000e5: eb 0f                 jmp    4000f6 <exit>

00000000004000e7 <fail>:
  4000e7: 48 b9 88 00 40 00 00  movabs rcx,0x400088
  4000ee: 00 00 00 
  4000f1: e8 9a ff ff ff        call   400090 <print>

00000000004000f6 <exit>:
  4000f6: b8 3c 00 00 00        mov    eax,0x3c
  4000fb: bf 00 00 00 00        mov    edi,0x0
  400100: 0f 05                 syscall 
*/