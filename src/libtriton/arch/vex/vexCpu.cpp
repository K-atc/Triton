//! \file
/*
**  Copyright (C) - Triton
**
**  This program is under the terms of the BSD License.
*/

#include <cstring>

#include <triton/architecture.hpp>
#include <triton/coreUtils.hpp>
#include <triton/cpuSize.hpp>
#include <triton/exceptions.hpp>
#include <triton/externalLibs.hpp>
#include <triton/immediate.hpp>
#include <triton/vexCpu.hpp>
#include <triton/vexLifter.hpp>

#include <triton/logger.hpp>

namespace triton {
  namespace arch {
    namespace vex {

      vexCpu::vexCpu(triton::callbacks::Callbacks* callbacks) {
        this->callbacks = callbacks;
        this->clear();

        triton::intlibs::vexlifter::vex_lift_init();
      }


      vexCpu::vexCpu(const vexCpu& other) {
        this->copy(other);
      }


      vexCpu::~vexCpu() {
        this->memory.clear();

        triton::intlibs::vexlifter::vex_lift_finilize();
      }


      void vexCpu::copy(const vexCpu& other) {
        this->callbacks = other.callbacks;
        this->memory    = other.memory;


        std::memcpy(this->cc_regs,     other.cc_regs,    sizeof(this->cc_regs));
      }


      void vexCpu::init(void) {
        /* Define registers ========================================================= */
        triton::arch::vex::vex_reg_invalid = triton::arch::Register(triton::arch::vex::ID_REG_INVALID);
        triton::arch::vex::vex_regs    = triton::arch::Register(); // not used
        triton::arch::vex::vex_tmp     = triton::arch::Register(); // not used
        triton::arch::vex::vex_reg_pc  = triton::arch::Register(triton::arch::vex::translatePairIDToRegID(triton::arch::vex::ID_REG_RIP, this->registerBitSize())); // FIXME: use archinfo

        // for (int i = 0; i < 8 * 100) {
        //     triton::arch::vex::vex_regs[i] = triton::arch::Register(i, 0x00, triton::arch::IMMUTABLE_REGISTER);
        // }
      }


      void vexCpu::clear(void) {
        /* Clear memory */
        this->memory.clear();

        /* Clear registers */
        std::memset((void *) this->cc_regs, 0x00, sizeof(this->cc_regs));
        this->cc_tmp.clear(); // Clear content of tmp
      }


      void vexCpu::operator=(const vexCpu& other) {
        this->copy(other);
      }


      bool vexCpu::isFlag(triton::uint32 regId) const {
        // return ((regId >= triton::arch::vex::ID_REG_AF && regId <= triton::arch::vex::ID_REG_FZ) ? true : false);
        return false; // FIXME
      }


      bool vexCpu::isRegister(triton::uint32 regId) const {
        return (
          this->isGPR(regId)      ||
          this->isMMX(regId)      ||
          this->isSSE(regId)      ||
          this->isAVX256(regId)   ||
          this->isControl(regId)  ||
          this->isSegment(regId)
        );
      }


      bool vexCpu::isRegisterValid(triton::uint32 regId) const {
        // return (this->isFlag(regId) || this->isRegister(regId));
        if (ID_REG_INVALID < regId && regId < ID_REG_LAST_ITEM) {
          return true;
        }
        if (triton::arch::vex::translateRegIDToPairID(regId).second % BYTE_SIZE_BIT == 0) {
          return true;
        }
        return false;
      }


      bool vexCpu::isGPR(triton::uint32 regId) const {
        // return ((regId >= triton::arch::vex::ID_REG_EAX && regId <= triton::arch::vex::ID_REG_EFLAGS) ? true : false);
        return false; // TODO: archinfo
      }


      bool vexCpu::isMMX(triton::uint32 regId) const {
        // return ((regId >= triton::arch::vex::ID_REG_MM0 && regId <= triton::arch::vex::ID_REG_MM7) ? true : false);
        return false; // TODO: archinfo
      }


      bool vexCpu::isSSE(triton::uint32 regId) const {
        // return ((regId >= triton::arch::vex::ID_REG_MXCSR && regId <= triton::arch::vex::ID_REG_XMM7) ? true : false);
        return false; // TODO: archinfo
      }


      bool vexCpu::isAVX256(triton::uint32 regId) const {
        // return ((regId >= triton::arch::vex::ID_REG_YMM0 && regId <= triton::arch::vex::ID_REG_YMM7) ? true : false);
        return false; // TODO: archinfo
      }


      bool vexCpu::isControl(triton::uint32 regId) const {
        // return ((regId >= triton::arch::vex::ID_REG_CR0 && regId <= triton::arch::vex::ID_REG_CR15) ? true : false);
        return false; // TODO: archinfo
      }


      bool vexCpu::isSegment(triton::uint32 regId) const {
        // return ((regId >= triton::arch::vex::ID_REG_CS && regId <= triton::arch::vex::ID_REG_SS) ? true : false);
        return false; // TODO: archinfo
      }


      triton::uint32 vexCpu::numberOfRegisters(void) const {
        return triton::arch::vex::ID_REG_LAST_ITEM;
        // return 0x11000; // FIXME (used by SymbolicEngine::SymbolicEngine)
      }


      triton::uint32 vexCpu::registerSize(void) const {
        return QWORD_SIZE;
      }


      triton::uint32 vexCpu::registerBitSize(void) const {
        return QWORD_SIZE_BIT;
      }


      triton::arch::RegisterSpecification vexCpu::getRegisterSpecification(triton::uint32 regId) const {
        return this->getVexRegisterSpecification(triton::arch::ARCH_VEX, regId);
      }


      std::set<triton::arch::Register*> vexCpu::getAllRegisters(void) const {
        std::set<triton::arch::Register*> ret;
        ret.insert(&triton::arch::vex::vex_regs);
        return ret;
      }


      std::set<triton::arch::Register*> vexCpu::getParentRegisters(void) const {
        std::set<triton::arch::Register*> ret;

        throw triton::exceptions::Cpu("vexCpu::getParentRegisters(): Not Implemented.");
        #if 0
        for (triton::uint32 index = 0; index < triton::arch::vex::ID_REG_LAST_ITEM; index++) {
          /* Add GPR */
          if (triton::arch::vex::vex_regs[index]->getSize() == this->registerSize())
            ret.insert(triton::arch::vex::vex_regs[index]);

          /* Add Flags */
          else if (this->isFlag(triton::arch::vex::vex_regs[index]->getId()))
            ret.insert(triton::arch::vex::vex_regs[index]);

          /* Add MMX */
          else if (this->isMMX(triton::arch::vex::vex_regs[index]->getId()))
            ret.insert(triton::arch::vex::vex_regs[index]);

          /* Add SSE */
          else if (this->isSSE(triton::arch::vex::vex_regs[index]->getId()))
            ret.insert(triton::arch::vex::vex_regs[index]);

          /* Add AVX-256 */
          else if (this->isAVX256(triton::arch::vex::vex_regs[index]->getId()))
            ret.insert(triton::arch::vex::vex_regs[index]);

          /* Add Control */
          else if (this->isControl(triton::arch::vex::vex_regs[index]->getId()))
            ret.insert(triton::arch::vex::vex_regs[index]);
        }
        #endif

        return ret;
      }

      triton::uint32 vexCpu::translateVexTyToSize(triton::intlibs::vexlifter::vex_ir_ity ty) {
        switch (ty) {
            case triton::intlibs::vexlifter::Ity_Invalid: return 0;
            case triton::intlibs::vexlifter::Ity_F32: return 32;
            case triton::intlibs::vexlifter::Ity_F64: return 64;
            case triton::intlibs::vexlifter::Ity_I1: return 1;
            case triton::intlibs::vexlifter::Ity_I16: return 16;
            case triton::intlibs::vexlifter::Ity_I32: return 32;
            case triton::intlibs::vexlifter::Ity_I64: return 64;
            case triton::intlibs::vexlifter::Ity_I8: return 8;
            case triton::intlibs::vexlifter::Ity_V128: return 128;
            case triton::intlibs::vexlifter::Ity_V256: return 256;
        }
        return 0;
      }

      triton::uint32 vexCpu::translateIexToRegId(triton::intlibs::vexlifter::vex_expr expr) {
        switch (expr.tag) {
          case triton::intlibs::vexlifter::Iex_RdTmp:
            return triton::arch::vex::translateTmpToRegID(expr.tmp, expr.result_size);
            break;
          case triton::intlibs::vexlifter::Iex_Get: {
            return translatePairIDToRegID(
                std::make_pair(expr.offset, translateVexTyToSize(expr.ty))
              );
            break;
          }
          default:
            puts("=== [errored] ===");
            triton::intlibs::vexlifter::print_vex_expr(expr, (char *) "expr.");
            puts("=================");
            triton::logger::warn("Unhandled %s", triton::intlibs::vexlifter::vex_tag_enum_to_str(expr.tag).c_str());
            break;
        }
        return 0;
      }

      triton::arch::OperandWrapper vexCpu::generateOperandWrapperFromExpr(
        triton::intlibs::vexlifter::vex_expr expr, triton::arch::Instruction &inst
        ) {
        switch (expr.tag) {
          case triton::intlibs::vexlifter::Iex_Get: {
            // std::cout << "case Ist_Get (" <<
            //   triton::intlibs::vexlifter::vex_tag_enum_to_str(expr.ty) << "): "<< std::endl;
            // std::cout <<                 inst.getRegisterState(
            //       translatePairIDToRegID(
            //         std::make_pair(expr.offset, translateVexTyToSize(expr.ty))
            //       )
            //     ) << std::endl;
            // std::cout <<                   triton::arch::Register(translatePairIDToRegID(
            //         std::make_pair(expr.offset, translateVexTyToSize(expr.ty))
            //       )) << std::endl;
            return
              triton::arch::OperandWrapper(
                inst.getRegisterState(
                  translatePairIDToRegID(
                    std::make_pair(expr.offset, translateVexTyToSize(expr.ty))
                  )
                )
              );
          } // case Iex_Get
          case triton::intlibs::vexlifter::Iex_Const: {
            return
              triton::arch::OperandWrapper(
                triton::arch::Immediate(expr.con, expr.result_size / BYTE_SIZE_BIT)
              )
            ;
          } // case iex_Const
          case triton::intlibs::vexlifter::Iex_RdTmp: {
            return
              triton::arch::OperandWrapper(
                inst.getRegisterState(
                  triton::arch::vex::translateTmpToRegID(expr.tmp, expr.result_size)
                )
              )
            ;
          } // case Iex_RdTmp
          default: {
            triton::logger::warn("vexCpu::generateOperandWrapperFromExpr: Unhandled tag = %s", triton::intlibs::vexlifter::vex_tag_enum_to_str(expr.tag).c_str());
          }
        }
        return triton::arch::OperandWrapper(TRITON_VEX_REG_INVALID);
      }

      triton::arch::OperandWrapper vexCpu::generateOperandWrapperFromData(
        triton::intlibs::vexlifter::vex_data data, triton::arch::Instruction &inst
        ) {
        switch (data.tag) {
          case triton::intlibs::vexlifter::Iex_Load: {
            switch (data.addr.tag) {
              case triton::intlibs::vexlifter::Iex_Invalid: {
                triton::logger::warn("vexCpu::generateOperandWrapperFromExpr: Handled tag = Iex_Invalid");
                break;
              }
              case triton::intlibs::vexlifter::Iex_Const: {
                // TODO: endness
                triton::logger::info("vexCpu::generateOperandWrapperFromExpr: case Iex_Load > Iex_Const");
                return triton::arch::OperandWrapper(triton::arch::Immediate(data.addr.con, data.result_size / BYTE_SIZE_BIT));
              }
              case triton::intlibs::vexlifter::Iex_RdTmp: {
                triton::logger::info("vexCpu::generateOperandWrapperFromExpr: case Iex_Load > Iex_RdTmp");
                triton::arch::MemoryAccess mem;

                /* Set the size of the memory access */
                mem.setPair(std::make_pair(((data.result_size) - 1), 0));

                /* LEA if exists */
                triton::arch::Register base(triton::arch::vex::translateTmpToRegID(data.addr.tmp, data.addr.result_size));
                triton::arch::Register index(ID_REG_INVALID); // must be invalid, or a bug occurs in SymbolicEngine::initLeaAst
                triton::arch::Register seg(ID_REG_INVALID); // must be invalid, or ...

                /* Specify that LEA contains a PC relative */
                if (base.getId() == TRITON_VEX_REG_PC.getId())
                  mem.setPcRelative(inst.getNextAddress());

                mem.setBaseRegister(base);
                mem.setIndexRegister(index);
                mem.setSegmentRegister(seg);

                // TODO: endness

                return triton::arch::OperandWrapper(mem);
              }
              default: {
                triton::logger::warn("vexCpu::generateOperandWrapperFromExpr: Unhandled tag = %s", triton::intlibs::vexlifter::vex_tag_enum_to_str(data.addr.tag).c_str());
              }
              break;
            }
          } // case Iex_Load
          default: {
            return generateOperandWrapperFromExpr(static_cast<triton::intlibs::vexlifter::vex_expr> (data), inst);
          }
        }
        return triton::arch::OperandWrapper(TRITON_VEX_REG_INVALID);
      }

      void vexCpu::disassembly(triton::arch::Instruction& baseInst) {
        triton::uint64 address = baseInst.getAddress();
        triton::intlibs::vexlifter::vex_insns vex_insns;
        triton::intlibs::vexlifter::vex_insns_group res;
        if (lifted_vex_insns.find(address) == lifted_vex_insns.end()) { // not lifted
          if (baseInst.getOpcodes() != nullptr && baseInst.getSize() > 0) {
            /* Lift native inst to VexIR */
            vex_lift(&res, (unsigned char*) baseInst.getOpcodes(), baseInst.getAddress(), baseInst.getSize());
            if (res.find(address) == res.end())
              throw triton::exceptions::Disassembly("vexCpu::disassembly(): failed to lift");
            print_vex_insns_group(res);
            vex_insns = res[address];
          }
          else {
            char msg[128];
            snprintf(msg, sizeof(msg), "vexCpu::disassembly(): VexIR at address 0x%lx not found.", address);
            throw triton::exceptions::Disassembly(msg);
          }
        }
        else { // already lifted
          vex_insns = lifted_vex_insns[address];

          // Set Opecodes (Not works)
          // baseInst.setOpcodes((triton::uint8*) vex_insns[0].asmbytes.c_str(), vex_insns[0].asmbytes.length()); // Ist_IMark
        }

        baseInst.setDisassembly(vex_insns[0].disasm);

        std::vector<triton::arch::Instruction> insts;
        for (auto &vex_insn : vex_insns) {

          triton::arch::Instruction inst;

          if (!vex_insn.full.empty()) {
            inst.setDisassembly(vex_insn.full);
          }

          /* Refine the size according with native instruction bytes size */
          inst.setSize(vex_insns[0].len);

          /* Init the instruction's type */
          if (vex_insn.data.cee == "amd64g_calculate_condition") {
            inst.setType(ID_AMD64G_CALCUATE_CONDITION);
          }
          else {
            inst.setType(
              triton::intlibs::vexlifter::vex_itype(
                vex_insn.tag,
                vex_insn.data.tag,
                triton::intlibs::vexlifter::vex_iop(vex_insn.data.op)
              )
            );
          }

          /* Set Instruction Address */
          inst.setAddress(address);

#if 0
          triton::logger::info("Pending: addr=0x%x, type=%s(0x%x): %s",
            address, triton::intlibs::vexlifter::vex_repr_itype(inst.getType()).c_str(), inst.getType(), vex_insn.full.c_str());
#endif

          // TODO: Set Context (writtenRegisters etc.)

          /* Check lift error */
          if (vex_insn.tag == triton::intlibs::vexlifter::Ist_Invalid) {
            puts("=== [errored] ===");
            triton::intlibs::vexlifter::print_vex_insn(vex_insn);
            puts("=================");
            throw triton::exceptions::Disassembly("vexCpu::disassembly(): Ist_Invalid.");
          }

          /* Init operands */
          // push dst registers (and etcetera)
          switch (vex_insn.tag) {
            case triton::intlibs::vexlifter::Ist_Put: {
              inst.operands.push_back(
                triton::arch::OperandWrapper(
                  inst.getRegisterState(
                    translatePairIDToRegID(
                      std::make_pair(vex_insn.offset, vex_insn.data.result_size)
                    )
                  )
                )
              );
              break;
            } // case Ist_Put
            case triton::intlibs::vexlifter::Ist_Store: {
              triton::arch::MemoryAccess mem;

              /* Set the size of the memory access */
              mem.setPair(std::make_pair(((vex_insn.data.result_size) - 1), 0));

              /* LEA if exists */
              triton::arch::Register base(triton::arch::vex::translateTmpToRegID(vex_insn.addr_expr.tmp, vex_insn.data.result_size));

              /* Specify that LEA contains a PC relative */
              if (base.getId() == TRITON_VEX_REG_PC.getId())
                mem.setPcRelative(inst.getNextAddress());

              mem.setBaseRegister(base);

              // TODO: endness

              inst.operands.push_back(triton::arch::OperandWrapper(mem));
              break;
            } // case Ist_Store
            case triton::intlibs::vexlifter::Ist_WrTmp: {
              auto reg = triton::arch::Register(
                inst.getRegisterState(triton::arch::vex::translateTmpToRegID(vex_insn.tmp, vex_insn.data.result_size))
              );
              // std::cout << "case Ist_WrTmp: dst: " << reg << std::endl;
              inst.operands.push_back(triton::arch::OperandWrapper(reg));
              break;
            } // case Ist_WrTmp
            case triton::intlibs::vexlifter::Ist_Exit: {
              // push guard
              inst.operands.push_back(
                triton::arch::OperandWrapper(inst.getRegisterState(translateIexToRegId(vex_insn.guard)))
              );
              // push dst register (jump target)
              inst.operands.push_back(
                triton::arch::OperandWrapper(
                  inst.getRegisterState(
                    translatePairIDToRegID(
                      std::make_pair(vex_insn.offsIP, vex_insn.dst.size)
                    )
                  )
                )
              );
              // push src const
              inst.operands.push_back(
                triton::arch::OperandWrapper(
                  triton::arch::Immediate(vex_insn.dst.value, vex_insn.dst.size / BYTE_SIZE_BIT)
                )
              );
              break;
            } // case Ist_Exit
            default:
              break;
          }

          // push src operands described in data
          if (vex_insn.data.tag != triton::intlibs::vexlifter::Iex_Invalid &&
              vex_insn.data.tag != triton::intlibs::vexlifter::Iex_Unop &&
              vex_insn.data.tag != triton::intlibs::vexlifter::Iex_Binop &&
              vex_insn.data.tag != triton::intlibs::vexlifter::Iex_Triop &&
              vex_insn.data.tag != triton::intlibs::vexlifter::Iex_CCall
            ) {
            inst.operands.push_back(
              generateOperandWrapperFromData(vex_insn.data, inst)
            );
          }

          // push src operands described in args
          // data.tag is Iex_Unop, Iex_Binop, Iex_Triop
          for (triton::uint32 n = 0; n < (triton::uint32) vex_insn.data.nargs; n++) {
            inst.operands.push_back(generateOperandWrapperFromExpr(vex_insn.data.args[n], inst));
          } // for ( args )

          // /* for debugging */
          // for (unsigned int op_index = 0; op_index != inst.operands.size(); op_index++) {
          //   std::cout << "\tOperand " << op_index << ": " << inst.operands[op_index] << std::endl;
          //   if (inst.operands[op_index].getType() == OP_MEM) {
          //     std::cout << "\t   base  : " << inst.operands[op_index].getMemory().getBaseRegister() << std::endl;
          //   }
          // }

          /* Set branch */
          if (vex_insn.tag == triton::intlibs::vexlifter::Ist_Jump)
            inst.setBranch(true);
          if (vex_insn.tag == triton::intlibs::vexlifter::Ist_Jump)
            if(vex_insn.jumpkind == triton::intlibs::vexlifter::Ijk_Boring ||
              vex_insn.jumpkind == triton::intlibs::vexlifter::Ijk_Call ||
              vex_insn.jumpkind == triton::intlibs::vexlifter::Ijk_Ret)
            inst.setControlFlow(true);

          // triton::logger::info("Done: addr=0x%x, type=0x%x: %s", inst.getAddress(), inst.getType(), vex_insn.full.c_str());
          insts.push_back(inst);
        } // for ( insn )

        baseInst.ir = insts;
        return;
      }

      void vexCpu::disassembleBytes(triton::uint8 *insnBytes, triton::uint32 insnBytesSize, triton::uint64 address) {
        /* Check if the insnBytes and insnBytes' size are defined */
        if (insnBytes == nullptr || insnBytes[0] == 0)
          throw triton::exceptions::Disassembly("vexCpu::disassembly(): Opcodes and insnBytesSize must be definied.");

        /* Lift native inst to VexIR */
        triton::intlibs::vexlifter::vex_insns_group res;
        vex_lift(&res, insnBytes, address, insnBytesSize);

        /* For debugging */
        print_vex_insns_group(res);

        /* Update CPU-side VexIRs */
        for ( auto &itr : res) {
          lifted_vex_insns[itr.first] = itr.second;
        }

        return;
      }


      triton::uint8 vexCpu::getConcreteMemoryValue(triton::uint64 addr) const {
        if (this->memory.find(addr) == this->memory.end())
          return 0x00;
        return this->memory.at(addr);
      }


      triton::uint512 vexCpu::getConcreteMemoryValue(const triton::arch::MemoryAccess& mem, bool execCallbacks) const {
        triton::uint512 ret = 0;
        triton::uint64 addr = mem.getAddress();
        triton::uint32 size = mem.getSize();

        if (size == 0 || size > DQQWORD_SIZE)
          throw triton::exceptions::Cpu("vexCpu::getConcreteMemoryValue(): Invalid size memory.");

        if (execCallbacks && this->callbacks)
          this->callbacks->processCallbacks(triton::callbacks::GET_CONCRETE_MEMORY_VALUE, mem);

        for (triton::sint32 i = size-1; i >= 0; i--)
          ret = ((ret << BYTE_SIZE_BIT) | this->getConcreteMemoryValue(addr+i));

        return ret;
      }


      std::vector<triton::uint8> vexCpu::getConcreteMemoryAreaValue(triton::uint64 baseAddr, triton::usize size, bool execCallbacks) const {
        std::vector<triton::uint8> area;

        for (triton::usize index = 0; index < size; index++) {
          if (execCallbacks && this->callbacks)
            this->callbacks->processCallbacks(triton::callbacks::GET_CONCRETE_MEMORY_VALUE, MemoryAccess(baseAddr+index, BYTE_SIZE));
          area.push_back(this->getConcreteMemoryValue(baseAddr+index));
        }

        return area;
      }


      triton::uint512 vexCpu::getConcreteRegisterValue(const triton::arch::Register& reg, bool execCallbacks) const {
        triton::uint512 value = 0;

        if (execCallbacks && this->callbacks)
          this->callbacks->processCallbacks(triton::callbacks::GET_CONCRETE_REGISTER_VALUE, reg);

        triton::uint32 regId = reg.getId();
        triton::uint32 offset = translateRegIDToPairID(regId).first;
        // triton::logger::info("vexCpu::getConcreteRegisterValue(): offset = %u, reg.getBitSize() = %d", offset, reg.getBitSize());
        // std::cout << "\treg: " << reg << std::endl;
        assert(reg.getBitSize() % BYTE_SIZE_BIT == 0);
        switch (reg.getBitSize()) {
          case 8:   return this->cc_regs[offset];
          case 16:  return triton::utils::fromBufferToUint<triton::uint16>(&(this->cc_regs[offset]));
          case 32:  return triton::utils::fromBufferToUint<triton::uint32>(&(this->cc_regs[offset]));
          case 64:  return triton::utils::fromBufferToUint<triton::uint64>(&(this->cc_regs[offset]));
          case 128: return triton::utils::fromBufferToUint<triton::uint128>(&(this->cc_regs[offset]));
          case 256: return triton::utils::fromBufferToUint<triton::uint256>(&(this->cc_regs[offset]));
          case 512: return triton::utils::fromBufferToUint<triton::uint512>(&(this->cc_regs[offset]));
          default:  return value;
        }
      }


      void vexCpu::setConcreteMemoryValue(triton::uint64 addr, triton::uint8 value) {
        this->memory[addr] = value;
      }


      void vexCpu::setConcreteMemoryValue(const triton::arch::MemoryAccess& mem) {
        triton::uint64 addr = mem.getAddress();
        triton::uint32 size = mem.getSize();
        triton::uint512 cv  = mem.getConcreteValue();

        if (size == 0 || size > DQQWORD_SIZE)
          throw triton::exceptions::Cpu("vexCpu::setConcreteMemoryValue(): Invalid size memory.");

        for (triton::uint32 i = 0; i < size; i++) {
          this->memory[addr+i] = (cv & 0xff).convert_to<triton::uint8>();
          cv >>= 8;
        }
      }


      void vexCpu::setConcreteMemoryAreaValue(triton::uint64 baseAddr, const std::vector<triton::uint8>& values) {
        for (triton::usize index = 0; index < values.size(); index++) {
          this->memory[baseAddr+index] = values[index];
        }
      }


      void vexCpu::setConcreteMemoryAreaValue(triton::uint64 baseAddr, const triton::uint8* area, triton::usize size) {
        for (triton::usize index = 0; index < size; index++) {
          this->memory[baseAddr+index] = area[index];
        }
      }


      void vexCpu::setConcreteRegisterValue(const triton::arch::Register& reg) {
        triton::uint512 value = reg.getConcreteValue();

        triton::uint32 offset = translateRegIDToPairID(reg.getId()).first;
        // triton::logger::info("vexCpu::setConcreteRegisterValue: offset = %d, reg.getSize() = %d", offset, reg.getSize());
        // std::cout << "\tvalue = " << value << std::endl;
        switch (reg.getSize()) {
          case BYTE_SIZE:     this->cc_regs[offset]  = value.convert_to<triton::uint8>(); break;
          case WORD_SIZE:     triton::utils::fromUintToBuffer(value.convert_to<triton::uint16>(), &(this->cc_regs[offset])); break;
          case DWORD_SIZE:    triton::utils::fromUintToBuffer(value.convert_to<triton::uint32>(), &(this->cc_regs[offset])); break;
          case QWORD_SIZE:    triton::utils::fromUintToBuffer(value.convert_to<triton::uint64>(), &(this->cc_regs[offset])); break;
          case DQWORD_SIZE:   triton::utils::fromUintToBuffer(value.convert_to<triton::uint128>(), &(this->cc_regs[offset])); break;
          case QQWORD_SIZE:   triton::utils::fromUintToBuffer(value.convert_to<triton::uint256>(), &(this->cc_regs[offset])); break;
          case DQQWORD_SIZE:  triton::utils::fromUintToBuffer(value.convert_to<triton::uint512>(), &(this->cc_regs[offset])); break;
          default:
            throw triton::exceptions::Cpu("vexCpu:setConcreteRegisterValue(): Invalid register size.");
        }

        // std::cout << "\tresult: " << getConcreteRegisterValue(reg, false) << std::endl;
      }


      bool vexCpu::isMemoryMapped(triton::uint64 baseAddr, triton::usize size) {
        for (triton::usize index = 0; index < size; index++) {
          if (this->memory.find(baseAddr + index) == this->memory.end())
            return false;
        }
        return true;
      }


      void vexCpu::unmapMemory(triton::uint64 baseAddr, triton::usize size) {
        for (triton::usize index = 0; index < size; index++) {
          if (this->memory.find(baseAddr + index) != this->memory.end())
            this->memory.erase(baseAddr + index);
        }
      }



    }; /* vex namespace */
  }; /* arch namespace */
}; /* triton namespace */

