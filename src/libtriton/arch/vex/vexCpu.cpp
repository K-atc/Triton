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
      }


      vexCpu::vexCpu(const vexCpu& other) {
        this->copy(other);
      }


      vexCpu::~vexCpu() {
        this->memory.clear();
      }


      void vexCpu::copy(const vexCpu& other) {
        this->callbacks = other.callbacks;
        this->memory    = other.memory;


        std::memcpy(this->cc_regs,     other.cc_regs,    sizeof(this->cc_regs));
      }


      void vexCpu::init(void) {
        /* Define registers ========================================================= */
        triton::arch::vex::vex_regs    = triton::arch::Register();
        triton::arch::vex::vex_tmp     = triton::arch::Register();
        // for (int i = 0; i < 8 * 100) {
        //     triton::arch::vex::vex_regs[i] = triton::arch::Register(i, 0x00, triton::arch::IMMUTABLE_REGISTER);
        // }
      }


      void vexCpu::clear(void) {
        /* Clear memory */
        this->memory.clear();

        /* Clear registers */
        for (triton::uint32 i = 0; i < sizeof(this->cc_regs) / sizeof(this->cc_regs[0]); i++){
          std::memset((void *)&(this->cc_regs[i]), 0x00, sizeof(this->cc_regs[0]));
        }
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
        return (this->isFlag(regId) || this->isRegister(regId));
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
      }


      triton::uint32 vexCpu::registerSize(void) const {
        return DWORD_SIZE;
      }


      triton::uint32 vexCpu::registerBitSize(void) const {
        return DWORD_SIZE_BIT;
      }


      triton::arch::RegisterSpecification vexCpu::getRegisterSpecification(triton::uint32 regId) const {
        return this->getVexRegisterSpecification(triton::arch::ARCH_Vex, regId);
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

      void vexCpu::disassembly(triton::arch::Instruction& inst) const {
        throw triton::exceptions::Disassembly("vexCpu::disassembly: Not Implemented.");
      }

      triton::uint32 vexCpu::translateIexToRegId(triton::intlibs::vexLifter::vex_expr expr) const {
        switch (expr.tag) { 
          case triton::intlibs::vexLifter::Iex_RdTmp:
            return translateTmpToRegID(vex_insn.guard.tmp);
            break;
          case triton::intlibs::vexLifter::Iex_Get:
            return translatePairIDToRegID(
                std::make_pair(vex_insn.data.offset, translateVexTyToSize(vex_insn.data.ty))
              );
            break;
          // TODO: memory
          default:
            triton::logger::warn("Unhandled guard.tag = %s", n, triton::intlibs::vexlifter::vex_tag_enum_to_str(expr_arg.tag));
            break;                
        }
        return 0;
      }

      void vexCpu::disassembly2(std::vector<triton::arch::Instruction>& insts, triton::uint64 address) {
            if (lifted_vex_insns.find(address) == lifted_vex_insns.end()) {
              char msg[128];
              snprintf(msg, sizeof(msg), "vexCpu::disassembly(): VexIR at address 0x%lx not found.", address);
              throw triton::exceptions::Disassembly(msg);
            }

            for (auto &vex_insn : lifted_vex_insns[address]) {

              triton::arch::Instruction inst;

              if (!vex_insn.disasm.empty()) {
                inst.setDisassembly(vex_insn.disasm);
              }

              /* Refine the size */
              if (vex_insn.tag != triton::intlibs::vexlifter::Ist_IMark) {
                inst.setSize(vex_insn.len);
              }

              /* Init the instruction's type */
              inst.setType(vex_insn.tag);

              /* Init the instruction's prefix */
              // inst.setPrefix(this->capstonePrefixToTritonPrefix(detail->vex.prefix[0]));

              inst.setAddress(address);

              /* Init operands */
              switch (vex_insn.data.tag) { // dst registers
                case triton::intlibs::vexlifter::Ist_Put: {
                  inst.operands.push_back(
                    triton::arch::OperandWrapper(
                      inst.getRegisterState(
                        translatePairIDToRegID(
                          std::make_pair(vex_insn.data.offset, translateVexTyToSize(vex_insn.data.ty))
                        )
                      )
                    )
                  );    
                  break;
                }
                case triton::intlibs::vexlifter::Ist_Store: {
                  // push dst 
                  inst.operands.push_back(
                    triton::arch::OperandWrapper(inst.getRegisterState(translateIexToRegId(insn.addr)))
                  );
                }
#if 0
#endif
                case triton::intlibs::vexlifter::Ist_Exit: {
                  // push dst resiter (jump target)
                  inst.operands.push_back(
                    triton::arch::OperandWrapper(
                      inst.getRegisterState(
                        translatePairIDToRegID(
                          std::make_pair(vex_insn.offsIP, vex_insn.result_size)
                        )
                      )
                    )
                  ); 
                  // push guard
                  inst.operands.push_back(
                    triton::arch::OperandWrapper(inst.getRegisterState(translateIexToRegId(insn.guard)))
                  );
                } // case Ist_Exit
              }
              switch (vex_insn.data.tag) { // src registers
                case triton::intlibs::vexlifter::Iex_Get:
                  inst.operands.push_back(
                    triton::arch::OperandWrapper(
                      inst.getRegisterState(
                        translatePairIDToRegID(
                          std::make_pair(vex_insn.data.offset, translateVexTyToSize(vex_insn.data.ty))
                        )
                      )
                    )
                  );
                  break;
                default:
                  break; // Do Nothing
              }
              for (triton::uint32 n = 0; n < (triton::uint32) vex_insn.data.nargs; n++) { // expr operands
                triton::intlibs::vexlifter::vex_expr expr_arg = vex_insn.data.args[n];
                switch (expr_arg.tag) {
                  case triton::intlibs::vexlifter::Iex_RdTmp: {
                    inst.operands.push_back(
                      triton::arch::OperandWrapper(
                        inst.getRegisterState(translateTmpToRegID(expr_arg.tmp))
                      )
                    );
                    break;
                  }
                  case triton::intlibs::vexlifter::Iex_Const: {
                    inst.operands.push_back(triton::arch::OperandWrapper(triton::arch::Immediate(expr_arg.con, expr_arg.result_size)));
                    break;
                  }
                  case triton::intlibs::vexlifter::Iex_Load: {
                    triton::arch::MemoryAccess mem;

                    /* Set the size of the memory access */
                    mem.setPair(std::make_pair(((expr_arg.result_size * BYTE_SIZE_BIT) - 1), 0));

                    mem.setAddress(expr_arg.con); // Really?

                    inst.operands.push_back(triton::arch::OperandWrapper(mem));
                    break;
                  }
                  default: {
                    triton::logger::warn("Unhandled arg[%d].tag = %s", n, triton::intlibs::vexlifter::vex_tag_enum_to_str(expr_arg.tag));
                    break;
                  }
                } // switch
              } // for ( args )
              insts.push_back(inst);

              /* Set branch */
              if (vex_insn.tag == triton::intlibs::vexlifter::Ist_Jump)
                inst.setBranch(true);
              if (vex_insn.tag == triton::intlibs::vexlifter::Ist_Jump)
                if(vex_insn.jumpkind == triton::intlibs::vexlifter::Ijk_Boring ||
                  vex_insn.jumpkind == triton::intlibs::vexlifter::Ijk_Call ||
                  vex_insn.jumpkind == triton::intlibs::vexlifter::Ijk_Ret)
                inst.setControlFlow(true);
            } // for ( insn )
        
        return;        
      }

      void vexCpu::disassemble_block(triton::uint8 *opcodes, triton::uint32 opcodesSize, triton::uint32 address) {
        /* Check if the opcodes and opcodes' size are defined */
        if (opcodes == nullptr || opcodes[0] == 0)
          throw triton::exceptions::Disassembly("vexCpu::disassembly(): Opcodes and opcodesSize must be definied.");

        /* Lift native inst to VexIR */
        triton::intlibs::vexlifter::vex_insns_group res; 
        vex_lift(&res, opcodes, address, opcodesSize);

        // Update CPU-side VexIRs
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

        triton::uint32 reg_id = reg.getId();
        switch (reg.getSize()) {
          case 8:   return this->cc_regs[reg_id];
          case 16:  return triton::utils::fromBufferToUint<triton::uint16>(&(this->cc_regs[reg_id]));
          case 32:  return triton::utils::fromBufferToUint<triton::uint32>(&(this->cc_regs[reg_id]));
          case 64:  return triton::utils::fromBufferToUint<triton::uint64>(&(this->cc_regs[reg_id]));
          case 128: return triton::utils::fromBufferToUint<triton::uint128>(&(this->cc_regs[reg_id]));
          case 256: return triton::utils::fromBufferToUint<triton::uint256>(&(this->cc_regs[reg_id]));
          case 512: return triton::utils::fromBufferToUint<triton::uint512>(&(this->cc_regs[reg_id]));
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

        triton::uint32 reg_id = reg.getId();
        switch (reg.getSize()) {
          case 8:   this->cc_regs[reg_id]  = value.convert_to<triton::uint8>(); break;
          case 16:  triton::utils::fromUintToBuffer(value.convert_to<triton::uint16>(), &(this->cc_regs[reg_id])); break;
          case 32:  triton::utils::fromUintToBuffer(value.convert_to<triton::uint32>(), &(this->cc_regs[reg_id])); break;
          case 64:  triton::utils::fromUintToBuffer(value.convert_to<triton::uint64>(), &(this->cc_regs[reg_id])); break;
          case 128: triton::utils::fromUintToBuffer(value.convert_to<triton::uint128>(), &(this->cc_regs[reg_id])); break;
          case 256: triton::utils::fromUintToBuffer(value.convert_to<triton::uint256>(), &(this->cc_regs[reg_id])); break;
          case 512: triton::utils::fromUintToBuffer(value.convert_to<triton::uint512>(), &(this->cc_regs[reg_id])); break;
          default:
            throw triton::exceptions::Cpu("vexCpu:setConcreteRegisterValue() - Invalid register size.");
        }
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

      triton::uint32 vexCpu::translateVexTyToSize(triton::intlibs::vexlifter::vex_ir_ity ty) {
        switch (ty) {
            case triton::intlibs::vexlifter::Ity_Invalid: return 0;
            case triton::intlibs::vexlifter::Ity_F32: return 32;
            case triton::intlibs::vexlifter::Ity_F64: return 64;
            case triton::intlibs::vexlifter::Ity_I1: return 1;
            case triton::intlibs::vexlifter::Ity_I16: return 16;
            case triton::intlibs::vexlifter::Ity_I32: return 32;
            case triton::intlibs::vexlifter::Ity_I64: return 54;
            case triton::intlibs::vexlifter::Ity_I8: return 8;
            case triton::intlibs::vexlifter::Ity_V128: return 128;
            case triton::intlibs::vexlifter::Ity_V256: return 256;
        }
        return 0;
      }

      triton::uint32 vexCpu::translatePairIDToRegID(std::pair<triton::uint32, triton::uint32> pairId) {
        return this->reg_map_pairid_to_regid[pairId];
      }

      std::pair<triton::uint32, triton::uint32> vexCpu::translateRegIDToPairID(triton::uint32 regId) {
        return this->reg_map_regid_to_pairid[regId];
      }

      triton::uint32 vexCpu::translateTmpToRegID(triton::uint32 tmp) {
        return tmp + 1000;
      }

      triton::uint32 vexCpu::translateRegIDToTmp(triton::uint32 regId) {
        return regId - 1000;
      }


    }; /* vex namespace */
  }; /* arch namespace */
}; /* triton namespace */

