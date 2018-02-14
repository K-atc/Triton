//! \file
/*
**  Copyright (C) - Triton
**
**  This program is under the terms of the BSD License.
*/

#include <triton/architecture.hpp>
#include <triton/cpuSize.hpp>
#include <triton/externalLibs.hpp>
#include <triton/vexSpecifications.hpp>
#include <triton/exceptions.hpp>

#include <triton/logger.hpp>


namespace triton {
  namespace arch {
    namespace vex {

      /*
       * Inside semantics, sometime we have to use references to registers.
       * TRITON_vex_REG_RAX, TRITON_vex_REG_RBX, ..., TRITON_vex_REG_AF...
       * are now available for a temporary access to the triton::arch::Register
       * class. By default, these vex_REG are empty. We must use init32 or init64 before.
       */

      triton::arch::Register vex_reg_invalid = triton::arch::Register();

      // triton::arch::Register vex_regs    = triton::arch::Register(); // not used
      triton::arch::Register vex_tmp     = triton::arch::Register(); // not used
      triton::arch::Register vex_reg_pc  = triton::arch::Register();

      triton::arch::Register vex_regs[ID_REG_TMP] = {triton::arch::Register()}; // dummy initialization

      vexSpecifications::vexSpecifications() {
      }


      vexSpecifications::~vexSpecifications() {
      }

      triton::arch::RegisterSpecification vexSpecifications::getVexRegisterSpecification(triton::uint32 arch, triton::uint32 regId) const {
        triton::arch::RegisterSpecification ret;

        if (arch != triton::arch::ARCH_VEX_X86_64) {
          throw triton::exceptions::Cpu("vexSpecifications::getVexRegisterSpecification: Invalid architecture (maybe implementation error).");
          return ret;
        }

        // triton::logger::info("vexSpecifications::getVexRegisterSpecification: regId = 0x%x", regId);
        // triton::logger::info("vexSpecifications::getVexRegisterSpecification: regId = 0x%x, offset=0x%x, size=%d", regId, offset, bitSize);

        char name[32] = "";
        if (regId < ID_REG_TMP) { // a query for parent registers
          snprintf(name, sizeof(name), "reg(offset=%d)", regId);
          ret.setName(std::string(name));
          ret.setHigh(QWORD_SIZE_BIT - 1); // FIXME: use archinfo
          ret.setLow(0);
          ret.setParentId(regId); // reference to self
        }
        else if (ID_REG_TMP <= regId && regId < ID_REG_LAST_ITEM) { // a query for tmp
          // auto pairId = translateRegIDToTmp(regId);
          // triton::uint32 tmpId = pairId.first;
          // triton::uint32 bitSize = pairId.second;
          // assert(bitSize % BYTE_SIZE_BIT == 0);

          snprintf(name, sizeof(name), "t%d", regId - ID_REG_TMP);
          ret.setName(std::string(name));
          ret.setHigh(QWORD_SIZE_BIT - 1);
          ret.setLow(0);
          ret.setParentId(regId); // reference to self
        }
        else {
          auto pairId = translateRegIDToPairID(regId);
          triton::uint32 offset = pairId.first;
          triton::uint32 bitSize = pairId.second;
          assert(bitSize % BYTE_SIZE_BIT == 0);

          if (offset < ID_REG_TMP) { // a query for virtual registers
            snprintf(name, sizeof(name), "reg'(offset=%d)", offset);
            ret.setName(std::string(name));
            ret.setHigh(bitSize - 1);
            ret.setLow(0);
            ret.setParentId(offset); // reference to parent registers
          }
          else {
            snprintf(name, sizeof(name), "t%d'", offset - ID_REG_TMP);
            ret.setName(std::string(name));
            ret.setHigh(bitSize - 1);
            ret.setLow(0);
            ret.setParentId(offset); // reference to parent registers (regId holds bit width)
          }
        }

        return ret;
      }

      triton::uint32 translatePairIDToRegID(triton::uint32 offset, triton::uint32 size) {
        assert(size > 0);
        if (size == 1) size = 8; // Triton's AST cannot handle 1 bit register. So we have to up the size.
        triton::uint32 ret = offset + 0x10000 * static_cast<triton::uint32>(std::log2(size));
        assert(ret > ID_REG_LAST_ITEM);
        return ret;
      }

      triton::uint32 translatePairIDToRegID(std::pair<triton::uint32, triton::uint32> pairId) {
        return translatePairIDToRegID(pairId.first, pairId.second);
      }

      std::pair<triton::uint32, triton::uint32> translateRegIDToPairID(triton::uint32 regId) {
        return std::make_pair(regId % 0x10000, 1 << ((regId / 0x10000)));
      }

      triton::uint32 translateTmpToRegID(triton::uint32 tmpId, triton::uint32 size) {
        return translatePairIDToRegID(tmpId + ID_REG_TMP, size);
      }

      std::pair<triton::uint32, triton::uint32> translateRegIDToTmp(triton::uint32 regId) {
        auto res = translateRegIDToPairID(regId);
        return std::make_pair(res.first - ID_REG_TMP, res.second);
      }

#if 0
      triton::uint32 translateTmpToRegID(triton::uint32 tmpId, triton::uint32 size) {
        assert(size > 0);
        return tmpId * 0x10 + std::log2(size) + ID_REG_TMP;
      }

      std::pair<triton::uint32, triton::uint32> translateRegIDToTmp(triton::uint32 regId) {
        auto tmpId = regId - ID_REG_TMP;
        return std::make_pair(tmpId / 0x10, 1 << (tmpId % 0x10));
      }
#endif

    }; /* vex namespace */
  }; /* arch namespace */
}; /* triton namespace */

