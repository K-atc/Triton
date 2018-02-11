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

      triton::arch::Register vex_regs    = triton::arch::Register(); // not used
      triton::arch::Register vex_tmp     = triton::arch::Register(); // not used
      triton::arch::Register vex_reg_pc  = triton::arch::Register();


      vexSpecifications::vexSpecifications() {
      }


      vexSpecifications::~vexSpecifications() {
      }

      triton::arch::RegisterSpecification vexSpecifications::getVexRegisterSpecification(triton::uint32 arch, triton::uint32 regId) const {
        triton::arch::RegisterSpecification ret;

        if (arch != triton::arch::ARCH_VEX)
          return ret;

        auto pairId = translateRegIDToPairID(regId);
        triton::uint32 offset = pairId.first;
        triton::uint32 bitSize = pairId.second;
        // triton::logger::info("vexSpecifications::getVexRegisterSpecification: regId = 0x%x, offset=0x%x, size=%d", regId, offset, bitSize);

#if 0 // NEEDLESS
        switch (offset) {
          case triton::arch::vex::ID_REG_RIP:
            ret.setName("rip");
            ret.setHigh(QWORD_SIZE_BIT-1);
            ret.setLow(0);
            ret.setParentId(regId);
            return ret;
          // TODO
        }
#endif

        char name[32] = "";
        if (regId < ID_REG_TMP) { // a query for parent registers
          snprintf(name, sizeof(name), "reg(offset=%d)", offset);
          ret.setName(std::string(name));
          ret.setHigh(QWORD_SIZE_BIT - 1); // FIXME: 
          ret.setLow(0);
          ret.setParentId(regId); // refference to self
        }
        else if (ID_REG_TMP < regId && regId < ID_REG_LAST_ITEM) { // a query for tmp
          snprintf(name, sizeof(name), "t%d", regId - ID_REG_TMP);
          ret.setName(std::string(name));
          ret.setHigh(QWORD_SIZE_BIT - 1); // FIXME: 
          ret.setLow(0);
          ret.setParentId(regId); // refference to self
        }
        else {
          if (offset < ID_REG_TMP) { // a query for virtual registers
            snprintf(name, sizeof(name), "virtualReg(offset=0x%x,size=%d)", offset, bitSize);
            ret.setName(std::string(name));
            ret.setHigh(bitSize - 1);
            ret.setLow(0);
            ret.setParentId(offset); // refference to parent registers
          }
          else { // a query for tmp
            snprintf(name, sizeof(name), "t%d", offset - ID_REG_TMP);
            ret.setName(std::string(name));
            ret.setHigh(QWORD_SIZE_BIT - 1); // FIXME: 
            ret.setLow(0);
            ret.setParentId(offset); // refference to self
          }
        }

        return ret;
      }

      triton::uint32 translatePairIDToRegID(triton::uint32 offset, triton::uint32 size) {
        return offset * 0x10 + static_cast<triton::uint32>(std::log2(size));
      }

      triton::uint32 translatePairIDToRegID(std::pair<triton::uint32, triton::uint32> pairId) {
        return pairId.first * 0x10 + static_cast<triton::uint32>(std::log2(pairId.second));
      }

      std::pair<triton::uint32, triton::uint32> translateRegIDToPairID(triton::uint32 regId) {
        return std::make_pair(regId / 0x10, 1 << (regId % 0x10));
      }

      triton::uint32 translateTmpToRegID(triton::uint32 tmp, triton::uint32 size) {
        return translatePairIDToRegID(tmp + ID_REG_TMP, size);
      }

      triton::uint32 translateRegIDToTmp(triton::uint32 regId) {
        return translateRegIDToPairID(regId).first - ID_REG_TMP;
      }

    }; /* vex namespace */
  }; /* arch namespace */
}; /* triton namespace */

