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

      triton::arch::Register vex_regs    = triton::arch::Register();
      triton::arch::Register vex_tmp     = triton::arch::Register();
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
        triton::uint32 size = pairId.second;
        char name[32] = "";
        snprintf(name, sizeof(name), "reg(offset=0x%x,size=%d)", offset, size);
        ret.setName(std::string(name));

#if 0
        switch (regId) {

          case triton::arch::vex::ID_REG_RAX:
            ret.setName("rax");
            ret.setHigh(QWORD_SIZE_BIT-1);
            ret.setLow(0);
            ret.setParentId(triton::arch::vex::ID_REG_RAX);
            break;

          // TODO
        }
#endif
        return ret;
      }




      triton::uint32 vexSpecifications::translatePairIDToRegID(triton::uint32 offset, triton::uint32 size) const {
        return offset * 0x10 + static_cast<triton::uint32>(std::log2(size));
      }

      triton::uint32 vexSpecifications::translatePairIDToRegID(std::pair<triton::uint32, triton::uint32> pairId) const {
        return pairId.first * 0x10 + static_cast<triton::uint32>(std::log2(pairId.second));
      }

      std::pair<triton::uint32, triton::uint32> vexSpecifications::translateRegIDToPairID(triton::uint32 regId) const {
        return std::make_pair(regId / 0x10, 1 << (regId % 0x10));
      }

      triton::uint32 vexSpecifications::translateTmpToRegID(triton::uint32 tmp) {
        return tmp + 0x1000;
      }

      triton::uint32 vexSpecifications::translateRegIDToTmp(triton::uint32 regId) {
        return regId - 0x1000;
      }


    }; /* vex namespace */
  }; /* arch namespace */
}; /* triton namespace */

