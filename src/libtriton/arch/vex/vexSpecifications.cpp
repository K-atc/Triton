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


      vexSpecifications::vexSpecifications() {
      }


      vexSpecifications::~vexSpecifications() {
      }


      triton::arch::RegisterSpecification vexSpecifications::getvexRegisterSpecification(triton::uint32 arch, triton::uint32 regId) const {
        triton::arch::RegisterSpecification ret;

        if (true) return ret; // TODO

        if (arch != triton::arch::ARCH_vex && arch != triton::arch::ARCH_vex_64)
          return ret;

        switch (regId) {

          case triton::arch::vex::ID_REG_RAX:
            ret.setName("rax");
            ret.setHigh(QWORD_SIZE_BIT-1);
            ret.setLow(0);
            ret.setParentId(triton::arch::vex::ID_REG_RAX);
            break;

          // TODO
        }
        return ret;
      }


    }; /* vex namespace */
  }; /* arch namespace */
}; /* triton namespace */

