//! \file
/*
**  Copyright (C) - Triton
**
**  This program is under the terms of the BSD License.
*/

#ifndef TRITON_VEXSPECIFICATIONS_H
#define TRITON_VEXSPECIFICATIONS_H

#include <triton/register.hpp>
#include <triton/registerSpecification.hpp>



//! The Triton namespace
namespace triton {
/*!
 *  \addtogroup triton
 *  @{
 */

  //! The Architecture namespace
  namespace arch {
  /*!
   *  \ingroup triton
   *  \addtogroup arch
   *  @{
   */

    //! The vex namespace
    namespace vex {
    /*!
     *  \ingroup arch
     *  \addtogroup vex
     *  @{
     */

      extern triton::arch::Register vex_reg_invalid;

      //! Symbolic Registers
      extern triton::arch::Register vex_regs;
      extern triton::arch::Register vex_tmp;
      extern triton::arch::Register vex_reg_pc;

      //! \class vexSpecifications
      /*! \brief The vexSpecifications class defines specifications about the vex and vex_64 CPU */
      class vexSpecifications {
        public:
          //! Constructor.
          vexSpecifications();

          //! Destructor.
          virtual ~vexSpecifications();

          //! Returns all specifications about a register from its ID according to the arch (32 or 64-bits).
          triton::arch::RegisterSpecification getVexRegisterSpecification(triton::uint32 arch, triton::uint32 regId) const;

          triton::uint32 translatePairIDToRegID(triton::uint32 offset, triton::uint32 size) const;
          triton::uint32 translatePairIDToRegID(std::pair<triton::uint32, triton::uint32> pairId) const;
          std::pair<triton::uint32, triton::uint32> translateRegIDToPairID(triton::uint32 regId) const;
          triton::uint32 translateTmpToRegID(triton::uint32 tmp);
          triton::uint32 translateRegIDToTmp(triton::uint32 regId);
      };


      //! The list of registers.
      enum registers_e {
        ID_REG_INVALID = 0, //!< invalid = 0

        // TODO

        /* Must be the last item */
        ID_REG_LAST_ITEM //!< must be the last item
      };

      //! The list of opcodes. (NOT USED)
      enum instructions_e {
        ID_INST_INVALID = 0, //!< invalid

        ID_INS_TODO, // TODO

        /* Must be the last item */
        ID_INST_LAST_ITEM //!< must be the last item
      };

    /*! @} End of vex namespace */
    };
  /*! @} End of arch namespace */
  };
/*! @} End of triton namespace */
};


//! Temporary INVALID register.
#define TRITON_VEX_REG_INVALID  triton::arch::vex::vex_reg_invalid
//! Temporary vex registers.
#define TRITON_VEX_REGS         triton::arch::vex::vex_regs
//! vex program counter.
#define TRITON_VEX_REG_PC       triton::arch::vex::vex_reg_pc


#endif /* TRITON_VexSPECIFICATIONS_H */
