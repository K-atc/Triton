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
      };


      //! The list of registers.
      enum registers_e {
        ID_REG_INVALID = 0, //!< invalid = 0

        // general registers here
        ID_REG_RIP = 184, // FIXME: use archinfo, non-multiarch-oriented

        // tmp registers here
        ID_REG_TMP = 0x400,


        /* Must be the last item */
        ID_REG_LAST_ITEM = 0x1000 //!< must be the last item
      };

      //! Global set of registers.
      extern triton::arch::Register vex_regs[ID_REG_TMP];

      //! The list of opcodes.
      enum instructions_e {
        ID_INST_INVALID = 0, //!< invalid

        ID_AMD64G_CALCUATE_CONDITION, //!< amd64g_calculate_condition()

        ID_INS_TODO, // TODO

        /* Must be the last item */
        ID_INST_LAST_ITEM //!< must be the last item
      };

      triton::uint32 translatePairIDToRegID(triton::uint32 offset, triton::uint32 size);
      triton::uint32 translatePairIDToRegID(std::pair<triton::uint32, triton::uint32> pairId);
      std::pair<triton::uint32, triton::uint32> translateRegIDToPairID(triton::uint32 regId);
      triton::uint32 translateTmpToRegID(triton::uint32 tmpId, triton::uint32 size);
      std::pair<triton::uint32, triton::uint32> translateRegIDToTmp(triton::uint32 regId);
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
