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

      namespace x86_64 {
        /*
        for k, v in sorted(archinfo.ArchAMD64().register_names.items(), key = lambda x:x[0]):
          print "OFFSET_{} = {},".format(v.upper(), k)
        */
        enum offsets_e {
          OFFSET_RAX = 16,
          OFFSET_RCX = 24,
          OFFSET_RDX = 32,
          OFFSET_RBX = 40,
          OFFSET_RSP = 48,
          OFFSET_RBP = 56,
          OFFSET_RSI = 64,
          OFFSET_RDI = 72,
          OFFSET_R8 = 80,
          OFFSET_R9 = 88,
          OFFSET_R10 = 96,
          OFFSET_R11 = 104,
          OFFSET_R12 = 112,
          OFFSET_R13 = 120,
          OFFSET_R14 = 128,
          OFFSET_R15 = 136,
          OFFSET_CC_OP = 144,
          OFFSET_CC_DEP1 = 152,
          OFFSET_CC_DEP2 = 160,
          OFFSET_CC_NDEP = 168,
          OFFSET_DFLAG = 176,
          OFFSET_RIP = 184,
          OFFSET_ACFLAG = 192,
          OFFSET_IDFLAG = 200,
          OFFSET_FS_CONST = 208,
          OFFSET_SSEROUND = 216,
          OFFSET_YMM0 = 224,
          OFFSET_YMM1 = 256,
          OFFSET_YMM2 = 288,
          OFFSET_YMM3 = 320,
          OFFSET_YMM4 = 352,
          OFFSET_YMM5 = 384,
          OFFSET_YMM6 = 416,
          OFFSET_YMM7 = 448,
          OFFSET_YMM8 = 480,
          OFFSET_YMM9 = 512,
          OFFSET_YMM10 = 544,
          OFFSET_YMM11 = 576,
          OFFSET_YMM12 = 608,
          OFFSET_YMM13 = 640,
          OFFSET_YMM14 = 672,
          OFFSET_YMM15 = 704,
          OFFSET_YMM16 = 736,
          OFFSET_FTOP = 768,
          OFFSET_MM0 = 776,
          OFFSET_MM1 = 784,
          OFFSET_MM2 = 792,
          OFFSET_MM3 = 800,
          OFFSET_MM4 = 808,
          OFFSET_MM5 = 816,
          OFFSET_MM6 = 824,
          OFFSET_MM7 = 832,
          OFFSET_FPU_TAGS = 840,
          OFFSET_FPROUND = 848,
          OFFSET_FC3210 = 856,
          OFFSET_EMNOTE = 864,
          OFFSET_CMSTART = 872,
          OFFSET_CMLEN = 880,
          OFFSET_NRADDR = 888,
          OFFSET_SC_CLASS = 896,
          OFFSET_GS_CONST = 904,
          OFFSET_IP_AT_SYSCALL = 912,
        };
      }

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
