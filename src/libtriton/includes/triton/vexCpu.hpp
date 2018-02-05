//! \file
/*
**  Copyright (C) - Triton
**
**  This program is under the terms of the BSD License.
*/

#ifndef TRITON_VEXCPU_HPP
#define TRITON_VEXCPU_HPP

#include <map>
#include <set>
#include <vector>

#include <triton/callbacks.hpp>
#include <triton/cpuInterface.hpp>
#include <triton/instruction.hpp>
#include <triton/memoryAccess.hpp>
#include <triton/register.hpp>
#include <triton/registerSpecification.hpp>
#include <triton/tritonTypes.hpp>
#include <triton/vexSpecifications.hpp>
#include <triton/vexLifter.hpp>



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

      //! \class vexCpu
      /*! \brief This class is used to describe the vex (32-bits) spec. */
      class vexCpu : public CpuInterface, public vexSpecifications {
        private:
          //! Callbacks API
          triton::callbacks::Callbacks* callbacks;

        protected:
          /*! \brief map of address -> concrete value
           *
           * \description
           * **item1**: memory address<br>
           * **item2**: concrete value
           */
          std::map<triton::uint64, triton::uint8> memory;

          //! Concrete value of registers
          triton::uint8 cc_regs[DWORD_SIZE * 1000];

          //! Concrete value of tmp
          std::map<triton::uint32, triton::uint512> cc_tmp;

          //! Holds VexIR Representations
          triton::intlibs::vexlifter::vex_insns_group lifted_vex_insns;

          std::map<std::pair<triton::uint32, triton::uint32>, triton::uint32> reg_map_pairid_to_regid;
          std::map<triton::uint32, std::pair<triton::uint32, triton::uint32>> reg_map_regid_to_pairid;

          triton::uint32 translateVexTyToSize(triton::intlibs::vexlifter::vex_ir_ity ty);
          triton::uint32 translatePairIDToRegID(std::pair<triton::uint32, triton::uint32> pairId);
          std::pair<triton::uint32, triton::uint32> translateRegIDToPairID(triton::uint32 regId);
          triton::uint32 translateTmpToRegID(triton::uint32 tmp);
          triton::uint32 translateRegIDToTmp(triton::uint32 regId);

        public:
          //! Constructor.
          vexCpu(triton::callbacks::Callbacks* callbacks=nullptr);

          //! Constructor by copy.
          vexCpu(const vexCpu& other);

          //! Destructor.
          virtual ~vexCpu();

          //! Copies a vexCpu class.
          void operator=(const vexCpu& other);

          //! Copies a vexCpu class.
          void copy(const vexCpu& other);

          //! Returns true if regId is a GRP.
          bool isGPR(triton::uint32 regId) const;

          //! Returns true if regId is a MMX register.
          bool isMMX(triton::uint32 regId) const;

          //! Returns true if regId is a SSE register.
          bool isSSE(triton::uint32 regId) const;

          //! Returns true if regId is a AVX-256 (YMM) register.
          bool isAVX256(triton::uint32 regId) const;

          //! Returns true if regId is a control (cr) register.
          bool isControl(triton::uint32 regId) const;

          //! Returns true if regId is a Segment.
          bool isSegment(triton::uint32 regId) const;

          /* Virtual pure inheritance ================================================= */
          bool isFlag(triton::uint32 regId) const;
          bool isMemoryMapped(triton::uint64 baseAddr, triton::usize size=1);
          bool isRegister(triton::uint32 regId) const;
          bool isRegisterValid(triton::uint32 regId) const;
          std::set<triton::arch::Register*> getAllRegisters(void) const;
          std::set<triton::arch::Register*> getParentRegisters(void) const;
          std::vector<triton::uint8> getConcreteMemoryAreaValue(triton::uint64 baseAddr, triton::usize size, bool execCallbacks=true) const;
          triton::arch::RegisterSpecification getRegisterSpecification(triton::uint32 regId) const;
          triton::uint32 numberOfRegisters(void) const;
          triton::uint32 registerBitSize(void) const;
          triton::uint32 registerSize(void) const;
          triton::uint512 getConcreteMemoryValue(const triton::arch::MemoryAccess& mem, bool execCallbacks=true) const;
          triton::uint512 getConcreteRegisterValue(const triton::arch::Register& reg, bool execCallbacks=true) const;
          triton::uint8 getConcreteMemoryValue(triton::uint64 addr) const;
          void clear(void);
          void disassembly(triton::arch::Instruction& inst) const;
          void disassembly2(std::vector<triton::arch::Instruction>& insts, triton::uint64 address);
          void disassemble_block(triton::uint8 *opcodes, triton::uint32 opcodesSize, triton::uint32 address);
          void init(void);
          void setConcreteMemoryAreaValue(triton::uint64 baseAddr, const std::vector<triton::uint8>& values);
          void setConcreteMemoryAreaValue(triton::uint64 baseAddr, const triton::uint8* area, triton::usize size);
          void setConcreteMemoryValue(const triton::arch::MemoryAccess& mem);
          void setConcreteMemoryValue(triton::uint64 addr, triton::uint8 value);
          void setConcreteRegisterValue(const triton::arch::Register& reg);
          void unmapMemory(triton::uint64 baseAddr, triton::usize size=1);
          /* End of virtual pure inheritance ========================================== */
      };

    /*! @} End of vex namespace */
    };
  /*! @} End of arch namespace */
  };
/*! @} End of triton namespace */
};


#endif  /* !vexCPU_HPP */
