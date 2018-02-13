//! \file
/*
**  Copyright (C) - Triton
**
**  This program is under the terms of the BSD License.
*/

#ifndef TRITON_VEXSEMANTICS_H
#define TRITON_VEXSEMANTICS_H

#include <triton/architecture.hpp>
#include <triton/instruction.hpp>
#include <triton/semanticsInterface.hpp>
#include <triton/symbolicEngine.hpp>
#include <triton/taintEngine.hpp>



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

      /*! \class vexSemantics
          \brief The vex ISA semantics. */
      class vexSemantics : public SemanticsInterface {
        private:
          //! Architecture API
          triton::arch::Architecture* architecture;

          //! Symbolic Engine API
          triton::engines::symbolic::SymbolicEngine* symbolicEngine;

          //! Taint Engine API
          triton::engines::taint::TaintEngine* taintEngine;

        public:
          //! Constructor.
          vexSemantics(triton::arch::Architecture* architecture,
                       triton::engines::symbolic::SymbolicEngine* symbolicEngine,
                       triton::engines::taint::TaintEngine* taintEngine);

          //! Destructor.
          virtual ~vexSemantics();

          //! Builds the semantics of the instruction. Returns true if the instruction is supported.
          bool buildSemantics(triton::arch::Instruction& inst);

          //! Aligns the stack (add). Returns the new stack value.
          triton::uint64 alignAddStack_s(triton::arch::Instruction& inst, triton::uint32 delta);

          //! Aligns the stack (sub). Returns the new stack value.
          triton::uint64 alignSubStack_s(triton::arch::Instruction& inst, triton::uint32 delta);

          //! Clears a flag.
          void clearFlag_s(triton::arch::Instruction& inst, triton::arch::Register& flag, std::string comment="");

          //! Sets a flag.
          void setFlag_s(triton::arch::Instruction& inst, triton::arch::Register& flag, std::string comment="");

          //! Control flow semantics. Used to represent IP.
          void controlFlow_s(triton::arch::Instruction& inst);

          void binop_add_s(triton::arch::Instruction& inst);
          void binop_shl_s(triton::arch::Instruction& inst);
          void binop_xor_s(triton::arch::Instruction& inst);
          void exit_s(triton::arch::Instruction& inst);
          void helper_amd64g_calculate_condition_s(triton::arch::Instruction& inst);
          void jump_boring_s(triton::arch::Instruction& inst);
          void mov_s(triton::arch::Instruction& inst);
          void unop_cast_s(triton::arch::Instruction& inst);
          void unop_castu_s(triton::arch::Instruction& inst);
      };

    /*! @} End of vex namespace */
    };
  /*! @} End of arch namespace */
  };
/*! @} End of triton namespace */
};


#endif /* TRITON_VEXSEMANTICS_H */
