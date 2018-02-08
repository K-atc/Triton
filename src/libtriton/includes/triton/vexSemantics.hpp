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

#if 0
          //! The AF semantics.
          void af_s(triton::arch::Instruction& inst,
                    triton::engines::symbolic::SymbolicExpression* parent,
                    triton::arch::OperandWrapper& dst,
                    triton::ast::AbstractNode* op1,
                    triton::ast::AbstractNode* op2,
                    bool vol=false);

          //! The AF semantics.
          void afNeg_s(triton::arch::Instruction& inst,
                       triton::engines::symbolic::SymbolicExpression* parent,
                       triton::arch::OperandWrapper& dst,
                       triton::ast::AbstractNode* op1,
                       bool vol=false);

          //! The CF semantics.
          void cfAdd_s(triton::arch::Instruction& inst,
                       triton::engines::symbolic::SymbolicExpression* parent,
                       triton::arch::OperandWrapper& dst,
                       triton::ast::AbstractNode* op1,
                       triton::ast::AbstractNode* op2,
                       bool vol=false);

          //! The CF semantics.
          void cfBlsi_s(triton::arch::Instruction& inst,
                        triton::engines::symbolic::SymbolicExpression* parent,
                        triton::arch::OperandWrapper& dst,
                        triton::ast::AbstractNode* op1,
                        bool vol=false);

          //! The CF semantics.
          void cfBlsmsk_s(triton::arch::Instruction& inst,
                          triton::engines::symbolic::SymbolicExpression* parent,
                          triton::arch::OperandWrapper& dst,
                          triton::ast::AbstractNode* op1,
                          bool vol=false);

          //! The CF semantics.
          void cfBlsr_s(triton::arch::Instruction& inst,
                        triton::engines::symbolic::SymbolicExpression* parent,
                        triton::arch::OperandWrapper& dst,
                        triton::ast::AbstractNode* op1,
                        bool vol=false);

          //! The CF semantics.
          void cfImul_s(triton::arch::Instruction& inst,
                        triton::engines::symbolic::SymbolicExpression* parent,
                        triton::arch::OperandWrapper& dst,
                        triton::ast::AbstractNode* op1,
                        triton::ast::AbstractNode* res,
                        bool vol=false);

          //! The CF semantics.
          void cfMul_s(triton::arch::Instruction& inst,
                       triton::engines::symbolic::SymbolicExpression* parent,
                       triton::arch::OperandWrapper& dst,
                       triton::ast::AbstractNode* op1,
                       bool vol=false);

          //! The CF semantics.
          void cfNeg_s(triton::arch::Instruction& inst,
                       triton::engines::symbolic::SymbolicExpression* parent,
                       triton::arch::OperandWrapper& dst,
                       triton::ast::AbstractNode* op1,
                       bool vol=false);

          //! The CF semantics.
          void cfPtest_s(triton::arch::Instruction& inst,
                         triton::engines::symbolic::SymbolicExpression* parent,
                         triton::arch::OperandWrapper& dst,
                         bool vol=false);

          //! The CF semantics.
          void cfRcl_s(triton::arch::Instruction& inst,
                       triton::engines::symbolic::SymbolicExpression* parent,
                       triton::ast::AbstractNode* result,
                       triton::ast::AbstractNode* op2,
                       bool vol=false);

          //! The CF semantics.
          void cfRcr_s(triton::arch::Instruction& inst,
                       triton::engines::symbolic::SymbolicExpression* parent,
                       triton::arch::OperandWrapper& dst,
                       triton::ast::AbstractNode* result,
                       triton::ast::AbstractNode* op2,
                       bool vol=false);

          //! The CF semantics.
          void cfRol_s(triton::arch::Instruction& inst,
                       triton::engines::symbolic::SymbolicExpression* parent,
                       triton::arch::OperandWrapper& dst,
                       triton::ast::AbstractNode* op2,
                       bool vol=false);

          //! The CF semantics.
          void cfRor_s(triton::arch::Instruction& inst,
                       triton::engines::symbolic::SymbolicExpression* parent,
                       triton::arch::OperandWrapper& dst,
                       triton::ast::AbstractNode* op2,
                       bool vol=false);

          //! The CF semantics.
          void cfSar_s(triton::arch::Instruction& inst,
                       triton::engines::symbolic::SymbolicExpression* parent,
                       triton::arch::OperandWrapper& dst,
                       triton::ast::AbstractNode* op1,
                       triton::ast::AbstractNode* op2,
                       bool vol=false);

          //! The CF semantics.
          void cfShl_s(triton::arch::Instruction& inst,
                       triton::engines::symbolic::SymbolicExpression* parent,
                       triton::arch::OperandWrapper& dst,
                       triton::ast::AbstractNode* op1,
                       triton::ast::AbstractNode* op2,
                       bool vol=false);

          //! The CF semantics.
          void cfShld_s(triton::arch::Instruction& inst,
                        triton::engines::symbolic::SymbolicExpression* parent,
                        triton::arch::OperandWrapper& dst,
                        triton::ast::AbstractNode* op1,
                        triton::ast::AbstractNode* op2,
                        triton::ast::AbstractNode* op3,
                        bool vol=false);

          //! The CF semantics.
          void cfShr_s(triton::arch::Instruction& inst,
                       triton::engines::symbolic::SymbolicExpression* parent,
                       triton::arch::OperandWrapper& dst,
                       triton::ast::AbstractNode* op1,
                       triton::ast::AbstractNode* op2,
                       bool vol=false);

          //! The CF semantics.
          void cfShrd_s(triton::arch::Instruction& inst,
                        triton::engines::symbolic::SymbolicExpression* parent,
                        triton::arch::OperandWrapper& dst,
                        triton::ast::AbstractNode* op1,
                        triton::ast::AbstractNode* op2,
                        triton::ast::AbstractNode* op3,
                        bool vol=false);

          //! The CF semantics.
          void cfSub_s(triton::arch::Instruction& inst,
                       triton::engines::symbolic::SymbolicExpression* parent,
                       triton::arch::OperandWrapper& dst,
                       triton::ast::AbstractNode* op1,
                       triton::ast::AbstractNode* op2,
                       bool vol=false);

          //! The OF semantics.
          void ofAdd_s(triton::arch::Instruction& inst,
                       triton::engines::symbolic::SymbolicExpression* parent,
                       triton::arch::OperandWrapper& dst,
                       triton::ast::AbstractNode* op1,
                       triton::ast::AbstractNode* op2,
                       bool vol=false);

          //! The OF semantics.
          void ofImul_s(triton::arch::Instruction& inst,
                        triton::engines::symbolic::SymbolicExpression* parent,
                        triton::arch::OperandWrapper& dst,
                        triton::ast::AbstractNode* op1,
                        triton::ast::AbstractNode* res,
                        bool vol=false);

          //! The OF semantics.
          void ofMul_s(triton::arch::Instruction& inst,
                       triton::engines::symbolic::SymbolicExpression* parent,
                       triton::arch::OperandWrapper& dst,
                       triton::ast::AbstractNode* op1,
                       bool vol=false);

          //! The OF semantics.
          void ofNeg_s(triton::arch::Instruction& inst,
                       triton::engines::symbolic::SymbolicExpression* parent,
                       triton::arch::OperandWrapper& dst,
                       triton::ast::AbstractNode* op1,
                       bool vol=false);

          //! The OF semantics.
          void ofRol_s(triton::arch::Instruction& inst,
                       triton::engines::symbolic::SymbolicExpression* parent,
                       triton::arch::OperandWrapper& dst,
                       triton::ast::AbstractNode* op2,
                       bool vol=false);

          //! The OF semantics.
          void ofRor_s(triton::arch::Instruction& inst,
                       triton::engines::symbolic::SymbolicExpression* parent,
                       triton::arch::OperandWrapper& dst,
                       triton::ast::AbstractNode* op2,
                       bool vol=false);

          //! The OF semantics.
          void ofRcr_s(triton::arch::Instruction& inst,
                       triton::engines::symbolic::SymbolicExpression* parent,
                       triton::arch::OperandWrapper& dst,
                       triton::ast::AbstractNode* op1,
                       triton::ast::AbstractNode* op2,
                       bool vol=false);

          //! The OF semantics.
          void ofSar_s(triton::arch::Instruction& inst,
                       triton::engines::symbolic::SymbolicExpression* parent,
                       triton::arch::OperandWrapper& dst,
                       triton::ast::AbstractNode* op2,
                       bool vol=false);

          //! The OF semantics.
          void ofShl_s(triton::arch::Instruction& inst,
                       triton::engines::symbolic::SymbolicExpression* parent,
                       triton::arch::OperandWrapper& dst,
                       triton::ast::AbstractNode* op1,
                       triton::ast::AbstractNode* op2,
                       bool vol=false);

          //! The OF semantics.
          void ofShld_s(triton::arch::Instruction& inst,
                        triton::engines::symbolic::SymbolicExpression* parent,
                        triton::arch::OperandWrapper& dst,
                        triton::ast::AbstractNode* op1,
                        triton::ast::AbstractNode* op2,
                        triton::ast::AbstractNode* op3,
                        bool vol=false);

          //! The OF semantics.
          void ofShr_s(triton::arch::Instruction& inst,
                       triton::engines::symbolic::SymbolicExpression* parent,
                       triton::arch::OperandWrapper& dst,
                       triton::ast::AbstractNode* op1,
                       triton::ast::AbstractNode* op2,
                       bool vol=false);

          //! The OF semantics.
          void ofShrd_s(triton::arch::Instruction& inst,
                        triton::engines::symbolic::SymbolicExpression* parent,
                        triton::arch::OperandWrapper& dst,
                        triton::ast::AbstractNode* op1,
                        triton::ast::AbstractNode* op2,
                        triton::ast::AbstractNode* op3,
                        bool vol=false);

          //! The OF semantics.
          void ofSub_s(triton::arch::Instruction& inst,
                       triton::engines::symbolic::SymbolicExpression* parent,
                       triton::arch::OperandWrapper& dst,
                       triton::ast::AbstractNode* op1,
                       triton::ast::AbstractNode* op2,
                       bool vol=false);

          //! The PF semantics.
          void pf_s(triton::arch::Instruction& inst,
                    triton::engines::symbolic::SymbolicExpression* parent,
                    triton::arch::OperandWrapper& dst,
                    bool vol=false);

          //! The PF semantics.
          void pfShl_s(triton::arch::Instruction& inst,
                       triton::engines::symbolic::SymbolicExpression* parent,
                       triton::arch::OperandWrapper& dst,
                       triton::ast::AbstractNode* op2,
                       bool vol=false);

          //! The SF semantics.
          void sf_s(triton::arch::Instruction& inst,
                    triton::engines::symbolic::SymbolicExpression* parent,
                    triton::arch::OperandWrapper& dst,
                    bool vol=false);

          //! The SF semantics.
          void sfShl_s(triton::arch::Instruction& inst,
                       triton::engines::symbolic::SymbolicExpression* parent,
                       triton::arch::OperandWrapper& dst,
                       triton::ast::AbstractNode* op2,
                       bool vol=false);

          //! The SF semantics.
          void sfShld_s(triton::arch::Instruction& inst,
                        triton::engines::symbolic::SymbolicExpression* parent,
                        triton::arch::OperandWrapper& dst,
                        triton::ast::AbstractNode* op1,
                        triton::ast::AbstractNode* op2,
                        triton::ast::AbstractNode* op3,
                        bool vol=false);

          //! The SF semantics.
          void sfShrd_s(triton::arch::Instruction& inst,
                        triton::engines::symbolic::SymbolicExpression* parent,
                        triton::arch::OperandWrapper& dst,
                        triton::ast::AbstractNode* op1,
                        triton::ast::AbstractNode* op2,
                        triton::ast::AbstractNode* op3,
                        bool vol=false);

          //! The ZF semantics.
          void zf_s(triton::arch::Instruction& inst,
                    triton::engines::symbolic::SymbolicExpression* parent,
                    triton::arch::OperandWrapper& dst,
                    bool vol=false);

          //! The ZF semantics.
          void zfBsf_s(triton::arch::Instruction& inst,
                       triton::engines::symbolic::SymbolicExpression* parent,
                       triton::arch::OperandWrapper& src,
                       triton::ast::AbstractNode* op2,
                       bool vol=false);

          //! The ZF semantics.
          void zfShl_s(triton::arch::Instruction& inst,
                       triton::engines::symbolic::SymbolicExpression* parent,
                       triton::arch::OperandWrapper& dst,
                       triton::ast::AbstractNode* op2,
                       bool vol=false);
#endif

          void add_s(triton::arch::Instruction& inst);
          void exit_s(triton::arch::Instruction& inst);
          void jump_boring_s(triton::arch::Instruction& inst);
          void mov_s(triton::arch::Instruction& inst);
      };

    /*! @} End of vex namespace */
    };
  /*! @} End of arch namespace */
  };
/*! @} End of triton namespace */
};


#endif /* TRITON_VEXSEMANTICS_H */
