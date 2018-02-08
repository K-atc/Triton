//! \file
/*
**  Copyright (C) - Triton
**
**  This program is under the terms of the BSD License.
*/

#include <triton/cpuSize.hpp>
#include <triton/exceptions.hpp>
#include <triton/vexSemantics.hpp>
#include <triton/vexSpecifications.hpp>

#include <triton/vexLifter.hpp>


/*! \page SMT_Semantics_Supported_page SMT Semantics Supported
    \brief [**internal**] All information about the supported semantics.

\tableofcontents

\section SMT_Semantics_Supported_description Description
<hr>

Here is the instructions' list of what **Triton** can convert into \ref py_ast_page. Please note that our main
objective is not to support all semantics right now, we are currently focusing on the design of **Triton**'s
engines. When engines will be reliable, we will write the last semantics :-). However, feel free to add your
own semantics into the [appropriate file](vexSemantics_8cpp_source.html). Thanks to `wisk` and his
[Medusa project](https://github.com/wisk/medusa/blob/dev/arch/vex.yaml) which has been really useful.

\subsection SMT_Semantics_Supported_vex vex and vex-64 SMT semantics supported


Mnemonic                     | Extensions | Description
-----------------------------|------------|----------------------------------------------------
AAD                          |            | ASCII Adjust AX Before Division
TODO                         |            | 
*/



namespace triton {
  namespace arch {
    namespace vex {

      vexSemantics::vexSemantics(triton::arch::Architecture* architecture,
                                 triton::engines::symbolic::SymbolicEngine* symbolicEngine,
                                 triton::engines::taint::TaintEngine* taintEngine) {

        this->architecture    = architecture;
        this->symbolicEngine  = symbolicEngine;
        this->taintEngine     = taintEngine;

        if (this->architecture == nullptr)
          throw triton::exceptions::Semantics("vexSemantics::vexSemantics(): The architecture API must be defined.");

        if (this->symbolicEngine == nullptr)
          throw triton::exceptions::Semantics("vexSemantics::vexSemantics(): The symbolic engine API must be defined.");

        if (this->taintEngine == nullptr)
          throw triton::exceptions::Semantics("vexSemantics::vexSemantics(): The taint engines API must be defined.");
      }


      vexSemantics::~vexSemantics() {
      }


      bool vexSemantics::buildSemantics(triton::arch::Instruction& inst) {
        using namespace triton::intlibs::vexlifter;
        switch ((triton::uint32) inst.getType()) {
          case vex_itype(Ist_IMark):
            break;
          case vex_itype(Ist_Exit, Iex_RdTmp):
            this->exit_s(inst); break;
          case vex_itype(Ist_Jump):
            this->jump_boring_s(inst); break; // TODO; Ijk_Syscall, etc.
          case vex_itype(Ist_Put, Iex_Const):
          case vex_itype(Ist_Put, Iex_RdTmp):
          case vex_itype(Ist_Store, Iex_RdTmp):
          case vex_itype(Ist_WrTmp, Iex_Get):
          case vex_itype(Ist_WrTmp, Iex_RdTmp):
          case vex_itype(Ist_WrTmp, Iex_Load):
            this->mov_s(inst); break;
            #if 0
          case vex_itype(Ist_WrTmp, Iex_Unop, Iop_Cast):
            this->mov_unop_cast_s(inst); break;
          case vex_itype(Ist_WrTmp, Iex_Binop, Iop_CmpEQ):
            this->mov_binop_cmpeq_s(inst); break;
          case vex_itype(Ist_WrTmp, Iex_Binop, Iop_Add):
            this->mov_binop_add_s(inst); break;
          case vex_itype(Ist_WrTmp, Iex_Binop, Iop_Sub):
            this->mov_binop_sub_s(inst); break;
            #endif
          default:
            char msg[128];
            snprintf(msg, sizeof(msg), "vexSemantics::vexSemantics(): Unknown type 0x%x.", inst.getType());
            throw triton::exceptions::Semantics(msg);
            return false;
        }
        return true;
      }

      void vexSemantics::controlFlow_s(triton::arch::Instruction& inst) {
        auto pc      = triton::arch::OperandWrapper(TRITON_VEX_REG_PC.getParent());

        /* Update instruction address if undefined */
        if (!inst.getAddress())
          inst.setAddress(this->architecture->getConcreteRegisterValue(pc.getConstRegister()).convert_to<triton::uint64>());

        /* Create the semantics */
        auto node = triton::ast::bv(inst.getNextAddress(), pc.getBitSize());

        /* Create symbolic expression */
        auto expr = this->symbolicEngine->createSymbolicRegisterExpression(inst, node, TRITON_VEX_REG_PC, "Program Counter");

        /* Spread taint */
        expr->isTainted = this->taintEngine->setTaintRegister(TRITON_VEX_REG_PC, triton::engines::taint::UNTAINTED);
      }

      void vexSemantics::add_s(triton::arch::Instruction& inst) {
        auto& dst = inst.operands[0];
        auto& src = inst.operands[1];

        /* Create symbolic operands */
        auto op1 = this->symbolicEngine->buildSymbolicOperand(inst, dst);
        auto op2 = this->symbolicEngine->buildSymbolicOperand(inst, src);

        /* Create the semantics */
        auto node = triton::ast::bvadd(op1, op2);

        /* Create symbolic expression */
        auto expr = this->symbolicEngine->createSymbolicExpression(inst, node, dst, "ADD operation");

        /* Spread taint */
        expr->isTainted = this->taintEngine->taintUnion(dst, src);

        /* Upate the symbolic control flow */
        this->controlFlow_s(inst);
      }

      void vexSemantics::exit_s(triton::arch::Instruction& inst) {
        auto& guard = inst.operands[0];
        auto& dst = inst.operands[1];
        auto  srcImm1 = triton::arch::OperandWrapper(Immediate(inst.getNextAddress(), dst.getSize()));
        auto& srcImm2 = inst.operands[2];

        /* Create symbolic operands */
        auto op1 = this->symbolicEngine->buildSymbolicOperand(inst, guard);
        // auto op2 = this->symbolicEngine->buildSymbolicOperand(inst, dst);
        auto op3 = this->symbolicEngine->buildSymbolicOperand(inst, srcImm1);
        auto op4 = this->symbolicEngine->buildSymbolicOperand(inst, srcImm2);

        /* Create the semantics */
        auto node = triton::ast::ite(triton::ast::equal(op1, triton::ast::bvtrue()), op4, op3);

        /* Create symbolic expression */
        auto expr = this->symbolicEngine->createSymbolicExpression(inst, node, dst, "Program Counter");

        /* Spread taint */
        // No Taints

        /* Create the path constraint */
        this->symbolicEngine->addPathConstraint(inst, expr);
      }

      void vexSemantics::jump_boring_s(triton::arch::Instruction& inst) {
        auto pc  = triton::arch::OperandWrapper(TRITON_VEX_REG_PC);
        auto srcImm = triton::arch::OperandWrapper(Immediate(inst.getNextAddress(), pc.getSize()));

        /* Create symbolic operands */
        auto op1 = this->symbolicEngine->buildSymbolicOperand(inst, srcImm);

        /* Create the semantics */
        auto node = op1;

        /* Create symbolic expression */
        auto expr = this->symbolicEngine->createSymbolicExpression(inst, node, pc, "Program Counter");

        /* Set condition flag */
        inst.setConditionTaken(true);

        /* Spread taint */
        // No Taints

        /* Create the path constraint */
        this->symbolicEngine->addPathConstraint(inst, expr);
      }

      void vexSemantics::mov_s(triton::arch::Instruction& inst) {
        auto dst = inst.operands[0];
        auto src = inst.operands[1];

        /* Create the semantics */
        auto node = this->symbolicEngine->buildSymbolicOperand(inst, src);

        /* Create symbolic expression */
        auto expr = this->symbolicEngine->createSymbolicExpression(inst, node, dst, "MOV operation");

        /* Spread taint */
        expr->isTainted = this->taintEngine->taintAssignment(dst, src);

        /* Upate the symbolic control flow */
        this->controlFlow_s(inst);
      }



    }; /* vex namespace */
  }; /* arch namespace */
}; /* triton namespace */

