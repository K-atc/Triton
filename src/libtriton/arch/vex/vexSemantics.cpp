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
        switch (inst.getType()) {
          case ID_INS_AAD:            this->aad_s(inst);          break;
          // TODO
          default:
            return false;
        }
        return true;
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

#if 0
      void x86Semantics::jne_s(triton::arch::Instruction& inst) {
        auto  pc      = triton::arch::OperandWrapper(TRITON_X86_REG_PC);
        auto  zf      = triton::arch::OperandWrapper(TRITON_X86_REG_ZF);
        auto  srcImm1 = triton::arch::OperandWrapper(Immediate(inst.getNextAddress(), pc.getSize()));
        auto& srcImm2 = inst.operands[0];

        /* Create symbolic operands */
        auto op1 = this->symbolicEngine->buildSymbolicOperand(inst, zf);
        auto op2 = this->symbolicEngine->buildSymbolicOperand(inst, srcImm1);
        auto op3 = this->symbolicEngine->buildSymbolicOperand(inst, srcImm2);

        /* Create the semantics */
        auto node = triton::ast::ite(triton::ast::equal(op1, triton::ast::bvfalse()), op3, op2);

        /* Create symbolic expression */
        auto expr = this->symbolicEngine->createSymbolicExpression(inst, node, pc, "Program Counter");

        /* Set condition flag */
        if (op1->evaluate().is_zero())
          inst.setConditionTaken(true);

        /* Spread taint */
        expr->isTainted = this->taintEngine->taintAssignment(pc, zf);

        /* Create the path constraint */
        this->symbolicEngine->addPathConstraint(inst, expr);
      }

      void x86Semantics::mov_s(triton::arch::Instruction& inst) {
        auto& dst = inst.operands[0];
        auto& src = inst.operands[1];

        /* Create the semantics */
        auto node = this->symbolicEngine->buildSymbolicOperand(inst, src);

        /*
         * Special cases:
         *
         * Triton defines segment registers as 32 or 64  bits vector to
         * avoid to simulate the GDT which allows users to directly define
         * their segments offset.
         *
         * The code below, handles the case: MOV r/m{16/32/64}, Sreg
         */
        if (src.getType() == triton::arch::OP_REG) {
          uint32 id = src.getConstRegister().getId();
          if (id >= triton::arch::x86::ID_REG_CS && id <= triton::arch::x86::ID_REG_SS) {
            node = triton::ast::extract(dst.getBitSize()-1, 0, node);
          }
        }

        /*
         * The code below, handles the case: MOV Sreg, r/m{16/32/64}
         */
        if (dst.getType() == triton::arch::OP_REG) {
          uint32 id = dst.getConstRegister().getId();
          if (id >= triton::arch::x86::ID_REG_CS && id <= triton::arch::x86::ID_REG_SS) {
            node = triton::ast::extract(WORD_SIZE_BIT-1, 0, node);
          }
        }

        /* Create symbolic expression */
        auto expr = this->symbolicEngine->createSymbolicExpression(inst, node, dst, "MOV operation");

        /* Spread taint */
        expr->isTainted = this->taintEngine->taintAssignment(dst, src);

        /* Upate the symbolic control flow */
        this->controlFlow_s(inst);
      }      
#endif

    }; /* vex namespace */
  }; /* arch namespace */
}; /* triton namespace */

