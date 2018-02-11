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

#include <triton/logger.hpp>
#include <triton/vexLifter.hpp>
#include <assert.h>


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
        triton::logger::info("vexSemantics::buildSemantics: addr = 0x%x, type = %s", inst.getAddress(), vex_repr_itype(inst.getType()).c_str());
        switch ((triton::uint32) inst.getType()) {
          case vex_itype(Ist_IMark):
            triton::logger::info("vexSemantics::buildSemantics: Ist_IMark"); break;
          case vex_itype(Ist_Exit, Iex_RdTmp):
            this->exit_s(inst); break;
          case vex_itype(Ist_Jump): // TODO; Ijk_Syscall, etc.
            this->jump_boring_s(inst); break;
          case vex_itype(Ist_Put, Iex_Const): // mov_s
          case vex_itype(Ist_Put, Iex_RdTmp): // mov_s
          case vex_itype(Ist_Store, Iex_RdTmp): // mov_s
          case vex_itype(Ist_WrTmp, Iex_Get): // mov_s
          case vex_itype(Ist_WrTmp, Iex_RdTmp): // mov_s
          case vex_itype(Ist_WrTmp, Iex_Load): // mov_s
            this->mov_s(inst); break;
          case vex_itype(Ist_WrTmp, Iex_Unop, Iop_Cast):
            this->unop_cast_s(inst); break;
          case vex_itype(Ist_WrTmp, Iex_Unop, Iop_CastU):
            this->unop_castu_s(inst); break;
          case vex_itype(Ist_WrTmp, Iex_Binop, Iop_Add):
            this->binop_add_s(inst); break;
          case vex_itype(Ist_WrTmp, Iex_Binop, Iop_Shl):
            this->binop_shl_s(inst); break;
#if 0
          case vex_itype(Ist_WrTmp, Iex_Binop, Iop_CmpEQ):
            this->binop_cmpeq_s(inst); break;
          case vex_itype(Ist_WrTmp, Iex_Binop, Iop_Sub):
            this->binop_sub_s(inst); break;
#endif
          default:
            char msg[128];
            snprintf(msg, sizeof(msg), "vexSemantics::vexSemantics(): Unknown type %s.", triton::intlibs::vexlifter::vex_repr_itype(inst.getType()).c_str());
            throw triton::exceptions::Semantics(msg);
            return false;
        }
        // dor debugging
        for (unsigned int exp_index = 0; exp_index != inst.symbolicExpressions.size(); exp_index++) {
          auto expr = inst.symbolicExpressions[exp_index];
          std::cout << "\tSymExpr " << exp_index << ": " << expr << std::endl;
        }
        return true;
      }

      void vexSemantics::controlFlow_s(triton::arch::Instruction& inst) {
        auto pc      = triton::arch::OperandWrapper(TRITON_VEX_REG_PC.getParent());

        std::cout << "vexSemantics::controlFlow_s: TRITON_VEX_REG_PC: " << TRITON_VEX_REG_PC << std::endl;
        std::cout << "vexSemantics::controlFlow_s: pc: " << pc << std::endl;

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

      // dst = src1 + src2
      void vexSemantics::binop_add_s(triton::arch::Instruction& inst) {
        auto& dst = inst.operands[0];
        auto& src1 = inst.operands[1];
        auto& src2 = inst.operands[2];

        std::cout << "binop_add_s: src1: " << src1 << std::endl;
        std::cout << "binop_add_s: src2: " << src2 << std::endl;
        assert(src1.getSize() == src2.getSize());

        /* Create symbolic operands */
        auto op1 = this->symbolicEngine->buildSymbolicOperand(inst, src1);
        auto op2 = this->symbolicEngine->buildSymbolicOperand(inst, src2);

        /* Create the semantics */
        auto node = triton::ast::bvadd(op1, op2);

        /* Create symbolic expression */
        auto expr = this->symbolicEngine->createSymbolicExpression(inst, node, dst, "ADD operation");

        /* Spread taint */
        expr->isTainted = this->taintEngine->taintUnion(dst, src1);
        expr->isTainted |= this->taintEngine->taintUnion(dst, src2);

        /* Upate the symbolic control flow */
        this->controlFlow_s(inst);
      }

      // dst = shl(src1, src2)
      void vexSemantics::binop_shl_s(triton::arch::Instruction& inst) {
        auto& dst    = inst.operands[0];
        auto& src   = inst.operands[1]; // to be shifted
        auto& src2   = inst.operands[2]; // shift amount

        /* Create symbolic operands */
        auto op1 = this->symbolicEngine->buildSymbolicOperand(inst, dst);
        auto op2 = triton::ast::zx(dst.getBitSize() - src2.getBitSize(), this->symbolicEngine->buildSymbolicOperand(inst, src2));

        if (dst.getBitSize() == QWORD_SIZE_BIT)
          op2 = triton::ast::bvand(op2, triton::ast::bv(QWORD_SIZE_BIT-1, dst.getBitSize()));
        else
          op2 = triton::ast::bvand(op2, triton::ast::bv(DWORD_SIZE_BIT-1, dst.getBitSize()));

        /* Create the semantics */
        auto node = triton::ast::bvshl(op1, op2);

        /* Create symbolic expression */
        auto expr = this->symbolicEngine->createSymbolicExpression(inst, node, dst, "SHL operation");

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
        auto& dst = inst.operands[0];
        auto& src = inst.operands[1];

#if 0
        if (src.getType() == triton::arch::OP_REG) {
          std::cout << "mov_s: src: #" << std::hex << src.getRegister().getId() << "<" << src.getRegister().getParent().getId() << " " << src.getRegister() << std::endl;
        }
        else {
          std::cout << "mov_s: src: " << src << std::endl;
        }
        if (dst.getType() == triton::arch::OP_REG) {
          std::cout << "mov_s: dst: #" << std::hex << dst.getRegister().getId() << "<" << dst.getRegister().getParent().getId() << " " << dst.getRegister() << std::endl;
        }
        else {
          std::cout << "mov_s: dst: " << dst << std::endl;
        }
#endif

        /* Create the semantics */
        // triton::logger::info("Create the semantics");
        auto node = this->symbolicEngine->buildSymbolicOperand(inst, src);

        /* Create symbolic expression */
        // triton::logger::info("Create symbolic expression");
        auto expr = this->symbolicEngine->createSymbolicExpression(inst, node, dst, "MOV operation");
        std::cout << expr << std::endl;

        /* Spread taint */
        // triton::logger::info("Spread taint");
        expr->isTainted = this->taintEngine->taintAssignment(dst, src);

        /* Upate the symbolic control flow */
        // triton::logger::info("Upate the symbolic control flow");
        this->controlFlow_s(inst);
      }

      void vexSemantics::unop_cast_s(triton::arch::Instruction& inst) {
        auto& dst = inst.operands[0];
        auto& src1 = inst.operands[1];

        auto castFromSize = src1.getBitSize();
        auto castToSize = dst.getBitSize();
        std::cout << "unop_cast_s: " << dst << " = " << castFromSize << "to" << castToSize << "(" << src1 << ")" << std::endl;

        auto op1 = this->symbolicEngine->buildSymbolicOperand(inst, src1);

        /* Create the semantics */
        triton::ast::AbstractNode* node;
        if (castFromSize <= castToSize){ // extend
          node = triton::ast::sx(castToSize - castFromSize, triton::ast::extract(castFromSize-1, 0, op1)); // padding with sign bit
        }
        else { // shorten
          node = triton::ast::concat(
            triton::ast::extract(castFromSize-1, castFromSize-1, op1), // MSB (sign bit)
            triton::ast::extract(castToSize-2, 0, op1)
            );
        }

        /* Create symbolic expression */
        auto expr = this->symbolicEngine->createSymbolicExpression(inst, node, dst, "CAST operation");

        /* Spread taint */
        expr->isTainted = this->taintEngine->taintAssignment(dst, src1);

        /* Upate the symbolic control flow */
        this->controlFlow_s(inst);
      }

      void vexSemantics::unop_castu_s(triton::arch::Instruction& inst) {
        auto& dst = inst.operands[0];
        auto& src1 = inst.operands[1];

        auto castFromSize = src1.getBitSize();
        auto castToSize = dst.getBitSize();
        std::cout << "unop_cast_s: " << dst << " = " << castFromSize << "to" << castToSize << "(" << src1 << ")" << std::endl;

        auto op1 = this->symbolicEngine->buildSymbolicOperand(inst, src1);

        /* Create the semantics */
        triton::ast::AbstractNode* node;
        if (castFromSize <= castToSize){ // extend
          node = triton::ast::zx(castToSize - castFromSize, triton::ast::extract(castFromSize-1, 0, op1)); // padding with zero
        }
        else { // shorten
          node = triton::ast::extract(castToSize-1, 0, op1);
        }

        /* Create symbolic expression */
        auto expr = this->symbolicEngine->createSymbolicExpression(inst, node, dst, "CAST operation");

        /* Spread taint */
        expr->isTainted = this->taintEngine->taintAssignment(dst, src1);

        /* Upate the symbolic control flow */
        this->controlFlow_s(inst);
      }

    }; /* vex namespace */
  }; /* arch namespace */
}; /* triton namespace */

