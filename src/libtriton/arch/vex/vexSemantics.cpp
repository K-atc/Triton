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

/* libVex */
#include <vex/priv/guest_amd64_defs.h>

#include <triton/logger.hpp>
#include <triton/vexLifter.hpp>
#include <assert.h>

#define UNUSED(x) ((void)(x))


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

        /* for debugging */
        for (unsigned int op_index = 0; op_index != inst.operands.size(); op_index++) {
          std::cout << "\tOperand " << op_index << ": " << inst.operands[op_index] << std::endl;
          if (inst.operands[op_index].getType() == OP_MEM) {
            std::cout << "\t   base  : " << inst.operands[op_index].getMemory().getBaseRegister() << std::endl;
          }
        }

        switch ((triton::uint32) inst.getType()) {
          case ID_AMD64G_CALCUATE_CONDITION:
            this->helper_amd64g_calculate_condition_s(inst); break;
          case vex_itype(Ist_IMark):
            // triton::logger::info("vexSemantics::buildSemantics: Ist_IMark"); break;
            break;
          case vex_itype(Ist_Exit, Ijk_Boring):
            this->exit_s(inst); break;
          case vex_itype(Ist_Jump):             // TODO; Ijk_Syscall, etc.
          case vex_itype(Ist_Jump, Ijk_Boring): // TODO; Ijk_Syscall, etc.
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
          case vex_itype(Ist_WrTmp, Iex_Binop, Iop_Sub):
            this->binop_sub_s(inst); break;
          case vex_itype(Ist_WrTmp, Iex_Binop, Iop_Xor):
            this->binop_xor_s(inst); break;
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
        // triton::logger::info("vexSemantics::vexSemantics(): build ended");
        return true;
      }

      void vexSemantics::controlFlow_s(triton::arch::Instruction& inst) {
        auto pc      = triton::arch::OperandWrapper(TRITON_VEX_REG_PC.getParent());

        // std::cout << "vexSemantics::controlFlow_s: TRITON_VEX_REG_PC: " << TRITON_VEX_REG_PC << std::endl;
        // std::cout << "vexSemantics::controlFlow_s: pc: " << pc << std::endl;

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
        auto& dst  = inst.operands[0];
        auto& src1 = inst.operands[1];
        auto& src2 = inst.operands[2];

        assert(src1.getBitSize() == src2.getBitSize());

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
        auto& src    = inst.operands[1]; // to be shifted
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

      // dst = src1 - src2
      void vexSemantics::binop_sub_s(triton::arch::Instruction& inst) {
        auto& dst  = inst.operands[0];
        auto& src1 = inst.operands[1];
        auto& src2 = inst.operands[2];

        assert(src1.getBitSize() == src2.getBitSize());

        /* Create symbolic operands */
        auto op1 = this->symbolicEngine->buildSymbolicOperand(inst, src1);
        auto op2 = this->symbolicEngine->buildSymbolicOperand(inst, src2);

        /* Create the semantics */
        auto node = triton::ast::bvsub(op1, op2);

        /* Create symbolic expression */
        auto expr = this->symbolicEngine->createSymbolicExpression(inst, node, dst, "ADD operation");

        /* Spread taint */
        expr->isTainted = this->taintEngine->taintUnion(dst, src1);
        expr->isTainted |= this->taintEngine->taintUnion(dst, src2);

        /* Upate the symbolic control flow */
        this->controlFlow_s(inst);
      }

      // dst = src1 ^ src2
      void vexSemantics::binop_xor_s(triton::arch::Instruction& inst) {
        auto& dst = inst.operands[0];
        auto& src1 = inst.operands[1];
        auto& src2 = inst.operands[2];

        assert(src1.getBitSize() == src2.getBitSize());

        /* Create symbolic operands */
        auto op1 = this->symbolicEngine->buildSymbolicOperand(inst, src1);
        auto op2 = this->symbolicEngine->buildSymbolicOperand(inst, src2);
        // auto op2 = triton::ast::zx(dst.getBitSize() - src2.getBitSize(), this->symbolicEngine->buildSymbolicOperand(inst, src2)); // e.g. Xor8

        /* Create the semantics */
        auto node = triton::ast::bvxor(op1, op2);

        /* Create symbolic expression */
        auto expr = this->symbolicEngine->createSymbolicExpression(inst, node, dst, "XOR operation");

        /* Spread taint */
        expr->isTainted = this->taintEngine->taintUnion(dst, src1);
        expr->isTainted |= this->taintEngine->taintUnion(dst, src2);

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

      // e.g. t5 = amd64g_calculate_condition(0x0000000000000006,t1,t2,t3,t4):Ity_I64
      void vexSemantics::helper_amd64g_calculate_condition_s(triton::arch::Instruction& inst) {
        /* Type annotations */
        assert(inst.operands[1].getType() == triton::arch::OP_IMM); // cond
        assert(inst.operands[2].getType() == triton::arch::OP_REG); // cc_op

        auto& dst = inst.operands[0];
        auto cond = inst.operands[1].getConcreteValue(); // symbolic const is not supported
        // auto cc_op = this->architecture->getConcreteRegisterValue(inst.operands[2].getRegister().getParent()).convert_to<triton::uint64>(); // symbolic cc_op is not supported
        auto cc_op = this->architecture->getConcreteRegisterValue(inst.operands[2].getRegister()).convert_to<triton::uint64>(); // symbolic cc_op is not supported
        auto& cc_dep1 = inst.operands[3];
        auto& cc_dep2 = inst.operands[4];
        auto& cc_ndep = inst.operands[5];

        std::cout << "\tcond = 0x" << std::hex << cond << std::endl;
        std::cout << "\tcc_op = 0x" << std::hex << cc_op << std::endl;

        /* Create symbolic operands */
        auto op1 = this->symbolicEngine->buildSymbolicOperand(inst, cc_dep1);
        auto op2 = this->symbolicEngine->buildSymbolicOperand(inst, cc_dep2);
        auto op3 = this->symbolicEngine->buildSymbolicOperand(inst, cc_ndep);
        UNUSED(op2);
        UNUSED(op3);

        /* Create the semantics (Phase I) */
        triton::ast::AbstractNode *cf = nullptr, *pf = nullptr, *af = nullptr, *zf = nullptr, *sf = nullptr, *of = nullptr;
        auto high = cc_dep1.getBitSize() - 1;
        triton::logger::info("vexSemantics::helper_amd64g_calculate_condition_s: high = %d", high);
        UNUSED(pf);
        UNUSED(af);
        UNUSED(sf);
        UNUSED(of);
        switch ((unsigned int) cc_op) {
          case AMD64G_CC_OP_COPY:  /* DEP1 = current flags, DEP2 = 0, NDEP = unused */
                                     /* just copy DEP1 to output */
          case AMD64G_CC_OP_ADDB:    /* 1 */
          case AMD64G_CC_OP_ADDW:    /* 2 DEP1 = argL, DEP2 = argR, NDEP = unused */
          case AMD64G_CC_OP_ADDL:    /* 3 */
          case AMD64G_CC_OP_ADDQ:    /* 4 */
          case AMD64G_CC_OP_SUBB:    /* 5 */
          case AMD64G_CC_OP_SUBW:    /* 6 DEP1 = argL, DEP2 = argR, NDEP = unused */
          case AMD64G_CC_OP_SUBL:    /* 7 */
          case AMD64G_CC_OP_SUBQ:    /* 8 */
          case AMD64G_CC_OP_ADCB:    /* 9 */
          case AMD64G_CC_OP_ADCW:    /* 10 DEP1 = argL, DEP2 = argR ^ oldCarry, NDEP = oldCarry */
          case AMD64G_CC_OP_ADCL:    /* 11 */
          case AMD64G_CC_OP_ADCQ:    /* 12 */
          case AMD64G_CC_OP_SBBB:    /* 13 */
          case AMD64G_CC_OP_SBBW:    /* 14 DEP1 = argL, DEP2 = argR ^ oldCarry, NDEP = oldCarry */
          case AMD64G_CC_OP_SBBL:    /* 15 */
          case AMD64G_CC_OP_SBBQ:    /* 16 */
            throw triton::exceptions::Semantics("vexSemantics::helper_amd64g_calculate_condition_s(): this cc_op not implemented.");
          case AMD64G_CC_OP_LOGICB:  /* 17 */
          case AMD64G_CC_OP_LOGICW:  /* 18 DEP1 = result, DEP2 = 0, NDEP = unused */
          case AMD64G_CC_OP_LOGICL:  /* 19 */
          case AMD64G_CC_OP_LOGICQ:  /* 20 */
            cf = triton::ast::bvfalse();
            af = triton::ast::bvfalse();
            zf = triton::ast::equal(op1, triton::ast::bv(0, cc_dep1.getBitSize()));
            std::cout << "\tzf = " << zf << std::endl;
            sf = triton::ast::extract(high, high, op1);
            std::cout << "\tsf = " << sf << std::endl;
            of = triton::ast::bvfalse();
            break;
          case AMD64G_CC_OP_INCB:    /* 21 */
          case AMD64G_CC_OP_INCW:    /* 22 DEP1 = result, DEP2 = 0, NDEP = oldCarry (0 or 1) */
          case AMD64G_CC_OP_INCL:    /* 23 */
          case AMD64G_CC_OP_INCQ:    /* 24 */
          case AMD64G_CC_OP_DECB:    /* 25 */
          case AMD64G_CC_OP_DECW:    /* 26 DEP1 = result, DEP2 = 0, NDEP = oldCarry (0 or 1) */
          case AMD64G_CC_OP_DECL:    /* 27 */
          case AMD64G_CC_OP_DECQ:    /* 28 */
          case AMD64G_CC_OP_SHLB:    /* 29 DEP1 = res, DEP2 = res', NDEP = unused */
          case AMD64G_CC_OP_SHLW:    /* 30 where res' is like res but shifted one bit less */
          case AMD64G_CC_OP_SHLL:    /* 31 */
          case AMD64G_CC_OP_SHLQ:    /* 32 */
          case AMD64G_CC_OP_SHRB:    /* 33 DEP1 = res, DEP2 = res', NDEP = unused */
          case AMD64G_CC_OP_SHRW:    /* 34 where res' is like res but shifted one bit less */
          case AMD64G_CC_OP_SHRL:    /* 35 */
          case AMD64G_CC_OP_SHRQ:    /* 36 */
          case AMD64G_CC_OP_ROLB:    /* 37 */
          case AMD64G_CC_OP_ROLW:    /* 38 DEP1 = res, DEP2 = 0, NDEP = old flags */
          case AMD64G_CC_OP_ROLL:    /* 39 */
          case AMD64G_CC_OP_ROLQ:    /* 40 */
          case AMD64G_CC_OP_RORB:    /* 41 */
          case AMD64G_CC_OP_RORW:    /* 42 DEP1 = res, DEP2 = 0, NDEP = old flags */
          case AMD64G_CC_OP_RORL:    /* 43 */
          case AMD64G_CC_OP_RORQ:    /* 44 */
          case AMD64G_CC_OP_UMULB:   /* 45 */
          case AMD64G_CC_OP_UMULW:   /* 46 DEP1 = argL, DEP2 = argR, NDEP = unused */
          case AMD64G_CC_OP_UMULL:   /* 47 */
          case AMD64G_CC_OP_UMULQ:   /* 48 */
          case AMD64G_CC_OP_SMULB:   /* 49 */
          case AMD64G_CC_OP_SMULW:   /* 50 DEP1 = argL, DEP2 = argR, NDEP = unused */
          case AMD64G_CC_OP_SMULL:   /* 51 */
          case AMD64G_CC_OP_SMULQ:   /* 52 */
          case AMD64G_CC_OP_ANDN32:  /* 53 */
          case AMD64G_CC_OP_ANDN64:  /* 54 DEP1 = res, DEP2 = 0, NDEP = unused */
          case AMD64G_CC_OP_BLSI32:  /* 55 */
          case AMD64G_CC_OP_BLSI64:  /* 56 DEP1 = res, DEP2 = arg, NDEP = unused */
          case AMD64G_CC_OP_BLSMSK32:/* 57 */
          case AMD64G_CC_OP_BLSMSK64:/* 58 DEP1 = res, DEP2 = arg, NDEP = unused */
          case AMD64G_CC_OP_BLSR32:  /* 59 */
          case AMD64G_CC_OP_BLSR64:  /* 60 DEP1 = res, DEP2 = arg, NDEP = unused */
            throw triton::exceptions::Semantics("vexSemantics::helper_amd64g_calculate_condition_s(): this cc_op not implemented."); break;
          default:
            throw triton::exceptions::Semantics("vexSemantics::helper_amd64g_calculate_condition_s(): Unknown cc_op.");
        }

        /* Create the semantics (Phase II) */
        triton::ast::AbstractNode* node = nullptr;
        switch (static_cast<AMD64Condcode>(cond)) {
          case AMD64CondO:    /* overflow           */
          case AMD64CondNO:   /* no overflow        */
          case AMD64CondB:    /* below              */
          case AMD64CondNB:   /* not below          */
            throw triton::exceptions::Semantics("vexSemantics::helper_amd64g_calculate_condition_s(): this cond Not implemented.");
          case AMD64CondZ:    /* zero               */
            node = triton::ast::equal(zf, triton::ast::bvtrue()); break;
          case AMD64CondNZ:   /* not zero           */
            node = triton::ast::equal(zf, triton::ast::bvfalse()); break;
          case AMD64CondBE:   /* below or equal     */
            node = triton::ast::bvor(cf, zf); break;                      // 1 & (inv ^ (cf | zf));
          case AMD64CondNBE:  /* not below or equal */
            node = triton::ast::bvneg(triton::ast::bvor(cf, zf)); break;  // 1 & (inv ^ (cf | zf));
          case AMD64CondS:    /* negative           */
          case AMD64CondNS:   /* not negative       */
          case AMD64CondP:    /* parity even        */
          case AMD64CondNP:   /* not parity even    */
          case AMD64CondL:    /* less               */
          case AMD64CondNL:   /* not less           */
          case AMD64CondLE:   /* less or equal      */
          case AMD64CondNLE:  /* not less or equal  */
            throw triton::exceptions::Semantics("vexSemantics::helper_amd64g_calculate_condition_s(): this cond Not implemented.");
          default:
            throw triton::exceptions::Semantics("vexSemantics::helper_amd64g_calculate_condition_s(): Unknown cond.");
        }

        /* Create symbolic expression */
        auto expr = this->symbolicEngine->createSymbolicExpression(inst, node, dst, "amd64g_calculate_condition operation");

        /* Spread taint */
        expr->isTainted  = this->taintEngine->taintUnion(dst, cc_dep1);
        expr->isTainted |= this->taintEngine->taintUnion(dst, cc_dep2);
        expr->isTainted |= this->taintEngine->taintUnion(dst, cc_ndep);

        /* Upate the symbolic control flow */
        this->controlFlow_s(inst);

        // throw triton::exceptions::Semantics("vexSemantics::helper_amd64g_calculate_condition_s(): Not implemented.");
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

        assert(dst.getBitSize() == src.getBitSize());

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
        // triton::logger::info("-- Create the semantics");
        auto node = this->symbolicEngine->buildSymbolicOperand(inst, src);

        /* Create symbolic expression */
        // triton::logger::info("-- Create symbolic expression");
        auto expr = this->symbolicEngine->createSymbolicExpression(inst, node, dst, "MOV operation");
        // std::cout << "mov_s: expr: " << expr << std::endl;

        /* Spread taint */
        // triton::logger::info("-- Spread taint");
        expr->isTainted = this->taintEngine->taintAssignment(dst, src);

        /* Upate the symbolic control flow */
        // triton::logger::info("-- Upate the symbolic control flow");
        this->controlFlow_s(inst);

        // triton::logger::info("-- End of semantics");
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

#undef UNUSED