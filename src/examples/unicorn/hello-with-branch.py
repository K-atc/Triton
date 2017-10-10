#!/usr/bin/env python2
## -*- coding: utf-8 -*-
from triton import *
from unicorn_tracer import *

DEADENDED_ADDR = [0x100013]
concrete_rax = None

def mycb(inst):
    global concrete_rax
    print "~" * 8
    print inst
    for expr in inst.getSymbolicExpressions():
        print "\t" + str(expr)
    print

    pc = inst.getAddress()
    if pc == 0x10000e: # 0x10000e: cmp rdx, rax
        pass
    if pc == 0x100011:
        pco = getPathConstraints()
        for pc in pco:
            if pc.isMultipleBranches():
                # print hex(pc.getTakenAddress())
                if pc.getTakenAddress() in DEADENDED_ADDR: # 
                    b1 = pc.getBranchConstraints()[0]['constraint']
                    b2 = pc.getBranchConstraints()[1]['constraint']
                    print "b1: " + str(b1)
                    print "b2: " + str(b2)
                    # Branch 1
                    models  = getModel(ast.assert_(b1))
                    for k, v in models.items():
                        symvar = getSymbolicVariableFromId(v.getId())
                        print "%s (%s) = %#x" % (v.getName(), symvar.getComment(), v.getValue())
                        concrete_rax = v.getValue()

                        cur_zf = getAstFromId(getSymbolicRegisterId(REG.ZF))
                        # expr = newSymbolicExpression(ast.equal(cur_zf, ast.bvtrue()))
                        expr = newSymbolicExpression(ast.bvtrue())
                        print "new ZF: " + str(expr)
                        assignSymbolicExpressionToRegister(expr, REG.ZF)
                        processing(inst) # re-evaluate
                    # Branch 2
                    models  = getModel(ast.assert_(b2))
                    for k, v in models.items():
                        print v                

    return

if __name__ == '__main__':
    global concrete_rax
    print "Hello!"
    print "use bin file: src/samples/test/with-branch.bin"

    # Set arch
    setArchitecture(ARCH.X86_64)

    enableMode(MODE.PC_TRACKING_SYMBOLIC, False)

    # Start JIT at the entry point, or insertCall callback won't be called
    startAnalysisFromEntry()

    # Add callback
    insertCall(mycb, INSERT_POINT.BEFORE)

    # init_rsi = convertRegisterToSymbolicVariable(REG.RSI, "init_rsi") # SymVar_0
    # init_rdx = convertRegisterToSymbolicVariable(REG.RDX, "init_rdx") # SymVar_1
    init_rax = convertRegisterToSymbolicVariable(REG.RAX, "init_rax") # SymVar_2

    # setConcreteRegisterValue(Register(REG.RSI, 2)) # NOTE: does not sync with unicorn
    # setConcreteRegisterValue(Register(REG.RDX, 2)) # NOTE: does not sync with unicorn
    setCurrentRegisterValue(REG.RSI, 2)
    setCurrentRegisterValue(REG.RDX, 2)

    taintRegister(REG.RAX)

    print "======== [init state] ========"
    # constraints = ast.assert_(ast.land(
    #     ast.variable(init_rsi) == 2,
    #     ast.variable(init_rdx) == 2
    #     ))
    ### How i add contraints?
    # Run Program
    runProgram()
    print ""

    print "======== [constraints] ========"
    rsi_ast = getAstFromId(getSymbolicRegisterId(REG.RSI))
    rdx_ast = getAstFromId(getSymbolicRegisterId(REG.RDX))
    rax_ast = getAstFromId(getSymbolicRegisterId(REG.RAX))
    print "AST of rsi@last: " + str(rsi_ast)
    print "AST of rdx@last: " + str(rdx_ast)
    print "AST of rax@last: " + str(rax_ast)

    print "======== [assertion] ========"
    # constraints = ast.assert_(ast.land(
    #     ast.variable(init_rsi) == 2,
    #     ast.variable(init_rdx) == 2
    #     ))
    # constraints = ast.assert_(rdx_ast == 1) 
    constraints = ast.assert_(ast.variable(init_rax) == concrete_rax)
    print constraints

    print "======== [solutions] ========"
    models = getModels(constraints, 2) # solver for max 2 solutions
    if not models:
        print "unsat"
    try:
        for (i, m) in enumerate(models):
            print "#%d:" % i
            for (k, v) in m.items():
                symvar = getSymbolicVariableFromId(v.getId())
                print "%s (%s) = %#x" % (v.getName(), symvar.getComment(), v.getValue())
    except Exception, e:
        print "[!] Exception: " + e
        import ipdb; ipdb.set_trace()

