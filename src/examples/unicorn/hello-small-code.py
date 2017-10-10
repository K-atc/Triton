#!/usr/bin/env python2
## -*- coding: utf-8 -*-
from triton import *
from unicorn_tracer import *

def mycb(inst):
    print "~" * 8
    print inst
    for expr in inst.getSymbolicExpressions():
        print "\t" + str(expr)
    print
    return

if __name__ == '__main__':
    print "Hello!"
    print "use bin file: src/samples/test/small-code.bin"

    # Set arch
    setArchitecture(ARCH.X86_64)

    # Start JIT at the entry point, or insertCall callback won't be called
    startAnalysisFromEntry()

    # Add callback
    insertCall(mycb, INSERT_POINT.BEFORE)

    init_rdi = convertRegisterToSymbolicVariable(REG.RDI, "init_rdi") # SymVar_0
    init_rsi = convertRegisterToSymbolicVariable(REG.RSI, "init_rsi") # SymVar_1
    print (init_rdi, init_rsi)

    # Run Program
    runProgram()
    print ""

    print "======== [constraints] ========"
    rdi_ast = getAstFromId(getSymbolicRegisterId(REG.RDI))
    rsi_ast = getAstFromId(getSymbolicRegisterId(REG.RSI))
    print "AST of rdi@last: " + str(rdi_ast)
    print "AST of rsi@last: " + str(rsi_ast)

    print "======== [assertion] ========"
    # constraints = ast.assert_(ast.land(
    #     ast.variable(init_rsi) == 4,
    #     rdi_ast == 2
    #     ))
    constraints = ast.assert_(rdi_ast == 1) # => SymVar_0 = 0x3
    # constraints = ast.assert_(ast.variable(init_rdi) == 3) # => SymVar_0 = 0x3
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

