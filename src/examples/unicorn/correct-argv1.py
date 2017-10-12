#!/usr/bin/env python2
## -*- coding: utf-8 -*-
from triton import *
from unicorn_tracer import *
from sys import argv

syscall_table = {
    0: ("sys_read", 3),
    1: ("sys_write", 3),
    2: ("sys_open", 3),
    3: ("sys_close", 1),
    60: ("sys_exit", 1),
}

def abs_addr(rel_addr):
    return rel_addr - 0x400080 + 0x100000

def rel_addr(abs_addr):
    return abs_addr + 0x400080 - 0x100000    

def handle_syscall(thread_id, syscall_no):
    global syscall_table
    rdi = getConcreteRegisterValue(REG.RDI)
    rsi = getConcreteRegisterValue(REG.RSI)
    rdx = getConcreteRegisterValue(REG.RDX)
    syscall_name, num_reg = syscall_table[syscall_no]
    print ">>> syscall(%d) %s, rdi=%#x, rsi=%#x, rdx=%#x" % (syscall_no, syscall_name, rdi, rsi, rdx)
    if syscall_name == "sys_exit":
        stopProgram()

def mycb(inst):
    global argv1, known_flag
    if False:
        print "~" * 8
        print inst
        for expr in inst.getSymbolicExpressions():
            print "\t" + str(expr)
        print "rax: %#x" % getConcreteRegisterValue(REG.RAX)
        print
    
    succ_addr = abs_addr(0x4000d6)
    fail_addr = abs_addr(0x4000e7)
    pc = inst.getAddress()
    # print "pc = %#x (rel=%#x)" % (pc, rel_addr(pc))
    if pc == succ_addr:
        print "\033[33m" + "[*] FLAG FOUND!! %s" % known_flag + "\033[0m"
        exit(0)
    if pc == fail_addr:
        pco = getPathConstraints()
        print pco
        ans = []
        for pc in pco:
            if pc.isMultipleBranches():
                # print "takenAdress = %#x (%#x)" % (pc.getTakenAddress(), rel_addr(pc.getTakenAddress()))
                if pc.getTakenAddress() in [fail_addr]:
                    b1 = pc.getBranchConstraints()[0]['constraint']
                    b2 = pc.getBranchConstraints()[1]['constraint']
                    # print "b1: " + str(b1)
                    # print "b2: " + str(b2)
                    # # Branch 1 (True Branch; Jump taken Branch)
                    # ans = []
                    # models = getModel(ast.assert_(b1))
                    # for k, v in models.items():
                    #     symvar = getSymbolicVariableFromId(v.getId())
                    #     print "%s (%s) = %#x" % (v.getName(), symvar.getComment(), v.getValue())
                    #     ans += [v.getValue()]
                    # print "[user:info] " + ''.join([chr(x) for x in ans])
                    # Branch 2 (False Branch; Jump not-taken Branch)
                    models = getModel(ast.assert_(b2))
                    for k, v in models.items():
                        symvar = getSymbolicVariableFromId(v.getId())
                        print "%s (%s) = %#x" % (v.getName(), symvar.getComment(), v.getValue())
                        ans += [v.getValue()]
                    print "[user:info] " + ''.join([chr(x) for x in ans])                    
        exit(1)
    return

if __name__ == '__main__':
    global argv1, known_flag
    argv1_ptr = 0x7f0000
    argv1 = 0x400000

    argv = argv[2:]
    print '[user:info] ' + str(argv)

    # Set arch
    setArchitecture(ARCH.X86_64)

    enableMode(MODE.PC_TRACKING_SYMBOLIC, False)

    # Start JIT at the entry point, or insertCall callback won't be called
    startAnalysisFromEntry()

    # Fix entry address
    start_addr = abs_addr(0x4000ae)
    startAnalysisFromAddress(start_addr) # mark analysisTrigger.update(true) in callback::preProcessing()
    setEmuStartAddr(start_addr)

    # Add callback
    insertCall(mycb, INSERT_POINT.BEFORE)
    insertCall(handle_syscall, INSERT_POINT.SYSCALL_ENTRY)

    # Fake stack
    setCurrentRegisterValue(REG.RSP, argv1_ptr - 0x18)
    setConcreteMemoryValue(MemoryAccess(argv1_ptr, CPUSIZE.DWORD, argv1)) # mov dword [argv1_ptr], argv1

    # Symblize argv[1]
    setCurrentRegisterValue(REG.RAX, argv1)
    for offset in range(4 * 4):
        convertMemoryToSymbolicVariable(MemoryAccess(argv1 + offset, CPUSIZE.BYTE))
    for i in range(8):
        setConcreteMemoryValue(MemoryAccess(argv1 + i, CPUSIZE.BYTE, ord("flag{it\'s"[i])))        
    known_flag = ""
    if len(argv) > 1:
        known_flag = argv[1]
        for i in range(len(known_flag)):
            setConcreteMemoryValue(MemoryAccess(argv1 + i, CPUSIZE.BYTE, ord(known_flag[i])))

    # Run Program
    runProgram()

    print "[*] anaysis finished"