# -*- coding: utf-8 -*-
from triton import *
from unicorn_tracer import *
from sys import argv
import archinfo

syscall_table = {
    0: ("sys_read", 3),
    1: ("sys_write", 3),
    2: ("sys_open", 3),
    3: ("sys_close", 1),
    60: ("sys_exit", 1),
}

def yellow_str(msg):
    return "\033[33m" + msg + "\033[0m"

def user_logger(msg):
    print('[user:info] {}'.format(msg))

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
    print(">>> syscall(%d) %s, rdi=%#x, rsi=%#x, rdx=%#x" % (syscall_no, syscall_name, rdi, rsi, rdx))
    if syscall_name == "sys_exit":
        stopProgram()

def mycb(inst):
    global argv1, known_flag

    succ_addr = abs_addr(0x4000d6)
    fail_addr = abs_addr(0x4000e7)
    inst_addr = inst.getAddress()
    flag = []

    if inst_addr == succ_addr: # Reached to success state
        print(yellow_str("[*] FLAG FOUND!! %s" % known_flag))
        exit(0)
    if inst_addr == fail_addr: # Reached to fail state
        pco = getPathConstraints()
        for i, pc in enumerate(pco):
            if pc.isMultipleBranches():
                ### Iterate branch conditions of this path constraint
                for j, br in enumerate(pc.getBranchConstraints()):
                    # if br['constraint'].isSymbolized():
                    #     # print "pc[%d]: #%d.: %s" % (i, j, br)
                    #     print "pc[%d]: #%d.dstAddr: %#x (%d)" % (i, j, br['dstAddr'], br['dstAddr'])
                    #     print "pc[%d]: #%d.isTaken: %s" % (i, j, br['isTaken'])
                    #     print "pc[%d]: #%d.constraint: %s" % (i, j, br['constraint'])
                    #     print "pc[%d]: #%d.isSymbolized: %s" % (i, j, br['constraint'].isSymbolized())

                    ### Inspect jump not taken branch
                    if br['isTaken'] is False and br['constraint'].isSymbolized():
                        models = getModel(ast.assert_(br['constraint']))
                        if len(models.items()) > 0:
                            for k, v in models.items():
                                symvar = getSymbolicVariableFromId(v.getId())
                                print "%s (%s) = %#x" % (v.getName(), symvar.getComment(), v.getValue())
                                flag += [v.getValue()]
                            user_logger("flag found: %r" % ''.join([chr(x) for x in flag]))
                            ### continue looping to find remain flag...
                        else:
                            user_logger("no solutions\n")
        if len(flag):
            exit()
    return

if __name__ == '__main__':
    global argv1, known_flag
    global REG_RDI, REG_RSI, REG_RDX, REG_RAX, REG_RSP
    argv1_ptr = 0x7f0000
    argv1 = 0x400000

    # Setup argv
    argv = argv[2:]
    user_logger(str(argv))

    # Setup arch
    setArchitecture(ARCH.VEX_X86_64)

    # Generate registers
    ai = archinfo.ArchAMD64()
    REG_RDI = Register(ai.registers["rdi"][0], 0)
    REG_RSI = Register(ai.registers["rsi"][0], 0)
    REG_RDX = Register(ai.registers["rdx"][0], 0)
    REG_RAX = Register(ai.registers["rax"][0], 0)
    REG_RSP = Register(ai.registers["rsp"][0], 0)

    enableMode(MODE.PC_TRACKING_SYMBOLIC, False)

    # Start JIT at the entry point, or insertCall callback won't be called
    startAnalysisFromEntry()

    # Fix entry address
    start_addr = abs_addr(0x4000ae)
    startAnalysisFromAddress(start_addr) # NOTE: mark analysisTrigger.update(true) in callback::preProcessing()
    setEmuStartAddr(start_addr)

    # Add callback
    insertCall(mycb, INSERT_POINT.BEFORE)
    insertCall(handle_syscall, INSERT_POINT.SYSCALL_ENTRY)

    # Prepare fake stack
    print(REG.RSP)
    setCurrentRegisterValue(REG.RSP, argv1_ptr - 0x18)
    setConcreteMemoryValue(MemoryAccess(argv1_ptr, CPUSIZE.DWORD, argv1)) # `mov dword [argv1_ptr], argv1`

    # Symbolize argv[1]
    setCurrentRegisterValue(REG.RAX, argv1)
    for offset in range(4 * 4):
        convertMemoryToSymbolicVariable(MemoryAccess(argv1 + offset, CPUSIZE.BYTE))
    known_flag = ""
    if len(argv) > 1:
        known_flag = argv[1]
        for i in range(len(known_flag)):
            setConcreteMemoryValue(MemoryAccess(argv1 + i, CPUSIZE.BYTE, ord(known_flag[i])))

    # Run Program
    runProgram()

    print "[*] analysis finished"