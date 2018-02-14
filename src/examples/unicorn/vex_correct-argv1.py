## -*- coding: utf-8 -*-
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

def user_logger(msg):
    print '[user:info] ' + str(msg)

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
    print("\n")
    if False:
        print "~" * 8
        print inst
        for expr in inst.getSymbolicExpressions():
            print "\t" + str(expr)
        print "rax: %#x" % getConcreteRegisterValue(REG_RAX)
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
        ans = []
        for i, pc in enumerate(pco):
            if pc.isMultipleBranches():
                print "#%d: takenAdress = %#x (%#x)" % (i, pc.getTakenAddress(), rel_addr(pc.getTakenAddress()))
                if pc.getTakenAddress() in [fail_addr]:
                    # b1 = pc.getBranchConstraints()[0]['constraint']
                    b2 = pc.getBranchConstraints()[1]['constraint']
                    # print "b1: " + str(b1)
                    print "b2: " + str(b2)
                    # print "b2.childs: \n" + '\n'.join(['\t' + str(x) for x in b2.getChilds()])
                    print "b2.isSymbolized(): " + str(b2.isSymbolized())

                    import ipdb; ipdb.set_trace()

                    # Branch 2 (False Branch; Jump not-taken Branch)
                    ### (error "line 1 column 935: Sorts Bool and (_ BitVec 1) are incompatible")
                    models = getModel(ast.assert_(b2))
                    # models = getModel(ast.assert_(ast.equal(ast.bvtrue(), ast.bvtrue()))) # no problem
                    if len(models.items()) > 0:
                        for k, v in models.items():
                            symvar = getSymbolicVariableFromId(v.getId())
                            print "%s (%s) = %#x" % (v.getName(), symvar.getComment(), v.getValue())
                            ans += [v.getValue()]
                        print "[user:info] " + ''.join([chr(x) for x in ans])
        exit(1)
    return

if __name__ == '__main__':
    global argv1, known_flag
    global REG_RDI, REG_RSI, REG_RDX, REG_RAX, REG_RSP
    argv1_ptr = 0x7f0000
    argv1 = 0x400000

    # Setup argv
    argv = argv[2:]
    user_logger(str(argv))

    # Set arch
    setArchitecture(ARCH.VEX_X86_64)

    # Generate registers
    ai = archinfo.ArchAMD64()
    REG_RDI = Register(ai.registers["rdi"][0], 0)
    REG_RSI = Register(ai.registers["rsi"][0], 0)
    REG_RDX = Register(ai.registers["rdx"][0], 0)
    REG_RAX = Register(ai.registers["rax"][0], 0)
    REG_RSP = Register(ai.registers["rsp"][0], 0)

    # import ipdb; ipdb.set_trace()

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
    print(REG.RSP)
    setCurrentRegisterValue(REG.RSP, argv1_ptr - 0x18)
    setConcreteMemoryValue(MemoryAccess(argv1_ptr, CPUSIZE.DWORD, argv1)) # mov dword [argv1_ptr], argv1

    # Symblize argv[1]
    setCurrentRegisterValue(REG.RAX, argv1)
    for offset in range(4 * 4):
        convertMemoryToSymbolicVariable(MemoryAccess(argv1 + offset, CPUSIZE.BYTE))
    # for i in range(8):
    #     setConcreteMemoryValue(MemoryAccess(argv1 + i, CPUSIZE.BYTE, ord("flag{it\'s"[i])))
    known_flag = ""
    if len(argv) > 1:
        known_flag = argv[1]
        for i in range(len(known_flag)):
            setConcreteMemoryValue(MemoryAccess(argv1 + i, CPUSIZE.BYTE, ord(known_flag[i])))

    # Run Program
    runProgram()

    print "[*] anaysis finished"