#include <triton/tritonTypes.hpp>
#include <triton/vexLifter.hpp>

#include <iostream>
#include <string.h>
#include <fstream>

#include <python2.7/Python.h>
#include <string>
#include <vector>
#include <map>

#include "lifter.py.inc"

#define tag_str_to_enum(x) if (tag == #x) {return x;}
#define tag_enum_to_str(x) if (tag == x) {return #x;}

template< size_t N >
constexpr size_t length(char const (&)[N]) {
  return N-1;
}
#define compare_tag_and_enum(x) if (tag.compare(0, length(#x), (#x)) == 0)
#define compare_tag_and_enum_with_return(x) compare_tag_and_enum(x) return x;

namespace triton {
    namespace intlibs {
        namespace vexlifter {

vex_abst_iop vex_iop(vex_tag_iop tag) {
    compare_tag_and_enum_with_return(Iop_Invalid);
    compare_tag_and_enum_with_return(Iop_Add);
    compare_tag_and_enum_with_return(Iop_Sub);
    compare_tag_and_enum_with_return(Iop_Mul);
    compare_tag_and_enum_with_return(Iop_MullS);
    compare_tag_and_enum_with_return(Iop_MullU);
    compare_tag_and_enum_with_return(Iop_DivS);
    compare_tag_and_enum_with_return(Iop_DivU);
    compare_tag_and_enum_with_return(Iop_Mod);
    compare_tag_and_enum_with_return(Iop_Or);
    compare_tag_and_enum_with_return(Iop_And);
    compare_tag_and_enum_with_return(Iop_Xor);
    compare_tag_and_enum_with_return(Iop_Shr);
    compare_tag_and_enum_with_return(Iop_Shl);
    compare_tag_and_enum_with_return(Iop_Not);
    compare_tag_and_enum_with_return(Iop_CmpEQ);
    compare_tag_and_enum_with_return(Iop_CmpNE);
    compare_tag_and_enum_with_return(Iop_CmpSLT);
    compare_tag_and_enum_with_return(Iop_CmpSLE);
    compare_tag_and_enum_with_return(Iop_CmpULT);
    compare_tag_and_enum_with_return(Iop_CmpULE);
    compare_tag_and_enum_with_return(Iop_CmpSGE);
    compare_tag_and_enum_with_return(Iop_CmpUGE);
    compare_tag_and_enum_with_return(Iop_CmpSGT);
    compare_tag_and_enum_with_return(Iop_CmpUGT);
    if (tag.find("to") != std::string::npos) {
        if (tag.find("Uto") != std::string::npos) return Iop_CastU;
        if (tag.find("Sto") != std::string::npos) return Iop_CastS;
        if (tag.find("HIto") != std::string::npos) return Iop_CastHI;
        if (tag.find("HLto") != std::string::npos) return Iop_CastHL;
        return Iop_Cast;
    }
    return Iop_Invalid;
}

vex_tag_ist vex_tag_ist_str_to_enum(std::string tag)
{
    tag_str_to_enum(Ist_Jump);
    tag_str_to_enum(Ist_AbiHint);
    tag_str_to_enum(Ist_CAS);
    tag_str_to_enum(Ist_Dirty);
    tag_str_to_enum(Ist_Exit);
    tag_str_to_enum(Ist_IMark);
    tag_str_to_enum(Ist_LLSC);
    tag_str_to_enum(Ist_LoadG);
    tag_str_to_enum(Ist_MBE);
    tag_str_to_enum(Ist_NoOp);
    tag_str_to_enum(Ist_Put);
    tag_str_to_enum(Ist_PutI);
    tag_str_to_enum(Ist_Store);
    tag_str_to_enum(Ist_StoreG);
    tag_str_to_enum(Ist_WrTmp);
    return Ist_Invalid;
}

std::string vex_tag_enum_to_str(vex_tag_ist tag)
{
    tag_enum_to_str(Ist_Jump);
    tag_enum_to_str(Ist_AbiHint);
    tag_enum_to_str(Ist_CAS);
    tag_enum_to_str(Ist_Dirty);
    tag_enum_to_str(Ist_Exit);
    tag_enum_to_str(Ist_IMark);
    tag_enum_to_str(Ist_LLSC);
    tag_enum_to_str(Ist_LoadG);
    tag_enum_to_str(Ist_MBE);
    tag_enum_to_str(Ist_NoOp);
    tag_enum_to_str(Ist_Put);
    tag_enum_to_str(Ist_PutI);
    tag_enum_to_str(Ist_Store);
    tag_enum_to_str(Ist_StoreG);
    tag_enum_to_str(Ist_WrTmp);
    return "Ist_Invalid";
}

vex_tag_iex vex_tag_iex_str_to_enum(std::string tag)
{
    tag_str_to_enum(Iex_Load);
    tag_str_to_enum(Iex_RdTmp);
    tag_str_to_enum(Iex_GetI);
    tag_str_to_enum(Iex_Unop);
    tag_str_to_enum(Iex_Const);
    tag_str_to_enum(Iex_Binop);
    tag_str_to_enum(Iex_Triop);
    tag_str_to_enum(Iex_Get);
    tag_str_to_enum(Iex_CCall);
    tag_str_to_enum(Iex_ITE);
    tag_str_to_enum(Iex_VECRET);
    tag_str_to_enum(Iex_Qop);
    tag_str_to_enum(Iex_GSPTR);
    tag_str_to_enum(Iex_Binder);
    return Iex_Invalid;
}

std::string vex_tag_enum_to_str(vex_tag_iex tag)
{
    tag_enum_to_str(Iex_Load);
    tag_enum_to_str(Iex_RdTmp);
    tag_enum_to_str(Iex_GetI);
    tag_enum_to_str(Iex_Unop);
    tag_enum_to_str(Iex_Const);
    tag_enum_to_str(Iex_Binop);
    tag_enum_to_str(Iex_Triop);
    tag_enum_to_str(Iex_Get);
    tag_enum_to_str(Iex_CCall);
    tag_enum_to_str(Iex_ITE);
    tag_enum_to_str(Iex_VECRET);
    tag_enum_to_str(Iex_Qop);
    tag_enum_to_str(Iex_GSPTR);
    tag_enum_to_str(Iex_Binder);
    return "Iex_Invalid";
}

vex_ir_ity vex_ir_ity_str_to_enum(std::string tag)
{
    tag_str_to_enum(Ity_F64);
    tag_str_to_enum(Ity_I32);
    tag_str_to_enum(Ity_I16);
    tag_str_to_enum(Ity_F32);
    tag_str_to_enum(Ity_I64);
    tag_str_to_enum(Ity_V128);
    tag_str_to_enum(Ity_V256);
    tag_str_to_enum(Ity_I1);
    tag_str_to_enum(Ity_I8);
    return Ity_Invalid;
}

std::string vex_tag_enum_to_str(vex_ir_ity tag)
{
    tag_enum_to_str(Ity_F64);
    tag_enum_to_str(Ity_I32);
    tag_enum_to_str(Ity_I16);
    tag_enum_to_str(Ity_F32);
    tag_enum_to_str(Ity_I64);
    tag_enum_to_str(Ity_V128);
    tag_enum_to_str(Ity_V256);
    tag_enum_to_str(Ity_I1);
    tag_enum_to_str(Ity_I8);
    return "Ity_Invalid";
}

std::string vex_tag_enum_to_str(vex_ir_ijk tag)
{
    tag_enum_to_str(Ijk_Boring);
    tag_enum_to_str(Ijk_Call);
    tag_enum_to_str(Ijk_Ret);
    tag_enum_to_str(Ijk_ClientReq);
    tag_enum_to_str(Ijk_Yield);
    tag_enum_to_str(Ijk_EmWarn);
    tag_enum_to_str(Ijk_EmFail);
    tag_enum_to_str(Ijk_NoDecode);
    tag_enum_to_str(Ijk_MapFail);
    tag_enum_to_str(Ijk_InvalICache);
    tag_enum_to_str(Ijk_FlushDCache);
    tag_enum_to_str(Ijk_NoRedir);
    tag_enum_to_str(Ijk_SigILL);
    tag_enum_to_str(Ijk_SigTRAP);
    tag_enum_to_str(Ijk_SigSEGV);
    tag_enum_to_str(Ijk_SigBUS);
    tag_enum_to_str(Ijk_SigFPE_IntDiv);
    tag_enum_to_str(Ijk_SigFPE_IntOvf);
    tag_enum_to_str(Ijk_Sys_syscall);
    tag_enum_to_str(Ijk_Sys_int32);
    tag_enum_to_str(Ijk_Sys_int128);
    tag_enum_to_str(Ijk_Sys_int129);
    tag_enum_to_str(Ijk_Sys_int130);
    tag_enum_to_str(Ijk_Sys_int145);
    tag_enum_to_str(Ijk_Sys_int210);
    tag_enum_to_str(Ijk_Sys_sysenter);
    return "Ijk_Invalid";
}

vex_ir_ijk vex_ijk_str_to_enum(std::string tag)
{
    tag_str_to_enum(Ijk_Boring);
    tag_str_to_enum(Ijk_Call);
    tag_str_to_enum(Ijk_Ret);
    tag_str_to_enum(Ijk_ClientReq);
    tag_str_to_enum(Ijk_Yield);
    tag_str_to_enum(Ijk_EmWarn);
    tag_str_to_enum(Ijk_EmFail);
    tag_str_to_enum(Ijk_NoDecode);
    tag_str_to_enum(Ijk_MapFail);
    tag_str_to_enum(Ijk_InvalICache);
    tag_str_to_enum(Ijk_FlushDCache);
    tag_str_to_enum(Ijk_NoRedir);
    tag_str_to_enum(Ijk_SigILL);
    tag_str_to_enum(Ijk_SigTRAP);
    tag_str_to_enum(Ijk_SigSEGV);
    tag_str_to_enum(Ijk_SigBUS);
    tag_str_to_enum(Ijk_SigFPE_IntDiv);
    tag_str_to_enum(Ijk_SigFPE_IntOvf);
    tag_str_to_enum(Ijk_Sys_syscall);
    tag_str_to_enum(Ijk_Sys_int32);
    tag_str_to_enum(Ijk_Sys_int128);
    tag_str_to_enum(Ijk_Sys_int129);
    tag_str_to_enum(Ijk_Sys_int130);
    tag_str_to_enum(Ijk_Sys_int145);
    tag_str_to_enum(Ijk_Sys_int210);
    tag_str_to_enum(Ijk_Sys_sysenter);
    return Ijk_Invalid;
}

vex_ir_endness vex_ir_endness_str_to_enum(std::string tag)
{
    tag_str_to_enum(Iend_LE);
    tag_str_to_enum(Iend_BE);
    return Iend_Invalid;
}

std::string vex_tag_enum_to_str(vex_ir_endness tag)
{
    tag_enum_to_str(Iend_LE);
    tag_enum_to_str(Iend_BE);
    return "Iend_Invalid";
}

vex_tag_ico vex_tag_ico_str_to_enum(std::string tag)
{
    tag_str_to_enum(Ico_F32);
    tag_str_to_enum(Ico_F32i);
    tag_str_to_enum(Ico_F64);
    tag_str_to_enum(Ico_F64i);
    tag_str_to_enum(Ico_U1);
    tag_str_to_enum(Ico_U16);
    tag_str_to_enum(Ico_U32);
    tag_str_to_enum(Ico_U64);
    tag_str_to_enum(Ico_U8);
    tag_str_to_enum(Ico_V128);
    tag_str_to_enum(Ico_V256);
    return Ico_Invalid;
}

std::string vex_tag_enum_to_str(vex_tag_ico tag)
{
    tag_enum_to_str(Ico_Invalid);
    tag_enum_to_str(Ico_F32);
    tag_enum_to_str(Ico_F32i);
    tag_enum_to_str(Ico_F64);
    tag_enum_to_str(Ico_F64i);
    tag_enum_to_str(Ico_U1);
    tag_enum_to_str(Ico_U16);
    tag_enum_to_str(Ico_U32);
    tag_enum_to_str(Ico_U64);
    tag_enum_to_str(Ico_U8);
    tag_enum_to_str(Ico_V128);
    tag_enum_to_str(Ico_V256);
    return "Ico_Invalid";
}

std::string vex_tag_enum_to_str(vex_abst_iop tag)
{
    tag_enum_to_str(Iop_Add);
    tag_enum_to_str(Iop_Sub);
    tag_enum_to_str(Iop_Mul);
    tag_enum_to_str(Iop_MullS);
    tag_enum_to_str(Iop_MullU);
    tag_enum_to_str(Iop_DivS);
    tag_enum_to_str(Iop_DivU);
    tag_enum_to_str(Iop_Mod);
    tag_enum_to_str(Iop_Or);
    tag_enum_to_str(Iop_And);
    tag_enum_to_str(Iop_Xor);
    tag_enum_to_str(Iop_Shr);
    tag_enum_to_str(Iop_Shl);
    tag_enum_to_str(Iop_Not);
    tag_enum_to_str(Iop_CmpEQ);
    tag_enum_to_str(Iop_CmpNE);
    tag_enum_to_str(Iop_CmpSLT);
    tag_enum_to_str(Iop_CmpSLE);
    tag_enum_to_str(Iop_CmpULT);
    tag_enum_to_str(Iop_CmpULE);
    tag_enum_to_str(Iop_CmpSGE);
    tag_enum_to_str(Iop_CmpUGE);
    tag_enum_to_str(Iop_CmpSGT);
    tag_enum_to_str(Iop_CmpUGT);
    tag_enum_to_str(Iop_Cast);
    tag_enum_to_str(Iop_CastU);
    tag_enum_to_str(Iop_CastS);
    tag_enum_to_str(Iop_CastHI);
    tag_enum_to_str(Iop_CastHL);
    return "Iop_Invalid";
}

std::string vex_repr_itype(triton::uint32 type) {
    triton::uint32 ist = type / VEX_IST_BASE;
    type -= ist * VEX_IST_BASE;
    triton::uint32 iex = type / VEX_IEX_BASE;
    type -= iex * VEX_IEX_BASE;
    triton::uint32 iop = type / VEX_IOP_BASE;
    std::ostringstream str;
    str <<
        vex_tag_enum_to_str((vex_tag_ist)(ist)) <<
        "|" <<
        vex_tag_enum_to_str((vex_tag_iex)(iex)) <<
        "|" <<
        vex_tag_enum_to_str((vex_abst_iop)(iop));
    return str.str();
}

void print_vex_const(vex_const vconst, char* prefix)
{
    if (vconst.tag == Ico_Invalid) return;
    printf("\t%stag = %s\n", prefix, vex_tag_enum_to_str(vconst.tag).c_str());
    printf("\t%ssize = %d\n", prefix, vconst.size);
    printf("\t%svalue = 0x%x\n", prefix, vconst.value);
}

void print_vex_expr(vex_expr expr, char* prefix)
{
    printf("\t%stag = %s\n", prefix, vex_tag_enum_to_str(expr.tag).c_str());
    if (expr.tag == Iex_Invalid) return;
    printf("\t%scon = 0x%x\n", prefix, expr.con);
    printf("\t%stmp = %d\n", prefix, expr.tmp);
    printf("\t%soffset = 0x%x\n", prefix, expr.offset);
    printf("\t%sresult_size = %d\n", prefix, expr.result_size);
    printf("\t%sty = %s\n", prefix, vex_tag_enum_to_str(expr.ty).c_str());
}

void print_vex_insn_data(vex_data data, char* prefix)
{
    if (data.tag == Iex_Invalid && data.op == "Iop_Invalid") return;
    print_vex_expr(static_cast<vex_expr> (data), (char *) prefix);
    // if (data.tag == Iex_Load) {
        print_vex_expr(data.addr, (char *) "data.addr.");
    // }
    printf("\t%sop = %s\n", prefix, data.op.c_str());
    printf("\t%snargs = %d\n", prefix, data.nargs);
    if (data.endness != Iend_Invalid) {
        printf("\t%sendness = %s\n", prefix, vex_tag_enum_to_str(data.endness).c_str());
    }
    for (int i = 0; i < data.nargs; i++) {
        char prefix2[128] = "";
        snprintf(prefix2, sizeof(prefix2), "%sargs[%d].", prefix, i);
        print_vex_expr(data.args[i], prefix2);
    }
}

void print_vex_insn(vex_insn insn)
{
    printf("%s\n", insn.full.c_str());
    // printf("\ttype = 0x%x\n", vex_itype(insn.tag, insn.data.tag, vex_iop(insn.data.op)));
    printf("\ttype = %s\n", vex_repr_itype(vex_itype(insn.tag, insn.data.tag, vex_iop(insn.data.op))).c_str());
    printf("\ttag = %s\n", vex_tag_enum_to_str(insn.tag).c_str());
    printf("\toffset = %d\n", insn.offset);
    if (insn.tag == Ist_Store) {
        print_vex_expr(insn.addr_expr, (char *) "addr.");
        printf("\tendness = %s\n", vex_tag_enum_to_str(insn.endness).c_str());
    }
    printf("\ttmp = %d\n", insn.tmp);
    print_vex_insn_data(insn.data, (char *) "data.");
    if (insn.tag == Ist_IMark) {
        printf("\tdisasm = %s\n", insn.disasm.c_str());
        printf("\taddr = 0x%x\n", insn.addr);
        printf("\tlen = %d\n", insn.len);
    }
    if (insn.tag == Ist_Exit || insn.tag == Ist_Jump) {
        printf("\tjumpkind = %s\n", vex_tag_enum_to_str(insn.jumpkind).c_str());
    }
    if (insn.tag == Ist_Exit) {
        print_vex_expr(insn.guard, (char *) "guard.");
        printf("\toffsIP = %d\n", insn.offsIP);
        print_vex_const(insn.dst, (char *) "dst.");
    }
}

void print_vex_insns(vex_insns insns)
{
    for (auto &insn : insns) {
        print_vex_insn(insn);
    }
}

void print_vex_insns_group(vex_insns_group &insns_group)
{
    for(auto itr = insns_group.begin(); itr != insns_group.end(); ++itr) {
        puts("");
        printf("*** [address = 0x%lx] ***\n", itr->first);
        print_vex_insns(itr->second);
    }
}

void set_const(vex_const *insn, PyObject *obj)
{
    PyObject *v = nullptr;
    v = PyDict_GetItemString(obj, "tag");
    if (v) insn->tag = vex_tag_ico_str_to_enum(PyString_AsString(v));
    //// Py_XDECREF(v);
    v = PyDict_GetItemString(obj, "size");
    if (v) insn->size = PyLong_AsUnsignedLong(v);
    //// Py_XDECREF(v);
    v = PyDict_GetItemString(obj, "value");
    if (v) insn->value = PyLong_AsUnsignedLong(v);
    //// Py_XDECREF(v);
}

void set_expr(vex_expr *insn, PyObject *obj)
{
    PyObject *v = nullptr;
    v = PyDict_GetItemString(obj, "tag");
    if (v) insn->tag = vex_tag_iex_str_to_enum(PyString_AsString(v));
    //// Py_XDECREF(v);
    v = PyDict_GetItemString(obj, "tmp");
    if (v) insn->tmp = PyInt_AsLong(v);
    //// Py_XDECREF(v);
    v = PyDict_GetItemString(obj, "con");
    if (v) insn->con = PyInt_AsLong(v);
    //// Py_XDECREF(v);
    v = PyDict_GetItemString(obj, "offset");
    if (v) insn->offset = PyInt_AsLong(v);
    //// Py_XDECREF(v);
    v = PyDict_GetItemString(obj, "result_size");
    if (v) insn->result_size = PyInt_AsLong(v);
    //// Py_XDECREF(v);
}

bool vex_lift(vex_insns_group *insns_group, unsigned char *insns_bytes, triton::uint64 start_addr, triton::uint64 count)
{
    PyObject *main, *global, *func;

    if (!Py_IsInitialized()) {
        fprintf(stderr, "error: Py_Initialize() must be called beforehand.\n");
        exit(1);
    }

    // Load Helper Script
    PyRun_SimpleString(script);

    // Get ref of function
    main = PyImport_ImportModule("__main__");
    global = PyModule_GetDict(main);
    func = PyDict_GetItemString(global, "Lift");

    setvbuf(stdout, NULL, _IONBF, 0);
    if (PyCallable_Check(func)) // Checks if we got ref
    {
        // Do Lift
        Py_ssize_t insns_bytes_size = PyLong_AsSsize_t(PyLong_FromLong(count));
        PyObject* pArg1 = PyBytes_FromStringAndSize((const char*) insns_bytes, insns_bytes_size);
        PyObject* pArg2 = PyLong_FromLong(start_addr);
        PyObject* pArgs = PyTuple_New(2);
        PyTuple_SetItem(pArgs, 0, pArg1);
        PyTuple_SetItem(pArgs, 1, pArg2);
        PyObject* ans = PyObject_CallObject(func, pArgs);
        if (ans)
        {
            if (PyList_Check(ans)) {
                unsigned int current_addr = 0;
                for(Py_ssize_t i = 0; i < PyList_Size(ans); i++) {
                    PyObject *item = PyList_GetItem(ans, i);
                    vex_insn insn;
                    PyObject *v = nullptr;
                    PyObject *data = nullptr;
                    PyObject *args = nullptr;
                    v = PyDict_GetItemString(item, "full");
                    if (v) insn.full = PyString_AsString(v);
                    //// Py_XDECREF(v);
                    // std::cout << insn.full << std::endl; /* for debug */
                    v = PyDict_GetItemString(item, "disasm");
                    if (v) insn.disasm = PyString_AsString(v);
                    //// Py_XDECREF(v);
                    v = PyDict_GetItemString(item, "tag");
                    if (v) insn.tag = vex_tag_ist_str_to_enum(PyString_AsString(v));
                    //// Py_XDECREF(v);
                    v = PyDict_GetItemString(item, "tmp");
                    if (v) insn.tmp = PyInt_AsLong(v);
                    //// Py_XDECREF(v);
                    v = PyDict_GetItemString(item, "offset");
                    if (v) insn.offset = PyInt_AsLong(v);
                    //// Py_XDECREF(v);
                    v = PyDict_GetItemString(item, "addr");
                    if (v) insn.addr = PyInt_AsLong(v);
                    //// Py_XDECREF(v);
                    v = PyDict_GetItemString(item, "len");
                    if (v) insn.len = PyInt_AsLong(v);
                    //// Py_XDECREF(v);
                    v = PyDict_GetItemString(item, "jumpkind");
                    if (v) insn.jumpkind = vex_ijk_str_to_enum(PyString_AsString(v));
                    //// Py_XDECREF(v);
                    v = PyDict_GetItemString(item, "dst");
                    if (v) set_const(&insn.dst, v);
                    //// Py_XDECREF(v);
                    v = PyDict_GetItemString(item, "offsIP");
                    if (v) insn.offsIP = PyInt_AsLong(v);
                    //// Py_XDECREF(v);
                    v = PyDict_GetItemString(item, "endness");
                    if (v) insn.endness = vex_ir_endness_str_to_enum(PyString_AsString(v));
                    //// Py_XDECREF(v);
                    v = PyDict_GetItemString(item, "guard");
                    if (v) set_expr(&insn.guard, v);
                    //// Py_XDECREF(v);
                    v = PyDict_GetItemString(item, "addr_expr");
                    if (v) set_expr(&insn.addr_expr, v);
                    //// Py_XDECREF(v);
                    data = PyDict_GetItemString(item, "data");
                    if (data) {
                        v = PyDict_GetItemString(data, "tag");
                        if (v) insn.data.tag = vex_tag_iex_str_to_enum(PyString_AsString(v));
                        //// Py_XDECREF(v);
                        v = PyDict_GetItemString(data, "addr");
                        if (v) set_expr(&insn.data.addr, v);
                        //// Py_XDECREF(v);
                        v = PyDict_GetItemString(data, "ty");
                        if (v) insn.data.ty = vex_ir_ity_str_to_enum(PyString_AsString(v));
                        //// Py_XDECREF(v);
                        v = PyDict_GetItemString(data, "endness");
                        if (v) insn.data.endness = vex_ir_endness_str_to_enum(PyString_AsString(v));
                        //// Py_XDECREF(v);
                        v = PyDict_GetItemString(data, "op");
                        if (v) insn.data.op = PyString_AsString(v);
                        //// Py_XDECREF(v);
                        v = PyDict_GetItemString(data, "tmp");
                        if (v) insn.data.tmp = PyInt_AsLong(v);
                        //// Py_XDECREF(v);
                        v = PyDict_GetItemString(data, "con");
                        if (v) insn.data.con = PyInt_AsLong(v);
                        //// Py_XDECREF(v);
                        v = PyDict_GetItemString(data, "offset");
                        if (v) insn.data.offset = PyInt_AsLong(v);
                        //// Py_XDECREF(v);
                        v = PyDict_GetItemString(data, "result_size");
                        if (v) insn.data.result_size = PyInt_AsLong(v);
                        //// Py_XDECREF(v);
                        args = PyDict_GetItemString(data, "args");
                        if (args) {
                            insn.data.nargs = PyList_Size(args);
                            for(Py_ssize_t j = 0; j < PyList_Size(args); j++) {
                                PyObject *args_j = PyList_GetItem(args, j);
                                set_expr(&insn.data.args[j], args_j);
                                if (insn.data.args[j].result_size == 0) {
                                    insn.data.args[j].result_size = insn.data.result_size; // fix result_size of args
                                }
                                // Py_XDECREF(args_j);
                            }
                            // Py_XDECREF(args);
                        }
                        // Py_XDECREF(data);
                    }
                    // Py_XDECREF(item);

                    if (insn.tag == Ist_IMark) {
                        current_addr = insn.addr;
                        (*insns_group)[current_addr].push_back(insn);
                    }
                    else {
                        (*insns_group)[current_addr].push_back(insn);
                    }

                }
            } else {
                fprintf(stderr, "Passed pointer of PyObject was not a list or tuple!");
            }
            Py_DECREF(ans);
        }
        Py_DECREF(pArgs);
        // Py_DECREF(pArg1);
        // Py_DECREF(pArg2);
    }
    else {
        fprintf(stderr, "error: There're no handle for lift function.\n");
        return false;
    }

    Py_DECREF(main);
    // Py_DECREF(global);
    // Py_DECREF(func);

    return true;
}

void vex_lift_init(void)
{
    // Invoke Python Interpreter
    if (!Py_IsInitialized()) {
        Py_Initialize();
    }

    // Load required modules
    PyRun_SimpleString(
        "import pyvex\n"
        "import archinfo\n"
        "import capstone\n"
        "import hexdump\n"
        );
}


void vex_lift_finilize(void)
{
    // Terminate Interpreter
    Py_Finalize();
}

        }
    }
}