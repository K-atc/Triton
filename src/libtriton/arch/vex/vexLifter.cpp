#include <triton/vexLifter.hpp>

#include <stdio.h>
#include <python2.7/Python.h>
#include <string>
#include <vector>
#include <map>

#include "lifter.py.inc"

#define tag_str_to_enum(x) if (tag == #x) {return x;}
#define tag_enum_to_str(x) if (tag == x) {return #x;}

namespace triton { 
    namespace intlibs {
        namespace vexlifter {

            vex_tag_ist vex_tag_ist_str_to_enum(std::string tag)
            {
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

            vex_tag_ity vex_tag_ity_str_to_enum(std::string tag)
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

            std::string vex_tag_enum_to_str(vex_tag_ity tag)
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

            void print_vex_expr(vex_expr expr, char* prefix)
            {
                if (expr.tag == Iex_Invalid) return;
                printf("\t%s.tag = %s\n", prefix, vex_tag_enum_to_str(expr.tag).c_str());
                printf("\t%s.con = 0x%x\n", prefix, expr.con);
                printf("\t%s.tmp = %d\n", prefix, expr.tmp);
                printf("\t%s.offset = 0x%x\n", prefix, expr.offset);
            }

            void print_vex_insn_data(vex_data data, char* prefix)
            {
                if (data.tag == Iex_Invalid && data.op == "Iop_Invalid") return;
                printf("\t%s.tag = %s\n", prefix, vex_tag_enum_to_str(data.tag).c_str());
                printf("\t%s.ty = %s\n", prefix, vex_tag_enum_to_str(data.ty).c_str());
                printf("\t%s.op = %s\n", prefix, data.op.c_str());
                printf("\t%s.con = 0x%x\n", prefix, data.con);
                printf("\t%s.tmp = %d\n", prefix, data.tmp);
                printf("\t%s.offset = 0x%x\n", prefix, data.offset);
                printf("\t%s.nargs = %d\n", prefix, data.nargs);
                for (int i = 0; i < data.nargs; i++) {
                    char prefix2[128] = "";
                    snprintf(prefix2, sizeof(prefix2), "%s.args[%d]", prefix, i);
                    print_vex_expr(data.args[i], prefix2);
                }
            }

            void print_vex_insns(vex_insns insns)
            {
                for (auto &insn : insns) {
                    printf("%s\n", insn.full.c_str());
                    printf("\ttag = %s\n", vex_tag_enum_to_str(insn.tag).c_str());
                    printf("\toffset = %d\n", insn.offset);
                    print_vex_insn_data(insn.data, (char *) "data");
                    if (insn.tag == Ist_IMark) {
                        printf("\taddr = 0x%x\n", insn.addr);
                        printf("\tlen = %d\n", insn.len);
                    }
                    if (insn.tag == Ist_Exit) {
                        print_vex_expr(insn.guard, (char *) "guard");
                        printf("\toffsIP = %d\n", insn.offsIP);
                        printf("\tdst = 0x%x\n", insn.dst);
                    }
                }
            }

            void set_expr(vex_expr *insn, PyObject *obj)
            {
                PyObject *v;
                v = PyDict_GetItemString(obj, "tag");
                if (v) insn->tag = vex_tag_iex_str_to_enum(PyString_AsString(v));
                v = PyDict_GetItemString(obj, "tmp");
                if (v) insn->tmp = PyInt_AsLong(v);
                v = PyDict_GetItemString(obj, "con");
                if (v) insn->con = PyInt_AsLong(v);
                v = PyDict_GetItemString(obj, "offset");
                if (v) insn->offset = PyInt_AsLong(v);
            }

            bool vex_lift(vex_insns_group *insns_group, unsigned char *insns_bytes, unsigned int start_addr, unsigned int count)
            {
                PyObject *global, *func;

                // Invoke Python Interpreter
                Py_Initialize();

                // Load Helper Script
                PyRun_SimpleString(script);

                // Get ref of function
                global = PyModule_GetDict(PyImport_ImportModule("__main__"));
                func = PyDict_GetItemString(global, "Lift");

                if (PyCallable_Check(func)) // Checks if we got ref
                {
                    // Do Lift
                    PyObject *ans = PyEval_CallFunction(func, "zii", insns_bytes, start_addr, count);
                    if( ans )
                    {
                        if (PyList_Check(ans)) {
                            unsigned int current_addr;
                            for(Py_ssize_t i = 0; i < PyList_Size(ans); i++) {
                                PyObject *item = PyList_GetItem(ans, i);
                                struct vex_insn insn;
                                PyObject *v, *data, *args;
                                v = PyDict_GetItemString(item, "full");
                                insn.full = PyString_AsString(v);
                                v = PyDict_GetItemString(item, "tag");
                                insn.tag = vex_tag_ist_str_to_enum(PyString_AsString(v));
                                v = PyDict_GetItemString(item, "tmp");
                                if (v) insn.tmp = PyInt_AsLong(v);
                                v = PyDict_GetItemString(item, "offset");
                                if (v) insn.offset = PyInt_AsLong(v);
                                v = PyDict_GetItemString(item, "addr");
                                if (v) insn.addr = PyInt_AsLong(v);
                                v = PyDict_GetItemString(item, "len");
                                if (v) insn.len = PyInt_AsLong(v);
                                v = PyDict_GetItemString(item, "jumpkind");
                                if (v) insn.jumpkind = PyString_AsString(v);
                                v = PyDict_GetItemString(item, "dst");
                                if (v) insn.dst = PyInt_AsLong(v);
                                v = PyDict_GetItemString(item, "offsIP");
                                if (v) insn.offsIP = PyInt_AsLong(v);
                                v = PyDict_GetItemString(item, "guard");
                                if (v) set_expr(&insn.guard, v);
                                data = PyDict_GetItemString(item, "data");
                                if (data) {
                                    v = PyDict_GetItemString(data, "tag");
                                    insn.data.tag = vex_tag_iex_str_to_enum(PyString_AsString(v));
                                    v = PyDict_GetItemString(data, "ty");
                                    if (v) insn.data.ty = vex_tag_ity_str_to_enum(PyString_AsString(v));
                                    v = PyDict_GetItemString(data, "op");
                                    if (v) insn.data.op = PyString_AsString(v);
                                    v = PyDict_GetItemString(data, "tmp");
                                    if (v) insn.data.tmp = PyInt_AsLong(v);
                                    v = PyDict_GetItemString(data, "con");
                                    if (v) insn.data.con = PyInt_AsLong(v);
                                    v = PyDict_GetItemString(data, "offset");
                                    if (v) insn.data.offset = PyInt_AsLong(v);
                                    args = PyDict_GetItemString(data, "args");
                                    if (args) {
                                        insn.data.nargs = PyList_Size(args);
                                        for(Py_ssize_t j = 0; j < PyList_Size(args); j++) {
                                            PyObject *args_j = PyList_GetItem(args, j);
                                            set_expr(&insn.data.args[j], args_j);
                                        }
                                    }
                                }

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
                        for(auto itr = insns_group->begin(); itr != insns_group->end(); ++itr) {
                            puts("");
                            printf("*** [address = 0x%x] ***\n", itr->first);
                            print_vex_insns(itr->second);
                        }
                    }
                    Py_DECREF(ans);
                }
                else {
                    fprintf(stderr, "ref error\n");
                    return false;
                }

                Py_DECREF(global);
                Py_DECREF(func);

                // Terminate Interpreter
                Py_Finalize();

                return true;
            }

        }
    }
}