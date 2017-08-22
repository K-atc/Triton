//! \file
/*
**  Copyright (C) - Triton
**
**  This program is under the terms of the BSD License.
*/

#include "unicorn_wrapper.h"

/* libTriton */
#include <triton/pythonUtils.hpp>
#include <triton/pythonObjects.hpp>
#include <triton/tritonTypes.hpp>

/* for unciron tracer */
#include "bindings.hpp"
#include "context.hpp"
#include "snapshot.hpp"


namespace tracer {
  namespace unicorn {

    static PyObject* unicorn_checkReadAccess(PyObject* self, PyObject* addr) {
      if (!PyLong_Check(addr) && !PyInt_Check(addr))
        return PyErr_Format(PyExc_TypeError, "tracer::unicorn::checkReadAccess(): Expected an address (integer) as argument.");

      if (UC_CheckReadAccess(reinterpret_cast<void*>(triton::bindings::python::PyLong_AsUint(addr))) == true)
        Py_RETURN_TRUE;

      Py_RETURN_FALSE;
    }


    static PyObject* unicorn_checkWriteAccess(PyObject* self, PyObject* addr) {
      if (!PyLong_Check(addr) && !PyInt_Check(addr))
        return PyErr_Format(PyExc_TypeError, "tracer::unicorn::checkWriteAccess(): Expected an address (integer) as argument.");

      if (UC_CheckWriteAccess(reinterpret_cast<void*>(triton::bindings::python::PyLong_AsUint(addr))) == true)
        Py_RETURN_TRUE;

      Py_RETURN_FALSE;
    }


    static PyObject* unicorn_detachProcess(PyObject* self, PyObject* noarg) {
      UC_Detach();
      tracer::unicorn::analysisTrigger.update(false);
      Py_INCREF(Py_None);
      return Py_None;
    }


    static PyObject* unicorn_disableSnapshot(PyObject* self, PyObject* noarg) {
      tracer::unicorn::snapshot.disableSnapshot();
      Py_INCREF(Py_None);
      return Py_None;
    }


    static PyObject* unicorn_getCurrentMemoryValue(PyObject* self, PyObject* args) {
      PyObject* mem   = nullptr;
      PyObject* size  = nullptr;

      /* Extract arguments */
      PyArg_ParseTuple(args, "|OO", &mem, &size);

      if (mem != nullptr && (PyMemoryAccess_Check(mem) || PyInt_Check(mem) || PyLong_Check(mem))) {

        if (size != nullptr && (!PyInt_Check(size) && !PyLong_Check(size)))
          return PyErr_Format(PyExc_TypeError, "tracer::unicorn::getCurrentMemoryValue(): The size must be an integer.");

        try {
          if (PyMemoryAccess_Check(mem))
            return triton::bindings::python::PyLong_FromUint512(tracer::unicorn::context::getCurrentMemoryValue(*PyMemoryAccess_AsMemoryAccess(mem)));
          else if (size != nullptr) {
            return triton::bindings::python::PyLong_FromUint512(tracer::unicorn::context::getCurrentMemoryValue(triton::bindings::python::PyLong_AsUint(mem), triton::bindings::python::PyLong_AsUint32(size)));
          }
          else
            return triton::bindings::python::PyLong_FromUint512(tracer::unicorn::context::getCurrentMemoryValue(triton::bindings::python::PyLong_AsUint(mem)));
        }
        catch (const std::exception& e) {
          return PyErr_Format(PyExc_TypeError, "%s", e.what());
        }

      }

      return PyErr_Format(PyExc_TypeError, "tracer::unicorn::getCurrentMemoryValue(): Expected a Memory as first argument.");
    }


    static PyObject* unicorn_getCurrentRegisterValue(PyObject* self, PyObject* reg) {
      if (!PyRegister_Check(reg))
        return PyErr_Format(PyExc_TypeError, "tracer::unicorn::getCurrentRegisterValue(): Expected a REG as argument.");
      try {
        return triton::bindings::python::PyLong_FromUint512(tracer::unicorn::context::getCurrentRegisterValue(*PyRegister_AsRegister(reg)));
      }
      catch (const std::exception& e) {
        return PyErr_Format(PyExc_TypeError, "%s", e.what());
      }
    }


    static PyObject* unicorn_getImageName(PyObject* self, PyObject* addr) {
      if (!PyLong_Check(addr) && !PyInt_Check(addr))
        return PyErr_Format(PyExc_TypeError, "tracer::unicorn::getImageName(): Expected an address (integer) as argument.");

      std::string imageName = tracer::unicorn::getImageName(triton::bindings::python::PyLong_AsUint(addr));
      return PyString_FromFormat("%s", imageName.c_str());;
    }


    static PyObject* unicorn_getRoutineName(PyObject* self, PyObject* addr) {
      if (!PyLong_Check(addr) && !PyInt_Check(addr))
        return PyErr_Format(PyExc_TypeError, "tracer::unicorn::getImageName(): Expected an address (integer) as argument.");

      std::string routineName = tracer::unicorn::getRoutineName(triton::bindings::python::PyLong_AsUint(addr));
      return PyString_FromFormat("%s", routineName.c_str());;
    }





    static PyObject* unicorn_getSyscallArgument(PyObject* self, PyObject* args) {
      PyObject* num = nullptr;
      PyObject* std = nullptr;
      triton::__uint ret;

      /* Extract arguments */
      PyArg_ParseTuple(args, "|OO", &std, &num);

      if (std == nullptr || (!PyLong_Check(std) && !PyInt_Check(std)))
        return PyErr_Format(PyExc_TypeError, "tracer::unicorn::getSyscallArgument(): Expected an id (integer) as first argument.");

      if (num == nullptr || (!PyLong_Check(num) && !PyInt_Check(num)))
        return PyErr_Format(PyExc_TypeError, "tracer::unicorn::getSyscallArgument(): Expected an id (integer) as second argument.");

      // TODO: 
      fprintf(stderr, "unicorn_getSyscallArgument is not implemented\n");
      // LEVEL_CORE::SYSCALL_STANDARD standard = static_cast<LEVEL_CORE::SYSCALL_STANDARD>(triton::bindings::python::PyLong_AsUint32(std));
      // ret = PIN_GetSyscallArgument(tracer::unicorn::context::lastContext, standard, triton::bindings::python::PyLong_AsUint32(num));

      return triton::bindings::python::PyLong_FromUint(ret);
    }


    static PyObject* unicorn_getSyscallNumber(PyObject* self, PyObject* std) {
      triton::uint32 syscallNumber;

      if (!PyLong_Check(std) && !PyInt_Check(std))
        return PyErr_Format(PyExc_TypeError, "tracer::unicorn::getSyscallNumber(): Expected an id (integer) as argument.");

      // TODO: 
      fprintf(stderr, "unicorn_getSyscallNumber is not implemented\n");
      // LEVEL_CORE::SYSCALL_STANDARD standard = static_cast<LEVEL_CORE::SYSCALL_STANDARD>(triton::bindings::python::PyLong_AsUint32(std));
      // syscallNumber = PIN_GetSyscallNumber(tracer::unicorn::context::lastContext, standard);

      return triton::bindings::python::PyLong_FromUint32(syscallNumber);
    }


    static PyObject* unicorn_getSyscallReturn(PyObject* self, PyObject* std) {
      triton::__uint ret;

      if (!PyLong_Check(std) && !PyInt_Check(std))
        return PyErr_Format(PyExc_TypeError, "tracer::unicorn::getSyscallReturn(): Expected an id (integer) as argument.");

      // TODO: 
      fprintf(stderr, "unicorn_getSyscallReturn is not implemented\n");
      // LEVEL_CORE::SYSCALL_STANDARD standard = static_cast<LEVEL_CORE::SYSCALL_STANDARD>(triton::bindings::python::PyLong_AsUint32(std));
      // ret = PIN_GetSyscallReturn(tracer::unicorn::context::lastContext, standard);

      return triton::bindings::python::PyLong_FromUint(ret);
    }


    static PyObject* unicorn_insertCall(PyObject* self, PyObject* args) {
      PyObject* function  = nullptr;
      PyObject* flag      = nullptr;
      PyObject* routine   = nullptr;

      /* Extract arguments */
      PyArg_ParseTuple(args, "|OOO", &function, &flag, &routine);

      if (function == nullptr || !PyCallable_Check(function))
        return PyErr_Format(PyExc_TypeError, "tracer::unicorn::insertCall(): Expected a function callback as first argument.");

      /* Check if the second arg is an INSERT_POINT*/
      if (flag == nullptr || (!PyLong_Check(flag) && !PyInt_Check(flag)))
        return PyErr_Format(PyExc_TypeError, "tracer::unicorn::insertCall(): Expected an INSERT_POINT (integer) as second argument.");

      if (triton::bindings::python::PyLong_AsUint32(flag) == tracer::unicorn::options::CB_BEFORE)
        tracer::unicorn::options::callbackBefore = function;

      else if ((triton::bindings::python::PyLong_AsUint32(flag) == tracer::unicorn::options::CB_BEFORE_SYMPROC))
        tracer::unicorn::options::callbackBeforeIRProc = function;

      else if ((triton::bindings::python::PyLong_AsUint32(flag) == tracer::unicorn::options::CB_AFTER))
        tracer::unicorn::options::callbackAfter = function;

      else if ((triton::bindings::python::PyLong_AsUint32(flag) == tracer::unicorn::options::CB_FINI))
        tracer::unicorn::options::callbackFini = function;

      else if ((triton::bindings::python::PyLong_AsUint32(flag) == tracer::unicorn::options::CB_SIGNALS))
        tracer::unicorn::options::callbackSignals = function;

      else if ((triton::bindings::python::PyLong_AsUint32(flag) == tracer::unicorn::options::CB_SYSCALL_ENTRY))
        tracer::unicorn::options::callbackSyscallEntry = function;

      else if ((triton::bindings::python::PyLong_AsUint32(flag) == tracer::unicorn::options::CB_SYSCALL_EXIT))
        tracer::unicorn::options::callbackSyscallExit = function;

      else if (triton::bindings::python::PyLong_AsUint32(flag) == tracer::unicorn::options::CB_IMAGE_LOAD)
        tracer::unicorn::options::callbackImageLoad = function;

      else if ((triton::bindings::python::PyLong_AsUint32(flag) == tracer::unicorn::options::CB_ROUTINE_ENTRY)) {
        if (routine == nullptr || !PyString_Check(routine))
          return PyErr_Format(PyExc_TypeError, "tracer::unicorn::insertCall(): Expected a routine name (string) as third argument.");
        tracer::unicorn::options::callbackRoutineEntry.insert(std::pair<const char*,PyObject*>(PyString_AsString(routine), function));
      }

      else if ((triton::bindings::python::PyLong_AsUint32(flag) == tracer::unicorn::options::CB_ROUTINE_EXIT)) {
        if (routine == nullptr || !PyString_Check(routine))
          return PyErr_Format(PyExc_TypeError, "tracer::unicorn::insertCall(): Expected a routine name (string) as third argument.");
        tracer::unicorn::options::callbackRoutineExit.insert(std::pair<const char*,PyObject*>(PyString_AsString(routine), function));
      }

      else
        return PyErr_Format(PyExc_TypeError, "tracer::unicorn::insertCall(): Expected an INSERT_POINT (integer) as second argument.");

      Py_INCREF(Py_None);
      return Py_None;
    }


    static PyObject* unicorn_isSnapshotEnabled(PyObject* self, PyObject* noarg) {
      if (tracer::unicorn::snapshot.isLocked() == false)
        Py_RETURN_TRUE;
      Py_RETURN_FALSE;
    }


    static PyObject* unicorn_restoreSnapshot(PyObject* self, PyObject* noarg) {
      tracer::unicorn::snapshot.setRestore(true);
      Py_INCREF(Py_None);
      return Py_None;
    }

    // @param bin binary
    // @param addr target memory begin address
    // @param size binary size
    static PyObject* unicorn_loadBinary(PyObject* self, PyObject* args) {
      unsigned char* bin;
      int addr  = 0;
      int size  = 0;

      /* Extract arguments */
      PyArg_ParseTuple(args, "yll", &bin, &addr, &size);
      uc_err err;
      err = UC_LoadBinary(bin, addr, size);
      return PyLong_FromLong(err);
    }

    static PyObject* unicorn_setEmuStartAddr(PyObject* self, PyObject* addr) {
      if (!PyLong_Check(addr) && !PyInt_Check(addr))
        return PyErr_Format(PyExc_TypeError, "UC_SetEmuStartAddr(): Expected an address (integer) as argument.");
      UC_SetEmuStartAddr(triton::bindings::python::PyLong_AsUint(addr));
    }

    static PyObject* unicorn_runProgram(PyObject* self, PyObject* noarg) {
      /* Check if the architecture is definied */
      if (triton::api.getArchitecture() == triton::arch::ARCH_INVALID)
        return PyErr_Format(PyExc_TypeError, "tracer::unicorn::runProgram(): Architecture is not defined.");
      /* Never returns - Rock 'n roll baby \o/ */
      try {
        /* Provide concrete values only if Triton needs them - cf #376 */
        triton::api.addCallback(tracer::unicorn::context::needConcreteRegisterValue);
        UC_StartProgram();
      }
      catch (const std::exception& e) {
        return PyErr_Format(PyExc_TypeError, "%s", e.what());
      }
      Py_INCREF(Py_None);
      return Py_None;
    }


    static PyObject* unicorn_setCurrentMemoryValue(PyObject* self, PyObject* args) {
      PyObject* mem   = nullptr;
      PyObject* value = nullptr;

      /* Extract arguments */
      PyArg_ParseTuple(args, "|OO", &mem, &value);

      if (mem != nullptr && (PyMemoryAccess_Check(mem) || PyInt_Check(mem) || PyLong_Check(mem))) {

        if (value != nullptr && (!PyInt_Check(value) && !PyLong_Check(value)))
          return PyErr_Format(PyExc_TypeError, "tracer::unicorn::setCurrentMemoryValue(): The value must be an integer.");

        try {
          if (value != nullptr && PyMemoryAccess_Check(mem))
            tracer::unicorn::context::setCurrentMemoryValue(*PyMemoryAccess_AsMemoryAccess(mem), triton::bindings::python::PyLong_AsUint512(value));
          else if (value != nullptr && (PyInt_Check(mem) || PyLong_Check(mem))) {
            triton::uint8 v = (triton::bindings::python::PyLong_AsUint512(value) & 0xff).convert_to<triton::uint8>();
            tracer::unicorn::context::setCurrentMemoryValue(triton::bindings::python::PyLong_AsUint(mem), v);
          }
          else
            tracer::unicorn::context::setCurrentMemoryValue(*PyMemoryAccess_AsMemoryAccess(mem));
        }
        catch (const std::exception& e) {
          return PyErr_Format(PyExc_TypeError, "%s", e.what());
        }

      }
      else
        return PyErr_Format(PyExc_TypeError, "tracer::unicorn::setCurrentMemoryValue(): Expected a Memory as first argument.");

      Py_INCREF(Py_None);
      return Py_None;
    }


    static PyObject* unicorn_setCurrentRegisterValue(PyObject* self, PyObject* args) {
      PyObject* reg   = nullptr;
      PyObject* value = nullptr;

      /* Extract arguments */
      PyArg_ParseTuple(args, "|OO", &reg, &value);

      if (reg != nullptr && PyRegister_Check(reg)) {
        if (value != nullptr && (!PyInt_Check(value) && !PyLong_Check(value)))
          return PyErr_Format(PyExc_TypeError, "tracer::unicorn::setCurrentRegisterValue(): The value must be an integer.");

        try {
          if (value != nullptr)
            tracer::unicorn::context::setCurrentRegisterValue(*PyRegister_AsRegister(reg), triton::bindings::python::PyLong_AsUint512(value));
          else
            tracer::unicorn::context::setCurrentRegisterValue(*PyRegister_AsRegister(reg));
        }
        catch (const std::exception& e) {
          return PyErr_Format(PyExc_TypeError, "%s", e.what());
        }

      }
      else
        return PyErr_Format(PyExc_TypeError, "tracer::unicorn::setCurrentRegisterValue(): Expected a REG as first argument.");

      Py_INCREF(Py_None);
      return Py_None;
    }


    static PyObject* unicorn_setupImageBlacklist(PyObject* self, PyObject* arg) {
      /* Check if the arg is a list */
      if (!PyList_Check(arg))
        return PyErr_Format(PyExc_TypeError, "tracer::unicorn::setupImageBlacklist(): Expected a list as first argument.");

      /* Check if the arg list contains only string item and insert them in the internal list */
      for (Py_ssize_t i = 0; i < PyList_Size(arg); i++) {
        PyObject* item = PyList_GetItem(arg, i);

        if (!PyString_Check(item))
          return PyErr_Format(PyExc_TypeError, "tracer::unicorn::setupImageBlacklist(): Each item of the list must be a string.");

        tracer::unicorn::options::imageBlacklist.push_back(PyString_AsString(item));
      }

      Py_INCREF(Py_None);
      return Py_None;
    }


    static PyObject* unicorn_setupImageWhitelist(PyObject* self, PyObject* arg) {
      /* Check if the arg is a list */
      if (!PyList_Check(arg))
        return PyErr_Format(PyExc_TypeError, "tracer::unicorn::setupImageWhitelist(): Expected a list as first argument.");

      /* Check if the arg list contains only string item and insert them in the internal list */
      for (Py_ssize_t i = 0; i < PyList_Size(arg); i++) {
        PyObject* item = PyList_GetItem(arg, i);

        if (!PyString_Check(item))
          return PyErr_Format(PyExc_TypeError, "tracer::unicorn::setupImageWhitelist(): Each item of the list must be a string.");

        tracer::unicorn::options::imageWhitelist.push_back(PyString_AsString(item));
      }

      Py_INCREF(Py_None);
      return Py_None;
    }


    static PyObject* unicorn_startAnalysisFromAddress(PyObject* self, PyObject* addr) {
      if (!PyLong_Check(addr) && !PyInt_Check(addr))
        return PyErr_Format(PyExc_TypeError, "tracer::unicorn::startAnalysisFromAddress(): Expected an address (integer) as argument.");

      tracer::unicorn::options::startAnalysisFromAddress.insert(triton::bindings::python::PyLong_AsUint(addr));
      Py_INCREF(Py_None);
      return Py_None;
    }


    static PyObject* unicorn_startAnalysisFromEntry(PyObject* self, PyObject* noarg) {
      tracer::unicorn::options::startAnalysisFromEntry = true;
      Py_INCREF(Py_None);
      return Py_None;
    }


    static PyObject* unicorn_startAnalysisFromOffset(PyObject* self, PyObject* offset) {
      if (!PyLong_Check(offset) && !PyInt_Check(offset))
        return PyErr_Format(PyExc_TypeError, "tracer::unicorn::startAnalysisFromOffset(): Expected an offset (integer) as argument.");

      tracer::unicorn::options::startAnalysisFromOffset.insert(triton::bindings::python::PyLong_AsUint(offset));
      Py_INCREF(Py_None);
      return Py_None;
    }


    static PyObject* unicorn_startAnalysisFromSymbol(PyObject* self, PyObject* name) {
      if (!PyString_Check(name))
        return PyErr_Format(PyExc_TypeError, "tracer::unicorn::startAnalysisFromSymbol(): Expected a string as argument.");

      tracer::unicorn::options::startAnalysisFromSymbol = PyString_AsString(name);
      Py_INCREF(Py_None);
      return Py_None;
    }


    static PyObject* unicorn_stopAnalysisFromAddress(PyObject* self, PyObject* addr) {
      if (!PyLong_Check(addr) && !PyInt_Check(addr))
        return PyErr_Format(PyExc_TypeError, "tracer::unicorn::stopAnalysisFromAddress(): Expected an address (integer) as argument.");

      tracer::unicorn::options::stopAnalysisFromAddress.insert(triton::bindings::python::PyLong_AsUint(addr));
      Py_INCREF(Py_None);
      return Py_None;
    }


    static PyObject* unicorn_stopAnalysisFromOffset(PyObject* self, PyObject* offset) {
      if (!PyLong_Check(offset) && !PyInt_Check(offset))
        return PyErr_Format(PyExc_TypeError, "tracer::unicorn::stopAnalysisFromOffset(): Expected an offset (integer) as argument.");

      tracer::unicorn::options::stopAnalysisFromOffset.insert(triton::bindings::python::PyLong_AsUint(offset));
      Py_INCREF(Py_None);
      return Py_None;
    }


    static PyObject* unicorn_takeSnapshot(PyObject* self, PyObject* noarg) {
      tracer::unicorn::snapshot.takeSnapshot(tracer::unicorn::context::lastContext);
      Py_INCREF(Py_None);
      return Py_None;
    }


    PyMethodDef unicornCallbacks[] = {
      {"checkReadAccess",           unicorn_checkReadAccess,            METH_O,         ""},
      {"checkWriteAccess",          unicorn_checkWriteAccess,           METH_O,         ""},
      {"detachProcess",             unicorn_detachProcess,              METH_NOARGS,    ""},
      {"disableSnapshot",           unicorn_disableSnapshot,            METH_NOARGS,    ""},
      {"getCurrentMemoryValue",     unicorn_getCurrentMemoryValue,      METH_VARARGS,   ""},
      {"getCurrentRegisterValue",   unicorn_getCurrentRegisterValue,    METH_O,         ""},
      {"getImageName",              unicorn_getImageName,               METH_O,         ""},
      {"getRoutineName",            unicorn_getRoutineName,             METH_O,         ""},
      {"getSyscallArgument",        unicorn_getSyscallArgument,         METH_VARARGS,   ""},
      {"getSyscallNumber",          unicorn_getSyscallNumber,           METH_O,         ""},
      {"getSyscallReturn",          unicorn_getSyscallReturn,           METH_O,         ""},
      {"insertCall",                unicorn_insertCall,                 METH_VARARGS,   ""},
      {"isSnapshotEnabled",         unicorn_isSnapshotEnabled,          METH_NOARGS,    ""},
      {"restoreSnapshot",           unicorn_restoreSnapshot,            METH_NOARGS,    ""},
      {"loadBinary",                unicorn_loadBinary,                 METH_VARARGS,   ""},
      {"setEmuStartAddr",           unicorn_setEmuStartAddr,            METH_O,         ""},
      {"runProgram",                unicorn_runProgram,                 METH_NOARGS,    ""},
      {"setCurrentMemoryValue",     unicorn_setCurrentMemoryValue,      METH_VARARGS,   ""},
      {"setCurrentRegisterValue",   unicorn_setCurrentRegisterValue,    METH_VARARGS,   ""},
      {"setupImageBlacklist",       unicorn_setupImageBlacklist,        METH_O,         ""},
      {"setupImageWhitelist",       unicorn_setupImageWhitelist,        METH_O,         ""},
      {"startAnalysisFromAddress",  unicorn_startAnalysisFromAddress,   METH_O,         ""},
      {"startAnalysisFromEntry",    unicorn_startAnalysisFromEntry,     METH_NOARGS,    ""},
      {"startAnalysisFromOffset",   unicorn_startAnalysisFromOffset,    METH_O,         ""},
      {"startAnalysisFromSymbol",   unicorn_startAnalysisFromSymbol,    METH_O,         ""},
      {"stopAnalysisFromAddress",   unicorn_stopAnalysisFromAddress,    METH_O,         ""},
      {"stopAnalysisFromOffset",    unicorn_stopAnalysisFromOffset,     METH_O,         ""},
      {"takeSnapshot",              unicorn_takeSnapshot,               METH_NOARGS,    ""},
      {nullptr,                     nullptr,                            0,              nullptr}
    };

  };
};

