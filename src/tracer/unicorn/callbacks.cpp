//! \file
/*
**  Copyright (C) - Triton
**
**  This program is under the terms of the BSD License.
*/

#include <iostream>
#include <stdexcept>
#include <string>

/* libTriton */
#include <triton/api.hpp>
#include <triton/pythonBindings.hpp>
#include <triton/pythonObjects.hpp>
#include <triton/pythonUtils.hpp>
#include <triton/pythonXFunctions.hpp>

#include "bindings.hpp"
#include "utils.hpp"
#include "logger.hpp"

namespace tracer {
  namespace unicorn {
    namespace callbacks {

      void after(triton::arch::Instruction* inst) {
        /* Check if there is a callback wich must be called at each instruction instrumented */
        if (tracer::unicorn::analysisTrigger.getState() && tracer::unicorn::options::callbackAfter) {

          /* Create the Instruction Python class */
          PyObject* instClass = triton::bindings::python::PyInstruction(*inst);

          /* CallObject needs a tuple. The size of the tuple is the number of arguments.
           * Triton sends only one argument to the callback. This argument is the Instruction
           * class and contains all information. */
          PyObject* args = triton::bindings::python::xPyTuple_New(1);
          PyTuple_SetItem(args, 0, instClass);
          if (PyObject_CallObject(tracer::unicorn::options::callbackAfter, args) == nullptr) {
            PyErr_Print();
            exit(1);
          }

          Py_DECREF(args);
        }
      }


      void before(triton::arch::Instruction* inst) {        
        // log::info("callback.cpp: before called. analysisTrigger state is %d", tracer::unicorn::analysisTrigger.getState());
        /* Check if there is a callback wich must be called at each instruction instrumented */
        if (tracer::unicorn::analysisTrigger.getState() && tracer::unicorn::options::callbackBefore){
          // log::info("callback.cpp: before called and in if-then clause");
          /* Create the Instruction Python class */
          PyObject* instClass = triton::bindings::python::PyInstruction(*inst);

          /* CallObject needs a tuple. The size of the tuple is the number of arguments.
           * Triton sends only one argument to the callback. This argument is the Instruction
           * class and contains all information. */
          PyObject* args = triton::bindings::python::xPyTuple_New(1);
          PyTuple_SetItem(args, 0, instClass);
          if (PyObject_CallObject(tracer::unicorn::options::callbackBefore, args) == nullptr) {
            PyErr_Print();
            exit(1);
          }

          Py_DECREF(args);
        }
      }


      void beforeIRProc(triton::arch::Instruction* inst) {
        /* Check if there is a callback wich must be called at each instruction instrumented */
        if (tracer::unicorn::analysisTrigger.getState() && tracer::unicorn::options::callbackBeforeIRProc) {

          /* Create the Instruction Python class */
          PyObject* instClass = triton::bindings::python::PyInstruction(*inst);

          /* CallObject needs a tuple. The size of the tuple is the number of arguments.
           * Triton sends only one argument to the callback. This argument is the Instruction
           * class and contains all information. */
          PyObject* args = triton::bindings::python::xPyTuple_New(1);
          PyTuple_SetItem(args, 0, instClass);
          if (PyObject_CallObject(tracer::unicorn::options::callbackBeforeIRProc, args) == nullptr) {
            PyErr_Print();
            exit(1);
          }

          Py_DECREF(args);
        }
      }


      void fini(void) {
        /* Check if there is a callback wich must be called at the end of the execution */
        if (tracer::unicorn::options::callbackFini) {

          /* CallObject needs a tuple. The size of the tuple is the number of arguments.
           * There is no argument sent to the callback. */
          PyObject* args = triton::bindings::python::xPyTuple_New(0);
          if (PyObject_CallObject(tracer::unicorn::options::callbackFini, args) == nullptr) {
            PyErr_Print();
            exit(1);
          }

          Py_DECREF(args);
        }
      }


      void routine(triton::uint32 threadId, PyObject* callback) {
        PyObject* args = triton::bindings::python::xPyTuple_New(1);
        PyTuple_SetItem(args, 0, triton::bindings::python::PyLong_FromUint32(threadId));
        if (PyObject_CallObject(callback, args) == nullptr) {
          PyErr_Print();
          exit(1);
        }
        Py_DECREF(args);
      }


      void signals(triton::uint32 threadId, triton::sint32 sig) {
        /* Check if there is a callback wich must be called when a signal occurs */
        if (tracer::unicorn::options::callbackSignals) {

          /* CallObject needs a tuple. The size of the tuple is the number of arguments.
           * threadId and sig are sent to the callback. */
          PyObject* args = triton::bindings::python::xPyTuple_New(2);
          PyTuple_SetItem(args, 0, triton::bindings::python::PyLong_FromUint32(threadId));
          PyTuple_SetItem(args, 1, triton::bindings::python::PyLong_FromUint32(sig));
          if (PyObject_CallObject(tracer::unicorn::options::callbackSignals, args) == nullptr) {
            PyErr_Print();
            exit(1);
          }

          Py_DECREF(args);
        }
      }


      void syscallEntry(triton::uint32 threadId, triton::uint32 std) {
        /* Check if there is a callback wich must be called before the syscall processing */
        if (tracer::unicorn::options::callbackSyscallEntry) {

          /* CallObject needs a tuple. The size of the tuple is the number of arguments.
           * threadId and Std are sent to the callback. */
          PyObject* args = triton::bindings::python::xPyTuple_New(2);
          PyTuple_SetItem(args, 0, triton::bindings::python::PyLong_FromUint32(threadId));
          PyTuple_SetItem(args, 1, triton::bindings::python::PyLong_FromUint32(std));
          if (PyObject_CallObject(tracer::unicorn::options::callbackSyscallEntry, args) == nullptr) {
            PyErr_Print();
            exit(1);
          }

          Py_DECREF(args);
        }
      }


      void syscallExit(triton::uint32 threadId, triton::uint32 std) {
        /* Check if there is a callback wich must be called after the syscall processing */
        if (tracer::unicorn::options::callbackSyscallExit) {

          /* CallObject needs a tuple. The size of the tuple is the number of arguments.
           * threadId and Std are sent to the callback. */
          PyObject* args = triton::bindings::python::xPyTuple_New(2);
          PyTuple_SetItem(args, 0, triton::bindings::python::PyLong_FromUint32(threadId));
          PyTuple_SetItem(args, 1, triton::bindings::python::PyLong_FromUint32(std));
          if (PyObject_CallObject(tracer::unicorn::options::callbackSyscallExit, args) == nullptr) {
            PyErr_Print();
            exit(1);
          }

          Py_DECREF(args);
        }
      }


      void imageLoad(std::string imagePath, triton::__uint imageBase, triton::__uint imageSize) {
        /* Check if there is a callback wich must be called when an image is loaded */
        if (tracer::unicorn::options::callbackImageLoad) {

          /* CallObject needs a tuple. The size of the tuple is the number of arguments.
           * imagePath, imageBase and imageSize are sent to the callback. */
          PyObject* args = triton::bindings::python::xPyTuple_New(3);
          PyTuple_SetItem(args, 0, PyString_FromString(imagePath.c_str()));
          PyTuple_SetItem(args, 1, triton::bindings::python::PyLong_FromUint(imageBase));
          PyTuple_SetItem(args, 2, triton::bindings::python::PyLong_FromUint(imageSize));
          if (PyObject_CallObject(tracer::unicorn::options::callbackImageLoad, args) == nullptr) {
            PyErr_Print();
            exit(1);
          }

          Py_DECREF(args);
        }
      }


      void preProcessing(triton::arch::Instruction* inst, triton::uint32 threadId) {
        triton::__uint addr   = inst->getAddress();
        triton::__uint offset = tracer::unicorn::getInsOffset(addr);
        if (tracer::unicorn::options::targetThreadId != -1)
          return;

        if (tracer::unicorn::options::startAnalysisFromAddress.find(addr) != tracer::unicorn::options::startAnalysisFromAddress.end()) {
          log::debug("tracer::unicorn::analysisTrigger.update(true)");
          tracer::unicorn::analysisTrigger.update(true);
          tracer::unicorn::options::targetThreadId = threadId;
        }

        if (tracer::unicorn::options::startAnalysisFromOffset.find(offset) != tracer::unicorn::options::startAnalysisFromOffset.end()) {
          log::debug("tracer::unicorn::analysisTrigger.update(true)");
          tracer::unicorn::analysisTrigger.update(true);
          tracer::unicorn::options::targetThreadId = threadId;
        }
      }


      void postProcessing(triton::arch::Instruction* inst, triton::uint32 threadId) {
        triton::__uint addr   = inst->getAddress();
        triton::__uint offset = tracer::unicorn::getInsOffset(addr);

        if (tracer::unicorn::options::targetThreadId != threadId)
          return;

        if (tracer::unicorn::options::stopAnalysisFromAddress.find(addr) != tracer::unicorn::options::stopAnalysisFromAddress.end()) {
          tracer::unicorn::analysisTrigger.update(false);
          tracer::unicorn::options::targetThreadId = -1;
        }

        if (tracer::unicorn::options::stopAnalysisFromOffset.find(offset) != tracer::unicorn::options::stopAnalysisFromOffset.end()) {
          tracer::unicorn::analysisTrigger.update(false);
          tracer::unicorn::options::targetThreadId = -1;
        }
      }

    };
  };
};

