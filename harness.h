

#include <Python.h>

/*

void LLVMFuzzerFinalizePythonModule();
*/


void LLVMFuzzerInitPythonModule();

PyObject* py_module = NULL;





void py_fatal_error() {
  fprintf(stderr, "The libFuzzer Python layer encountered a critical error.\n");
  fprintf(stderr, "Please fix the messages above and then restart fuzzing.\n");
  exit(1);
}


PyObject* mutator;


PyObject* otherthing;

size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);








PyObject* LLVMFuzzerMutatePyCallback(PyObject* data, PyObject* args) {
  PyObject* py_value;

  py_value = PyTuple_GetItem(args, 1);
  if (!py_value) {
    fprintf(stderr, "Error: Missing MaxSize argument to native callback.\n");
    py_fatal_error();
  }
  size_t MaxSize = PyLong_AsSize_t(py_value);
  if (MaxSize == (size_t)-1 && PyErr_Occurred()) {
    PyErr_Print();
    fprintf(stderr, "Error: Failed to convert MaxSize argument to size_t.\n");
    py_fatal_error();
  }

  py_value = PyTuple_GetItem(args, 0);
  size_t Size = (size_t)PyByteArray_Size(py_value);
  if (PyByteArray_Resize(py_value, MaxSize) < 0) {
    fprintf(stderr, "Error: Failed to resize ByteArray to MaxSize.\n");
    py_fatal_error();
  }

  size_t RetLen =
    LLVMFuzzerMutate((uint8_t *)PyByteArray_AsString(py_value), Size, MaxSize);

  if (PyByteArray_Resize(py_value, RetLen) < 0) {
    fprintf(stderr, "Error: Failed to resize ByteArray to RetLen.\n");
    py_fatal_error();
  }

  Py_RETURN_NONE;
}

PyMethodDef LLVMFuzzerMutatePyMethodDef = {
  "LLVMFuzzerMutate",
  LLVMFuzzerMutatePyCallback,
  METH_VARARGS | METH_STATIC,
  NULL
};

void LLVMFuzzerInitPythonModule() {
  Py_Initialize();
  char* module_name = getenv("LIBFUZZER_PYTHON_MODULE");

  if (module_name) {
    PyObject* py_name = PyUnicode_FromString(module_name);

    py_module = PyImport_Import(py_name);
    Py_DECREF(py_name);

    if (py_module != NULL) {
      mutator =
        PyObject_GetAttrString(py_module, "custom_mutator");
      otherthing =
        PyObject_GetAttrString(py_module, "custom_crossover");

      if (!mutator
        || !PyCallable_Check(mutator)) {
        if (PyErr_Occurred())
          PyErr_Print();
        fprintf(stderr, "Error: Cannot find/call custom mutator function in"
                        " external Python module.\n");
        py_fatal_error();
      }

      if (!otherthing
        || !PyCallable_Check(otherthing)) {
        if (PyErr_Occurred())
          PyErr_Print();
        fprintf(stderr, "Warning: Python module does not implement crossover"
                        " API, standard crossover will be used.\n");
        otherthing = NULL;
      }
    } else {
      if (PyErr_Occurred())
        PyErr_Print();
      fprintf(stderr, "Error: Failed to load external Python module \"%s\"\n",
        module_name);
      py_fatal_error();
    }
  } else {
    fprintf(stderr, "Warning: No Python module specified, using the default libfuzzer mutator (for now).\n");
    }


}


/*
PyObject mutator;


PyObject otherthing;
*/



size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size,
                                          size_t MaxSize, unsigned int Seed) {
  if (!py_module) { 
		return LLVMFuzzerMutate(Data, Size, MaxSize);
  }
  PyObject* py_args = PyTuple_New(4);

  PyObject* py_value = PyByteArray_FromStringAndSize((const char*)Data, Size);
  if (!py_value) {
    Py_DECREF(py_args);
    fprintf(stderr, "Error: Failed to convert buffer.\n");
    py_fatal_error();
  }
  PyTuple_SetItem(py_args, 0, py_value);

  py_value = PyLong_FromSize_t(MaxSize);
  if (!py_value) {
    Py_DECREF(py_args);
    fprintf(stderr, "Error: Failed to convert maximum size.\n");
    py_fatal_error();
  }
  PyTuple_SetItem(py_args, 1, py_value);

  py_value = PyLong_FromUnsignedLong((unsigned long)Seed);
  if (!py_value) {
    Py_DECREF(py_args);
    fprintf(stderr, "Error: Failed to convert seed.\n");
    py_fatal_error();
  }
  PyTuple_SetItem(py_args, 2, py_value);

  PyObject* py_callback = PyCFunction_New(&LLVMFuzzerMutatePyMethodDef, NULL);
  if (!py_callback) {
    fprintf(stderr, "Failed to create native callback\n");
    py_fatal_error();
  }

  PyTuple_SetItem(py_args, 3, py_callback);

  py_value = PyObject_CallObject(mutator, py_args);

  Py_DECREF(py_args);
  Py_DECREF(py_callback);

  if (py_value != NULL) {
    ssize_t ReturnedSize = PyByteArray_Size(py_value);
    if (ReturnedSize > MaxSize) {
      fprintf(stderr, "Warning: Python module returned buffer that exceeds "
                      "the maximum size. Returning a truncated buffer.\n");
      ReturnedSize = MaxSize;
    }
    memcpy(Data, PyByteArray_AsString(py_value), ReturnedSize);
    Py_DECREF(py_value);
    if (getenv("FUZZ_ONLY_CUSTOM")) { 
			return ReturnedSize;
    }


    return LLVMFuzzerMutate(Data, ReturnedSize, MaxSize);

  } else {
    if (PyErr_Occurred())
      PyErr_Print();
    fprintf(stderr, "Error: Call failed\n");
    py_fatal_error();
  }
  return 0;
}

