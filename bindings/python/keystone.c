// Keystone Assembler Engine
// By Nguyen Anh Quynh <aquynh@gmail.com>, 2016
// By Amaan Qureshi <git@amaanq.com>, 2026

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <keystone/keystone.h>

#include <limits.h>
#include <stdbool.h>
#include <string.h>

typedef struct {
   const char *name;
   long value;
} Member;

static const Member ARCH_MEMBERS[] = {
   {"AARCH64",   KS_ARCH_AARCH64  },
   {"AMDGPU",    KS_ARCH_AMDGPU   },
   {"ARM",       KS_ARCH_ARM      },
   {"AVR",       KS_ARCH_AVR      },
   {"BPF",       KS_ARCH_BPF      },
   {"CSKY",      KS_ARCH_CSKY     },
   {"EVM",       KS_ARCH_EVM      },
   {"LANAI",     KS_ARCH_LANAI    },
   {"LOONGARCH", KS_ARCH_LOONGARCH},
   {"HEXAGON",   KS_ARCH_HEXAGON  },
   {"M68K",      KS_ARCH_M68K     },
   {"MIPS",      KS_ARCH_MIPS     },
   {"MSP430",    KS_ARCH_MSP430   },
   {"PPC",       KS_ARCH_PPC      },
   {"RISCV",     KS_ARCH_RISCV    },
   {"SPARC",     KS_ARCH_SPARC    },
   {"SYSTEMZ",   KS_ARCH_SYSTEMZ  },
   {"THUMB",     KS_ARCH_THUMB    },
   {"VE",        KS_ARCH_VE       },
   {"WASM",      KS_ARCH_WASM     },
   {"X86",       KS_ARCH_X86      },
   {"X64",       KS_ARCH_X64      },
   {"XTENSA",    KS_ARCH_XTENSA   },
   {NULL,        0                },
};

static const Member WIDTH_MEMBERS[] = {
   {"W16", KS_WIDTH_16},
   {"W32", KS_WIDTH_32},
   {"W64", KS_WIDTH_64},
   {NULL,  0          }
};

static const Member ARCH_VARIANT_MEMBERS[] = {
   {"NONE",         KS_ARCH_VARIANT_NONE        },
   {"ARM_V7",       KS_ARCH_VARIANT_ARM_V7      },
   {"ARM_MCLASS",   KS_ARCH_VARIANT_ARM_MCLASS  },
   {"ARM_EM",       KS_ARCH_VARIANT_ARM_EM      },
   {"THUMB_V7",     KS_ARCH_VARIANT_THUMB_V7    },
   {"THUMB_MCLASS", KS_ARCH_VARIANT_THUMB_MCLASS},
   {"THUMB_EM",     KS_ARCH_VARIANT_THUMB_EM    },
   {NULL,           0                           },
};

static const Member ENDIAN_MEMBERS[] = {
   {"LITTLE", KS_ENDIAN_LITTLE},
   {"BIG",    KS_ENDIAN_BIG   },
   {NULL,     0               }
};

static const Member KS_ERR_MEMBERS[] = {
   {"OK",                    KS_ERR_OK                   },
   {"MEM",                   KS_ERR_MEM                  },
   {"HANDLE",                KS_ERR_HANDLE               },
   {"ARCH",                  KS_ERR_ARCH                 },
   {"ENDIAN",                KS_ERR_ENDIAN               },
   {"WIDTH",                 KS_ERR_WIDTH                },
   {"FEATURE",               KS_ERR_FEATURE              },
   {"CPU",                   KS_ERR_CPU                  },
   {"VERSION",               KS_ERR_VERSION              },
   {"OPT_INVALID",           KS_ERR_OPT_INVALID          },
   {"ASM_SYNTAX",            KS_ERR_ASM_SYNTAX           },
   {"ASM_INVALID_TOKEN",     KS_ERR_ASM_INVALID_TOKEN    },
   {"ASM_INVALID_DIRECTIVE", KS_ERR_ASM_INVALID_DIRECTIVE},
   {"ASM_MISSING_SYMBOL",    KS_ERR_ASM_MISSING_SYMBOL   },
   {"ASM_INVALID_SYMBOL",    KS_ERR_ASM_INVALID_SYMBOL   },
   {"ASM_MACRO_ERROR",       KS_ERR_ASM_MACRO_ERROR      },
   {"ASM_INSN_UNSUPPORTED",  KS_ERR_ASM_INSN_UNSUPPORTED },
   {"ASM_EXPR_ERROR",        KS_ERR_ASM_EXPR_ERROR       },
   {"ASM_FIXUP_INVALID",     KS_ERR_ASM_FIXUP_INVALID    },
   {"ASM_LABEL_INVALID",     KS_ERR_ASM_LABEL_INVALID    },
   {"ASM_INVALID_OPERAND",   KS_ERR_ASM_INVALID_OPERAND  },
   {"ASM_MISSING_FEATURE",   KS_ERR_ASM_MISSING_FEATURE  },
   {"ASM_MNEMONIC_FAIL",     KS_ERR_ASM_MNEMONIC_FAIL    },
   {NULL,                    0                           },
};

static const Member X86_SYNTAX_MEMBERS[] = {
   {"ATT",   KS_X86_SYNTAX_ATT  },
   {"INTEL", KS_X86_SYNTAX_INTEL},
   {"NASM",  KS_X86_SYNTAX_NASM },
   {NULL,    0                  }
};

static const Member RADIX_MEMBERS[] = {
   {"BINARY",      KS_RADIX_BINARY     },
   {"OCTAL",       KS_RADIX_OCTAL      },
   {"DECIMAL",     KS_RADIX_DECIMAL    },
   {"HEXADECIMAL", KS_RADIX_HEXADECIMAL},
   {"BASE36",      KS_RADIX_BASE36     },
   {NULL,          0                   }
};

static const Member ARM_IT_MODE_MEMBERS[] = {
   {"ALWAYS",     KS_ARM_IT_ALWAYS    },
   {"NEVER",      KS_ARM_IT_NEVER     },
   {"ARM_ONLY",   KS_ARM_IT_ARM_ONLY  },
   {"THUMB_ONLY", KS_ARM_IT_THUMB_ONLY},
   {NULL,         0                   },
};

static PyObject *Arch, *Width, *ArchVariant, *Endian, *KsErr, *X86Syntax, *Radix, *ArmItMode;

static const struct {
   PyObject **cls;
   const char *kind;
   const char *name;
   const Member *members;
} ENUMS[] = {
   {&Arch,        "IntEnum", "Arch",        ARCH_MEMBERS        },
   {&Width,       "IntEnum", "Width",       WIDTH_MEMBERS       },
   {&ArchVariant, "IntFlag", "ArchVariant", ARCH_VARIANT_MEMBERS},
   {&Endian,      "IntEnum", "Endian",      ENDIAN_MEMBERS      },
   {&KsErr,       "IntEnum", "KsErr",       KS_ERR_MEMBERS      },
   {&X86Syntax,   "IntEnum", "X86Syntax",   X86_SYNTAX_MEMBERS  },
   {&Radix,       "IntEnum", "Radix",       RADIX_MEMBERS       },
   {&ArmItMode,   "IntEnum", "ArmItMode",   ARM_IT_MODE_MEMBERS },
};

static PyObject *KeystoneError;
static PyTypeObject *AssemblyType, *ErrorLocationType;

typedef struct {
   PyObject_HEAD
   ks_engine *ks;
   PyObject *resolver;
   PyObject *resolver_error;
   bool busy;
} Engine;

static PyObject *make_enum(
   PyObject *module,
   PyObject *enum_module,
   const char *kind,
   const char *name,
   const Member *members
) {
   PyObject *items = PyDict_New();
   if (!items) {
      return NULL;
   }

   for (const Member *member = members; member->name; member++) {
      PyObject *value = PyLong_FromLong(member->value);
      int failed      = !value || PyDict_SetItemString(items, member->name, value);
      Py_XDECREF(value);
      if (failed) {
         Py_DECREF(items);
         return NULL;
      }
   }

   PyObject *cls     = NULL;
   PyObject *factory = PyObject_GetAttrString(enum_module, kind);
   PyObject *args    = Py_BuildValue("(sO)", name, items);
   PyObject *kwargs  = Py_BuildValue("{ss}", "module", "keystone");
   if (factory && args && kwargs) {
      cls = PyObject_Call(factory, args, kwargs);
   }

   Py_XDECREF(factory);
   Py_XDECREF(args);
   Py_XDECREF(kwargs);
   Py_DECREF(items);
   if (cls && PyModule_AddObjectRef(module, name, cls) < 0) {
      Py_CLEAR(cls);
   }
   return cls;
}

static PyObject *enum_value(PyObject *cls, long value) {
   return PyObject_CallFunction(cls, "l", value);
}

static bool as_int(PyObject *value, int *out) {
   long wide = PyLong_AsLong(value);
   if (wide == -1 && PyErr_Occurred()) {
      return false;
   }

   if (wide < INT_MIN || wide > INT_MAX) {
      PyErr_SetString(PyExc_OverflowError, "value does not fit in a C int");
      return false;
   }
   *out = (int)wide;
   return true;
}

static void raise_error(ks_err code, const ks_asm_result *result) {
   PyObject *exc        = NULL;
   PyObject *code_value = enum_value(KsErr, code);
   PyObject *locations  = PyList_New(0);
   PyObject *message    = PyUnicode_FromString(ks_strerror(code));
   if (!code_value || !locations || !message) {
      goto done;
   }

   for (size_t i = 0; result && i < result->error_count; i++) {
      const ks_error_location *at = &result->errors[i];
      PyObject *text =
         PyUnicode_DecodeUTF8(at->error_message, (Py_ssize_t)strlen(at->error_message), "replace");
      PyObject *location = text ? PyStructSequence_New(ErrorLocationType) : NULL;
      if (!location) {
         Py_XDECREF(text);
         goto done;
      }

      PyStructSequence_SetItem(location, 0, PyLong_FromUnsignedLongLong(at->line_number));
      PyStructSequence_SetItem(location, 1, PyLong_FromUnsignedLongLong(at->column_number));
      PyStructSequence_SetItem(location, 2, Py_NewRef(text));
      PyObject *joined = PyUnicode_FromFormat(
         "%U\nat line %llu, column %llu: %U",
         message,
         (unsigned long long)at->line_number,
         (unsigned long long)at->column_number,
         text
      );
      Py_DECREF(text);
      int failed = PyErr_Occurred() || !joined || PyList_Append(locations, location) < 0;
      Py_DECREF(location);
      Py_DECREF(message);
      message = joined;
      if (failed) {
         goto done;
      }
   }

   exc = PyObject_CallFunctionObjArgs(KeystoneError, message, NULL);
   if (exc && PyObject_SetAttrString(exc, "code", code_value) == 0
       && PyObject_SetAttrString(exc, "locations", locations) == 0) {
      PyErr_SetObject(KeystoneError, exc);
   }

done:
   Py_XDECREF(exc);
   Py_XDECREF(code_value);
   Py_XDECREF(locations);
   Py_XDECREF(message);
}

static bool check(ks_err code) {
   if (code == KS_ERR_OK) {
      return true;
   }
   raise_error(code, NULL);
   return false;
}

static ks_engine *live(Engine *self) {
   if (self->busy) {
      PyErr_SetString(PyExc_RuntimeError, "the engine is busy assembling");
      return NULL;
   }

   if (!self->ks) {
      raise_error(KS_ERR_HANDLE, NULL);
   }

   return self->ks;
}

static const char *as_text(PyObject *value, Py_ssize_t *size) {
   const char *text = NULL;
   if (PyUnicode_Check(value)) {
      text = PyUnicode_AsUTF8AndSize(value, size);
   } else if (PyBytes_Check(value)) {
      char *buffer;
      if (PyBytes_AsStringAndSize(value, &buffer, size) == 0) {
         text = buffer;
      }
   } else {
      PyErr_SetString(PyExc_TypeError, "expected str or bytes");
   }

   if (text && strlen(text) != (size_t)*size) {
      PyErr_SetString(PyExc_ValueError, "embedded null character");
      return NULL;
   }
   return text;
}

static bool resolve_symbol(void *payload, const char *symbol, uint64_t *value) {
   Engine *self         = payload;
   bool resolved        = false;
   PyGILState_STATE gil = PyGILState_Ensure();

   // After the first exception, fail the remaining lookups so asm() raises it.
   if (!self->resolver || self->resolver_error) {
      goto done;
   }

   PyObject *name = PyUnicode_DecodeUTF8(symbol, (Py_ssize_t)strlen(symbol), "replace");
   PyObject *ret  = name ? PyObject_CallFunctionObjArgs(self->resolver, name, NULL) : NULL;
   Py_XDECREF(name);
   if (ret && ret != Py_None) {
      unsigned long long number = PyLong_AsUnsignedLongLongMask(ret);
      if (!PyErr_Occurred()) {
         *value   = number;
         resolved = true;
      }
   }
   Py_XDECREF(ret);
   if (PyErr_Occurred()) {
      self->resolver_error = PyErr_GetRaisedException();
   }

done:
   PyGILState_Release(gil);
   return resolved;
}

static PyObject *engine_new(PyTypeObject *type, PyObject *args, PyObject *kwargs) {
   static char *keywords[] = {"arch", NULL};
   PyObject *arch_value;
   int arch;
   if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O:Keystone", keywords, &arch_value)
       || !as_int(arch_value, &arch)) {
      return NULL;
   }

   ks_engine *ks;
   if (!check(ks_new(&ks, arch))) {
      return NULL;
   }

   allocfunc alloc = (allocfunc)PyType_GetSlot(type, Py_tp_alloc);
   Engine *self    = (Engine *)alloc(type, 0);
   if (!self) {
      ks_delete(ks);
      return NULL;
   }
   self->ks = ks;
   return (PyObject *)self;
}

static int engine_traverse(PyObject *op, visitproc visit, void *arg) {
   Engine *self = (Engine *)op;
   Py_VISIT(Py_TYPE(op));
   Py_VISIT(self->resolver);
   Py_VISIT(self->resolver_error);
   return 0;
}

static int engine_clear(PyObject *op) {
   Engine *self = (Engine *)op;
   Py_CLEAR(self->resolver);
   Py_CLEAR(self->resolver_error);
   return 0;
}

static void engine_dealloc(PyObject *op) {
   Engine *self       = (Engine *)op;
   PyTypeObject *type = Py_TYPE(op);
   PyObject_GC_UnTrack(op);
   if (self->ks) {
      ks_delete(self->ks);
   }
   engine_clear(op);

   freefunc tp_free = (freefunc)PyType_GetSlot(type, Py_tp_free);
   tp_free(op);
   Py_DECREF(type);
}

static PyObject *engine_close(PyObject *op, PyObject *unused) {
   Engine *self = (Engine *)op;
   if (self->busy) {
      PyErr_SetString(PyExc_RuntimeError, "the engine is busy assembling");
      return NULL;
   }

   if (self->ks) {
      ks_delete(self->ks);
      self->ks = NULL;
   }
   Py_CLEAR(self->resolver);
   Py_RETURN_NONE;
}

static PyObject *engine_enter(PyObject *op, PyObject *unused) {
   return Py_NewRef(op);
}

static PyObject *engine_exit(PyObject *op, PyObject *args) {
   return engine_close(op, NULL);
}

static PyObject *make_assembly(const ks_asm_result *result) {
   PyObject *assembly = PyStructSequence_New(AssemblyType);
   PyObject *bytes    = PyBytes_FromStringAndSize((const char *)result->bytes, result->size);
   PyObject *count    = PyLong_FromSize_t(result->stat_count);
   if (!assembly || !bytes || !count) {
      Py_XDECREF(assembly);
      Py_XDECREF(bytes);
      Py_XDECREF(count);
      return NULL;
   }

   PyStructSequence_SetItem(assembly, 0, bytes);
   PyStructSequence_SetItem(assembly, 1, count);
   return assembly;
}

static PyObject *engine_asm(PyObject *op, PyObject *args, PyObject *kwargs) {
   static char *keywords[] = {"code", "address", NULL};
   Engine *self            = (Engine *)op;
   PyObject *code;
   PyObject *address_value = NULL;
   if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O|O:asm", keywords, &code, &address_value)) {
      return NULL;
   }

   unsigned long long address = 0;
   if (address_value) {
      address = PyLong_AsUnsignedLongLong(address_value);
      if (PyErr_Occurred()) {
         return NULL;
      }
   }

   Py_ssize_t size;
   const char *text = as_text(code, &size);
   ks_engine *ks    = text ? live(self) : NULL;
   if (!ks) {
      return NULL;
   }

   ks_asm_result result = {0};
   ks_err rc;
   self->busy = true;
   Py_BEGIN_ALLOW_THREADS
      rc = ks_assemble(ks, text, address, &result);
   Py_END_ALLOW_THREADS
   self->busy = false;

   PyObject *assembly = NULL;
   if (self->resolver_error) {
      PyErr_SetRaisedException(self->resolver_error);
      self->resolver_error = NULL;
   } else if (rc != KS_ERR_OK) {
      raise_error(rc, &result);
   } else {
      assembly = make_assembly(&result);
   }
   ks_asm_result_free(&result);
   return assembly;
}

#define INT_OPTION(name, cls)                                                           \
   static PyObject *get_##name(PyObject *op, void *closure) {                           \
      ks_engine *ks = live((Engine *)op);                                               \
      return ks ? enum_value(cls, ks_get_##name(ks)) : NULL;                            \
   }                                                                                    \
                                                                                        \
   static int set_##name(PyObject *op, PyObject *value, void *closure) {                \
      int number;                                                                       \
      if (!value) {                                                                     \
         PyErr_SetString(PyExc_AttributeError, "cannot delete " #name);                 \
         return -1;                                                                     \
      }                                                                                 \
      ks_engine *ks = live((Engine *)op);                                               \
      return ks && as_int(value, &number) && check(ks_set_##name(ks, number)) ? 0 : -1; \
   }

INT_OPTION(endian, Endian)
INT_OPTION(width, Width)
INT_OPTION(arch_variant, ArchVariant)
INT_OPTION(x86_syntax, X86Syntax)
INT_OPTION(radix, Radix)
INT_OPTION(arm_it_mode, ArmItMode)

static PyObject *get_arch(PyObject *op, void *closure) {
   ks_engine *ks = live((Engine *)op);
   return ks ? enum_value(Arch, ks_get_arch(ks)) : NULL;
}

static int set_arch(PyObject *op, PyObject *value, void *closure) {
   Engine *self = (Engine *)op;
   int arch;
   if (!value) {
      PyErr_SetString(PyExc_AttributeError, "cannot delete arch");
      return -1;
   }

   ks_engine *ks = live(self);
   if (!ks || !as_int(value, &arch) || !check(ks_set_arch(ks, arch))) {
      return -1;
   }
   Py_CLEAR(self->resolver);
   return 0;
}

static PyObject *get_csky_compressed(PyObject *op, void *closure) {
   ks_engine *ks = live((Engine *)op);
   return ks ? PyBool_FromLong(ks_get_csky_compressed(ks)) : NULL;
}

static int set_csky_compressed(PyObject *op, PyObject *value, void *closure) {
   if (!value) {
      PyErr_SetString(PyExc_AttributeError, "cannot delete csky_compressed");
      return -1;
   }

   ks_engine *ks  = live((Engine *)op);
   int compressed = ks ? PyObject_IsTrue(value) : -1;
   return compressed >= 0 && check(ks_set_csky_compressed(ks, compressed)) ? 0 : -1;
}

#define STRING_OPTION(name)                                              \
   static PyObject *get_##name(PyObject *op, void *closure) {            \
      ks_engine *ks = live((Engine *)op);                                \
      return ks ? PyUnicode_FromString(ks_get_##name(ks)) : NULL;        \
   }                                                                     \
                                                                         \
   static int set_##name(PyObject *op, PyObject *value, void *closure) { \
      Py_ssize_t size;                                                   \
      if (!value) {                                                      \
         PyErr_SetString(PyExc_AttributeError, "cannot delete " #name);  \
         return -1;                                                      \
      }                                                                  \
      if (!PyUnicode_Check(value)) {                                     \
         PyErr_SetString(PyExc_TypeError, #name " must be str");         \
         return -1;                                                      \
      }                                                                  \
      const char *text = as_text(value, &size);                          \
      ks_engine *ks    = text ? live((Engine *)op) : NULL;               \
      return ks && check(ks_set_##name(ks, text)) ? 0 : -1;              \
   }

STRING_OPTION(feature)
STRING_OPTION(cpu)

static PyObject *get_symbol_resolver(PyObject *op, void *closure) {
   Engine *self = (Engine *)op;
   if (!live(self)) {
      return NULL;
   }
   return Py_NewRef(self->resolver ? self->resolver : Py_None);
}

static int set_symbol_resolver(PyObject *op, PyObject *value, void *closure) {
   Engine *self = (Engine *)op;
   if (!value) {
      PyErr_SetString(PyExc_AttributeError, "cannot delete symbol_resolver");
      return -1;
   }

   ks_engine *ks = live(self);
   if (!ks) {
      return -1;
   }

   if (value != Py_None && !PyCallable_Check(value)) {
      PyErr_SetString(PyExc_TypeError, "symbol_resolver must be callable or None");
      return -1;
   }

   bool clear               = value == Py_None;
   ks_sym_resolver resolver = {clear ? NULL : self, clear ? NULL : resolve_symbol};
   if (!check(ks_set_symbol_resolver(ks, resolver))) {
      return -1;
   }

   PyObject *old  = self->resolver;
   self->resolver = clear ? NULL : Py_NewRef(value);
   Py_XDECREF(old);
   return 0;
}

PyDoc_STRVAR(
   asm_doc, "asm($self, code, address=0)\n--\n\nAssemble code as if it were loaded at address."
);
PyDoc_STRVAR(close_doc, "close($self)\n--\n\nFree the engine. Later calls raise KsErr.HANDLE.");
PyDoc_STRVAR(arch_doc, "Setting it resets every other option and the symbol resolver.");
PyDoc_STRVAR(radix_doc, "Radix of unprefixed integer literals.");
PyDoc_STRVAR(feature_doc, "Comma-separated features.");
PyDoc_STRVAR(symbol_resolver_doc, "Called with each undefined symbol, returns its value or None.");

static PyMethodDef engine_methods[] = {
   {"asm",       (PyCFunction)(void (*)(void))engine_asm, METH_VARARGS | METH_KEYWORDS, asm_doc  },
   {"close",     engine_close,                            METH_NOARGS,                  close_doc},
   {"__enter__", engine_enter,                            METH_NOARGS,                  NULL     },
   {"__exit__",  engine_exit,                             METH_VARARGS,                 NULL     },
   {NULL,        NULL,                                    0,                            NULL     },
};

static PyGetSetDef engine_getset[] = {
   {"arch",            get_arch,            set_arch,            arch_doc,            NULL},
   {"endian",          get_endian,          set_endian,          NULL,                NULL},
   {"width",           get_width,           set_width,           NULL,                NULL},
   {"arch_variant",    get_arch_variant,    set_arch_variant,    NULL,                NULL},
   {"x86_syntax",      get_x86_syntax,      set_x86_syntax,      NULL,                NULL},
   {"radix",           get_radix,           set_radix,           radix_doc,           NULL},
   {"arm_it_mode",     get_arm_it_mode,     set_arm_it_mode,     NULL,                NULL},
   {"csky_compressed", get_csky_compressed, set_csky_compressed, NULL,                NULL},
   {"feature",         get_feature,         set_feature,         feature_doc,         NULL},
   {"cpu",             get_cpu,             set_cpu,             NULL,                NULL},
   {"symbol_resolver", get_symbol_resolver, set_symbol_resolver, symbol_resolver_doc, NULL},
   {NULL,              NULL,                NULL,                NULL,                NULL},
};

PyDoc_STRVAR(engine_doc, "Keystone(arch)\n--\n\nAn assembler for one architecture.");

static PyType_Slot engine_slots[] = {
   {Py_tp_doc,      (void *)engine_doc},
   {Py_tp_new,      engine_new        },
   {Py_tp_dealloc,  engine_dealloc    },
   {Py_tp_traverse, engine_traverse   },
   {Py_tp_clear,    engine_clear      },
   {Py_tp_methods,  engine_methods    },
   {Py_tp_getset,   engine_getset     },
   {0,              NULL              },
};

static PyType_Spec engine_spec = {
   .name      = "keystone.Keystone",
   .basicsize = sizeof(Engine),
   .flags     = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,
   .slots     = engine_slots,
};

static PyStructSequence_Field assembly_fields[] = {
   {"bytes",      "the encoded machine code"          },
   {"stat_count", "the number of statements assembled"},
   {NULL,         NULL                                },
};

static PyStructSequence_Desc assembly_desc = {"keystone.Assembly", NULL, assembly_fields, 2};

static PyStructSequence_Field location_fields[] = {
   {"line",    "1-based line number"  },
   {"column",  "1-based column number"},
   {"message", NULL                   },
   {NULL,      NULL                   },
};

static PyStructSequence_Desc location_desc = {"keystone.ErrorLocation", NULL, location_fields, 3};

static PyObject *version(PyObject *module, PyObject *unused) {
   unsigned int major, minor;
   ks_version(&major, &minor);
   return Py_BuildValue("(II)", major, minor);
}

static PyObject *arch_supported(PyObject *module, PyObject *value) {
   int arch;
   return as_int(value, &arch) ? PyBool_FromLong(ks_arch_supported(arch)) : NULL;
}

PyDoc_STRVAR(version_doc, "version($module)\n--\n\nThe C API version as (major, minor).");
PyDoc_STRVAR(
   arch_supported_doc, "arch_supported($module, arch)\n--\n\nWhether this build includes arch."
);

static PyMethodDef module_methods[] = {
   {"version",        version,        METH_NOARGS, version_doc       },
   {"arch_supported", arch_supported, METH_O,      arch_supported_doc},
   {NULL,             NULL,           0,           NULL              },
};

static struct PyModuleDef module_def = {
   PyModuleDef_HEAD_INIT,
   "keystone._keystone",
   "Keystone assembler engine.",
   -1,
   module_methods,
};

static PyObject *add_type(PyObject *module, const char *name, PyObject *type) {
   if (type && PyModule_AddObjectRef(module, name, type) < 0) {
      Py_CLEAR(type);
   }
   return type;
}

PyMODINIT_FUNC PyInit__keystone(void) {
   PyObject *module      = PyModule_Create(&module_def);
   PyObject *enum_module = module ? PyImport_ImportModule("enum") : NULL;
   if (!enum_module) {
      goto fail;
   }

   for (size_t i = 0; i < sizeof ENUMS / sizeof *ENUMS; i++) {
      *ENUMS[i].cls =
         make_enum(module, enum_module, ENUMS[i].kind, ENUMS[i].name, ENUMS[i].members);
      if (!*ENUMS[i].cls) {
         Py_DECREF(enum_module);
         goto fail;
      }
   }
   Py_DECREF(enum_module);

   KeystoneError = add_type(
      module,
      "KeystoneError",
      PyErr_NewExceptionWithDoc(
         "keystone.KeystoneError",
         "Raised with the KsErr code and the locations of every error.",
         NULL,
         NULL
      )
   );
   AssemblyType = (PyTypeObject *)add_type(
      module, "Assembly", (PyObject *)PyStructSequence_NewType(&assembly_desc)
   );
   ErrorLocationType = (PyTypeObject *)add_type(
      module, "ErrorLocation", (PyObject *)PyStructSequence_NewType(&location_desc)
   );
   PyObject *engine_type = add_type(module, "Keystone", PyType_FromSpec(&engine_spec));
   Py_XDECREF(engine_type);
   if (!KeystoneError || !AssemblyType || !ErrorLocationType || !engine_type
       || PyModule_AddStringConstant(module, "__version__", KEYSTONE_VERSION) < 0) {
      goto fail;
   }
   return module;

fail:
   Py_XDECREF(module);
   return NULL;
}
