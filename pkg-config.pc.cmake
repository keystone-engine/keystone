Name: @PROJECT_NAME@
Description: Keystone assembler engine
Version: @PROJECT_VERSION@
prefix=@PC_PREFIX@
exec_prefix=${prefix}
libdir=@PC_LIBDIR@
includedir=@PC_INCLUDEDIR@
Libs: -L${libdir} -lkeystone
Cflags: -I${includedir}
