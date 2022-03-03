/*
	Keystone Assembler Engine bindings for VB6
	Contributed by FireEye FLARE Team
	Author:  David Zimmer <david.zimmer@fireeye.com>, <dzzie@yahoo.com>
	License: Apache 2.0
	Copyright: FireEye 2017

	This dll is a small stdcall shim so VB6 can access the keystone API
*/

#include <stdio.h>
#include <conio.h>
#include <string.h>

#include <keystone/keystone.h>
#pragma comment(lib, "keystone.lib")

#define EXPORT comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)

/* - I will enable this once it makes it into the stable binary release...not tested yet..
typedef bool (__stdcall *vb_sym_resolver)(const char *symbol, uint64_t *value);
vb_sym_resolver vbResolver = NULL;

bool c_sym_resolver(const char *symbol, uint64_t *value){
	if((int)vbResolver == 0) return false;
	return vbResolver(symbol, value);
}

void __stdcall setResolver(ks_engine *ks, unsigned int lpfnVBResolver){
#pragma EXPORT
	vbResolver = (vb_sym_resolver)lpfnVBResolver;
    ks_option(ks, KS_OPT_SYM_RESOLVER, (size_t)c_sym_resolver);
}
*/

unsigned int __stdcall vs_version(unsigned int *major, unsigned int *minor){
#pragma EXPORT
	return ks_version(major,minor);
}

bool __stdcall vs_arch_supported(ks_arch arch){
#pragma EXPORT
	return ks_arch_supported(arch);
}

ks_err __stdcall vs_open(ks_arch arch, int mode, ks_engine **ks){
#pragma EXPORT
	return ks_open(arch, mode,ks);
}

ks_err __stdcall vs_close(ks_engine *ks){
#pragma EXPORT
	return ks_close(ks);
}

ks_err __stdcall vs_errno(ks_engine *ks){
#pragma EXPORT
	return ks_errno(ks);
}
const char* __stdcall vs_strerror(ks_err code){
#pragma EXPORT
	return ks_strerror(code);
}

ks_err __stdcall vs_option(ks_engine *ks, ks_opt_type type, size_t value){
#pragma EXPORT
	return ks_option(ks,type, value);
}

int __stdcall vs_asm(ks_engine *ks, const char *string, uint64_t address, unsigned char **encoding, size_t *encoding_size, size_t *stat_count){
#pragma EXPORT
	return ks_asm(ks,string,address,encoding,encoding_size,stat_count);
}

void __stdcall vs_free(unsigned char *p){
#pragma EXPORT
	return ks_free(p);
}
