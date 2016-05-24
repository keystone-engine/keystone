/*

Ruby bindings for the Keystone Engine

Copyright(c) 2016 Sascha Schirra

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
version 2 as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

*/
#include "ruby.h"
#include <keystone/keystone.h>
#include "keystone.h"

VALUE KeystoneModule = Qnil;
VALUE KsClass = Qnil;
VALUE KsError = Qnil;


void Init_keystone() {
    rb_require("keystone/keystone_const");
    KeystoneModule = rb_define_module("Keystone");
    KsError = rb_define_class_under(KeystoneModule, "KsError", rb_eStandardError);

    KsClass = rb_define_class_under(KeystoneModule, "Ks", rb_cObject);
    rb_define_method(KsClass, "initialize", m_ks_initialize, 2);
    rb_define_method(KsClass, "asm", m_ks_asm, -1);
    rb_define_method(KsClass, "syntax", m_ks_get_syntax, 0);
    rb_define_method(KsClass, "syntax=", m_ks_set_syntax, 1);
}

VALUE m_ks_initialize(VALUE self, VALUE arch, VALUE mode) {
    ks_engine *_ks;
    ks_err err;
    err = ks_open(NUM2INT(arch), NUM2INT(mode), &_ks);
    if (err != KS_ERR_OK) {
      rb_raise(KsError, "%d", err);
    }

    VALUE ks = Data_Wrap_Struct(KsClass, 0, ks_close, _ks);
    rb_iv_set(self, "@ksh", ks);

    if(NUM2INT(arch) == KS_ARCH_X86){
      rb_iv_set(self, "@syntax", INT2NUM(KS_OPT_SYNTAX_INTEL));
    }
    else{
      rb_iv_set(self, "@syntax", Qnil);
    }

    return self;
}

VALUE m_ks_asm(int argc, VALUE* argv, VALUE self){
    VALUE string;
    VALUE addr;

    size_t count;
    unsigned char *encode;
    size_t size;

    ks_err err;
    ks_engine *_ks;

    VALUE to_return = rb_ary_new();

    Data_Get_Struct(rb_iv_get(self,"@ksh"), ks_engine, _ks);

    rb_scan_args(argc, argv, "11", &string, &addr);
    if (NIL_P(addr))
        addr = INT2NUM(0);

    err = ks_asm(_ks, StringValuePtr(string), NUM2INT(addr), &encode, &size, &count);
    if (err != KS_ERR_OK) {
      rb_raise(KsError, "%d", err);
    }

    if (count == 0){
        rb_ary_store(to_return, 0, Qnil);
        rb_ary_store(to_return, 1, INT2NUM(0));
    }
    else{
        rb_ary_store(to_return, 0, rb_str_new(encode, size));
        rb_ary_store(to_return, 1, INT2NUM(count));
    }
    ks_free(encode);
    return to_return;
}

VALUE m_ks_get_syntax(VALUE self){
  return rb_iv_get(self, "@syntax");
}

VALUE m_ks_set_syntax(VALUE self, VALUE val){
  ks_err err;
  ks_engine *_ks;

  Data_Get_Struct(rb_iv_get(self,"@ksh"), ks_engine, _ks);

  ks_option(_ks, KS_OPT_SYNTAX, NUM2INT(val));
  rb_iv_set(self, "@syntax", val);

  return Qnil;
}
