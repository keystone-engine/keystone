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
VALUE m_ks_initialize(VALUE self, VALUE arch, VALUE mode);
VALUE m_ks_asm(int argc, VALUE* argv, VALUE self);
VALUE m_ks_get_syntax(VALUE self);
VALUE m_ks_set_syntax(VALUE self, VALUE val);
