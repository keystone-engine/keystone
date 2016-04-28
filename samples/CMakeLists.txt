# Sample for Keystone assembler engine (www.keystone-engine.org).
# By Nguyen Anh Quynh, 2016

# For Linux, be sure to install Keystone before compiling this
# For Windows, be sure to copy keystone.dll or keystone.lib
# to this directory before compiling

cmake_minimum_required(VERSION 2.8)

project(sample)

# For Linux, be sure to install Keystone before compiling this
# For Windows, make sure to point to include dir of Keystone
include_directories("../../include")

add_executable(sample sample.c)

target_link_libraries(sample keystone)
