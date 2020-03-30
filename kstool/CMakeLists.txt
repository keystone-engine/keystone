# Kstool for Keystone assembler engine.
# By Nguyen Anh Quynh, 2016

cmake_minimum_required(VERSION 2.8)

project(kstool)

include_directories("../include")
include_directories("./")

if (WIN32)
  add_executable(kstool getopt.c kstool.cpp)
else()
  add_executable(kstool kstool.cpp)
endif()

target_link_libraries(kstool keystone)

install(TARGETS kstool DESTINATION bin)
