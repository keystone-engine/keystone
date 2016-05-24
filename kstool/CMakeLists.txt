# Kstool for Keystone assembler engine.
# By Nguyen Anh Quynh, 2016

cmake_minimum_required(VERSION 2.8)

project(kstool)

include_directories("../include")

add_executable(kstool kstool.cpp)

target_link_libraries(kstool keystone)

install(TARGETS kstool DESTINATION bin)
