#!/bin/bash

readonly COLOR_BOLD="\e[1m"
readonly COLOR_GREEN="\e[32m"
readonly COLOR_NORMAL_DISPLAY="\e[0m"
readonly COLOR_RED="\e[31m"

echo
printf "== %b ==\n" "${COLOR_BOLD}keystone engine crashers${COLOR_NORMAL_DISPLAY}"
echo
num_crashed=0
num_tests=0
for crash_case in $(find . -name "crash-??-*" -not -name "*.sh" -type f | sort -n); do
  if [[ ! -x ${crash_case} ]]; then
    continue
  fi
  num_tests=$((num_tests + 1))
  { $crash_case; } > /dev/null 2> /dev/null
  if [[ $? == 0 ]]; then
    printf "  %b  %b\n" "${COLOR_GREEN}✓${COLOR_NORMAL_DISPLAY}" "${crash_case}"
  else
    num_crashed=$((num_crashed + 1))
    printf "  %b  %b\n" "${COLOR_RED}✘${COLOR_NORMAL_DISPLAY}" "${crash_case}"
  fi
done
if [[ ${num_tests} == 0 ]]; then
    echo "No tests to process. Please run 'make' to build the tests."
    echo
    exit
fi
echo
printf "** Results: %b of %b tests resulted in a crash **\n" "${COLOR_BOLD}${num_crashed}${COLOR_NORMAL_DISPLAY}" "${COLOR_BOLD}${num_tests}${COLOR_NORMAL_DISPLAY}"
echo
