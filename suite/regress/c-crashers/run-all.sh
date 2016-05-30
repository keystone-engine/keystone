#!/bin/sh

for i in $(find . -not -name "*.sh" -type f | sort -n); do
    [ -x $i ] && echo "\nRun $i" && $i
done
