#!/bin/sh

for i in `find . -not -name "*.sh" -type f`; do [ -x $i ] && echo "Run $i" && $i; done
