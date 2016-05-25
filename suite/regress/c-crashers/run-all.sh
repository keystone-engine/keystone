#!/bin/sh

for i in `find . -type f`; do [ -x $i ] && echo "Run $i" && $i; done
