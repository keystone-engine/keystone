#!/bin/bash

for i in $(seq 1 100)
do
    python test_diag_printer.py

    if [ $? -ne 0 ]
    then
        echo "Diagnostic Handler test failed"
        exit
    fi
done
echo "Diagnostic Handler test pass"
