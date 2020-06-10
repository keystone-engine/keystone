#!/bin/bash
set -e -x

cd /work/bindings/python

sudo rm /usr/bin/python && sudo ln -s /opt/python/cp36-cp36m/bin/python /usr/bin/python; python -V

function repair_wheel {
    wheel="$1"
    if ! auditwheel show "$wheel"; then
        echo "Skipping non-platform wheel $wheel"
    else
        auditwheel repair "$wheel" -w /work/bindings/python/dist/
    fi
}


# Compile wheels
/opt/python/cp36-cp36m/bin/python setup.py bdist_wheel -d wheelhouse

# Bundle external shared libraries into the wheels
for whl in wheelhouse/*.whl; do
    repair_wheel "$whl"
done
