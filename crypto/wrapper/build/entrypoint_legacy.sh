#!/bin/bash
source scl_source enable devtoolset-2
# Python35 installed from sources and absent in SCL
#source scl_source enable rh-python35
pip3 install protobuf
exec "$@"
