#!/bin/bash
source scl_source enable devtoolset-2
source scl_source enable rh-python35
exec "$@"
