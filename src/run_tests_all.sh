#!/bin/bash

echo Started at: $(date)

./run_tests_python_all.sh
./run_tests_java.sh

echo Finished at: $(date)
