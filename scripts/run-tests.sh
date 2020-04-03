#!/bin/bash

echo "Running the C++ systematic testing engine tests..."

cd ./build
retVal=$?
if [ $retVal -ne 0 ]
then
    echo "Failed to detect tests. Have you built the project?"
    exit $retVal
fi

ctest
retVal=$?
if [ $retVal -eq 0 ]
then
    echo "Result: all tests passed."
else
    echo "Result: one or more tests failed."
fi

cd ..

exit $retVal
