#!/bin/bash

echo "Building the C++ systematic testing engine..."

# Install ninja build dependency, if it does not already exist
sudo apt-get install ninja-build -y

# Create build directory
rm -r ./build
mkdir ./build
cd ./build

# Build the project
cmake -G "Ninja" -DCMAKE_BUILD_TYPE=Release ..
retVal=$?
if [ $retVal -eq 0 ]
then
    ninja
    retVal=$?
fi

cd ..

if [ $retVal -eq 0 ]
then
    echo "Successfully built the project."
else
    echo "Failed to build the project."
fi
exit $retVal
