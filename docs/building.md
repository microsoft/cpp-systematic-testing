## Building the project on Windows

On Windows, run the following script for a VS 2019 developer command prompt:
```bat
scripts\build.bat
```

Or, to build manually, open the project as a Visual Studio 2019 CMake project by selecting the
CMakeLists.txt file and then build the project.

After building the project, you can find a static and shared library in `bin`.

## Building the project on Linux

On Linux, run the following bash script from the root directory:
```bash
./scripts/build.sh
```

Or, to build manually, follow these commands from the root directory:
```bash
mkdir build
cd build
cmake -G "Ninja" -DCMAKE_BUILD_TYPE=Release ..
ninja
```

To build for debug under Linux, add to the `-DCMAKE_BUILD_TYPE=Debug` flag when invoking `cmake`.

After building the project, you can find a static and shared library in `bin`.
