# `Systematic Testing for C++`

![Windows CI](https://github.com/microsoft/cpp-systematic-testing/workflows/Windows%20CI/badge.svg)
![Linux CI](https://github.com/microsoft/cpp-systematic-testing/workflows/Linux%20CI/badge.svg)

**Note: This is still work-in-progress (WIP) and provided here as-is. If you are a Microsoft
employee interested in using this library please get in touch over Teams or email to discuss.**

A library for **systematically testing** concurrent C++ code and **deterministically reproducing**
bugs.

Using this library, you get access to a `SystematicTesting::TestEngine` that can be used to (1)
instrument your code for taking control of sources of concurrency and nondeterminism in your C++
code, and (2) for writing and running what we call concurrency unit tests. These look like your
regular unit tests, but can reliably test concurrent workloads (such as tasks and threads). In
regular unit tests, you would typically avoid concurrency due to flakiness, but with this library
you are encouraged to embrace concurrency in your tests to find bugs.

This library is part of the [Coyote](https://microsoft.github.io/coyote/) project by [Microsoft
Research](https://www.microsoft.com/en-us/research/). To learn more about the research behind our
technology, check out our published papers
[here](https://microsoft.github.io/coyote/learn/resources/publications).

## How to build

On Windows, run the following script for a VS 2019 developer command prompt:
```bat
scripts\build.bat
```

On Linux, run the following bash script from the root directory:
```bash
./scripts/build.sh
```

After building the project, you can find a static and shared library in `bin`.

For more detailed building instructions (e.g. if you want to build without the scripts), read
[here](./docs/building.md).

*Note: the build/ci scripts do not currently work on macOS, feel free to contribute!*

## How to use

To use the systematic testing engine in a C++ project, link the static or shared library to your
project, and include the following header file (from the [`include`](./include) directory):
```c++
#include "systematic_testing.h"
```

Then use the `SystematicTesting::TestEngine` APIs to instrument your code similar to our examples
[here](./test/integration).

## Contributing

This project welcomes contributions and suggestions. Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide a
CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repositories using our CLA.

## Code of Conduct

This project has adopted the [Microsoft Open Source Code of
Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Code of
Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact
[opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
