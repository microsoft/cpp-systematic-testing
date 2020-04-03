@echo off

echo Running the C++ systematic testing engine tests...

cd build
if %ERRORLEVEL% NEQ 0 goto notbuilt

ctest
if %ERRORLEVEL% NEQ 0 goto testfail

echo Result: all tests passed.

:done
cd ..
exit /B %ERRORLEVEL%

:notbuilt
echo Failed to detect tests. Have you built the project?
goto done

:testfail
echo Result: one or more tests failed.
goto done
