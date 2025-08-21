# about
example projects demonstrating work with **q-tee** libraries.

# build
- build with Visual Studio:
1. open the solution in repository root directory
2. select target architecture and build type
3. build the solution
4. output files will be written to the `build` directory
- build with CMake:
1. open terminal in repository root directory
2. create the project and build
```console
user@machine:~/examples$ cmake -B intermediate -D CMAKE_BUILD_TYPE=Release
user@machine:~/examples$ cmake --build intermediate --config=Release
```
3. output files will be written to the `build` directory

# further information
you can read about installation of particular libraries, contributing and look for other general information on the [q-tee](https://github.com/q-tee/) main page.
