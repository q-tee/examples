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
user@machine:~/examples$ mkdir intermediate
user@machine:~/examples$ cd intermediate
user@machine:~/examples/intermediate$ cmake .. -G "Unix Makefiles" -D CMAKE_BUILD_TYPE=Release
user@machine:~/examples/intermediate$ make
```
3. output files will be written to the `build` directory

# further information
you can read about installation of particular libraries, contributing and look for other general information on the [q-tee](https://github.com/q-tee/) main page.
