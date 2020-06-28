#  About TortoiseFuzz

We propose coverage accounting, an innovative approach that evaluates code coverage by security impacts. Based on the proposed metrics, we design a new scheme to prioritize fuzzing inputs and develop TortoiseFuzz, a greybox fuzzer for memory corruption vulnerabilities. 
Read the [NDSS 2020 paper (Not all coverage measurements are equal: fuzzing by coverage accounting for input prioritization)](https://www.ndss-symposium.org/ndss-paper/not-all-coverage-measurements-are-equal-fuzzing-by-coverage-accounting-for-input-prioritization/) for more details. TortoiseFuzz is developed based on top of Michal Zalewski's  (lcamtuf@google.com) AFL.

# Environment
Tested on Ubuntu 16.04 64bit and LLVM 6.0.  
The tested program code is in this [link](https://drive.google.com/open?id=1y9DqUCIt0TwS1hJ9TPp7OGtrnK60aP4J).

### LLVM
Before install TortoiseFuzz, user should prepare llvm.
- Download clang 6.0.0 source code from the [link](http://releases.llvm.org/download.html). You at least need to download LLVM source code and Clang source code. 
    ```
    $ wget https://releases.llvm.org/6.0.0/llvm-6.0.0.src.tar.xz
    $ wget https://releases.llvm.org/6.0.0/cfe-6.0.0.src.tar.xz
    ```
- Decompression the downloaded archives:
    ```
    $ tar -xvf llvm-6.0.0.src.tar.xz && mv llvm-6.0.0.src llvm
    $ tar -xvf cfe-6.0.0.src.tar.xz && mv cfe-6.0.0.src llvm/tools/clang
    ```
- Compile clang. `-DLLVM_ENABLE_ASSERTIONS=On` is required, otherwise the TortoiseFuzz maybe won't work properly.
    ```
    $ mkdir build
    $ cmake -G "Unix Makefiles" -DLLVM_ENABLE_ASSERTIONS=On -DCMAKE_BUILD_TYPE=Release ../llvm
    $ make -j4
    $ make install
    ```

# Install TortoiseFuzz
- Clone repository:
    ```
    $ git clone https://github.com/TortoiseFuzz/TortoiseFuzz.git
    ```
- Compile:
    ```
    $ cd TortoiseFuzz
    $ make
    ```

# Usage
### Manually
Here we take bb_metric as an example.
1. Compile the target program:
   ```
    CC=/path_to_TF/bb_metric/afl-clang-fast \
    CXX=/path_to_TF/bb_metric/afl-clang-fast++ \
    ./configure \
    --prefix=/path_to_compiled_program
   ```
2. Start fuzz, use `-s` argument to activate our tool:
   ```
    /path_to_TF/bb_metric/afl-fuzz -s -i in -o out_bb -- /path_to_compiled_program ...
   ```

### Automatically
1. Compile the target program:
    Script `compile.py` can be used to compile the target program automatically, and the argument of the compiling process and the path of TortoiseFuzz should be set in the *compile_arg.json* file. There is a sample json file here. To compile program `libtiff`, user should provide three argument:
    - The first argument decides how to make the build folder, under most conditions, `mkdir` is enough, but you could also use `cp` to copy the folder.
    - The second argument decides the compiling method, like doing `cmake` or configure (`conf`) first and then make, or directly `make`. 
    - The third argument is the extra flag, like `-m32` to compile the 32 bit program, ` ` means default option (64 bit program). 
    
    ```json
    [{
    "libtiff"     : ["mkdir", "conf", "-m32"]
    },
    {
    "tofuzz_path" : [absolute_path_to_tofuzz]
    }]
    ```

    To use this script, the file location should be like this:  

    ```
    ├── libtiff
    │   └── code
    ├── compile.py
    ```

    The command to use this script is like:

    ```
    $ python compile.py evaluation/compile_arg.json PROGRAM_NAME
    ```

2. Start fuzz:
The *fuzz_tf.py* could automatically start the fuzzing process in the tmux, and the argument of the target program and AFL is set in the *fuzz_arg.json*.
The json is like 
    ```json
    [
        {
            "PACKAGE": [ADDITION_AFL_ARG, PROGRAM_ARG], 
        },
        {
            "tofuzz_path" : [absolute_path_to_tofuzz]
        }
    ]
        
    ```
The `ADDITION_AFL_ARG` is the extra argument for the fuzzer, like `-m 1000`; the `PROGRAM_ARG` is the command for the tested program, for catdoc it is `catdoc @@`.
To use this script, the file location should be like this:  

```
    ├── catdoc
    │   ├── bin_bb
    │   │   └── bin
    │   │       └── catdoc
    │   ├── bin_func     
    │   ├── bin_loop     
    │   └── in                      // the init seeds should be here
    └── fuzz_tf.py
```

The command to use this script is like:

```
$ python fuzz_tf.py evaluation/fuzz_arg.json PROGRAM_NAME
```