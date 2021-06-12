This was forked from [Steve Checkoway's](https://github.com/stevecheckoway) [Ghidra macOS app script](https://github.com/stevecheckoway/ghidra_app) and later rewritten in Swift for reasons which are a mystery to even myself.

The changes I made were primarily to add support for Apple Silicon and to
make the script error out if a hash mismatch is detected. I also build
the [BinExport plugin](https://github.com/google/binexport/tree/master/java/BinExport).

# Dependencies
Probably the Xcode command line tools for git, but the script downloads
everything else it needs like a Java runtime and gradle. Nothing is intentionally
installed or written outside the script's directory.

# Usage
Clone the repository and run the `build.swift` script.
```
$ git clone https://github.com/nickg-ca/Ghidra.app-builder.git
$ cd Ghidra.app-builder
$ ./build.swift
```

At this point, you should have `Ghidra.app` in the `Ghidra.app-builder` directory.

The script will download Ghidra (currently version 10.0 beta which is the most
recent at time of writing, 2021-06-07) and the Azul OpenJDK 11 binaries.

If you're using BinDiff on Apple Silicon you probably need to process the diffs
via the command line:

```
/Applications/BinDiff/BinDiff.app/Contents/MacOS/bin/bindiff --output_dir OUTPUT_DIR file1.BinExport file2.BinExport
```

The downloads will be cached for future use in the `cache` directory. You may
delete this directory after building if you wish.

# Apple Silicon decompile/sleigh

I spent a little time trying to get a universal binary build working for the decompile/sleigh tools. Because it would currently require modifying gradle itself (see https://github.com/gradle/gradle/blob/5ec3f672ed600a86280be490395d70b7bc634862/subprojects/platform-native/src/main/java/org/gradle/nativeplatform/toolchain/internal/gcc/AbstractGccCompatibleToolChain.java#L310 - the -m64 option overrides any attempt at specifying multiple architectures within the Ghidra gradle build script) as well as the Ghidra build scripts I'm not going to support it here, but if you want to manually build arm64 support you can do this:

1. curl -L https://github.com/NationalSecurityAgency/ghidra/archive/refs/tags/Ghidra_10.0-BETA_build.zip -o Ghidra_10.0-BETA_build.zip
2. unzip Ghidra_10.0-BETA_build.zip
3. cd ghidra-Ghidra_10.0-BETA_build
4. export JAVA_HOME=$(pwd)../Ghidra.app/Contents/Resources/zulu11.48.21-ca-jdk11.0.11-macosx_aarch64 
5. ../cache/gradle/gradle-7.1-rc-1/bin/gradle -I gradle/support/fetchDependencies.gradle init
6. ../cache/gradle/gradle-7.1-rc-1/bin/gradle -i buildNatives_osx64
7. cp Ghidra/Features/Decompiler/build/os/osx64/decompile ../Ghidra.app/Contents/Resources/ghidra_10.0-BETA_PUBLIC/Ghidra/Features/Decompiler/os/osx64
8. cp Ghidra/Features/Decompiler/build/os/osx64/sleigh ../Ghidra.app/Contents/Resources/ghidra_10.0-BETA_PUBLIC/Ghidra/Features/Decompiler/os/osx64
9. Use Ghidra.app as usual
