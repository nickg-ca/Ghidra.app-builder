[![Swift](https://github.com/nickg-ca/Ghidra.app-builder/actions/workflows/swift.yml/badge.svg)](https://github.com/nickg-ca/Ghidra.app-builder/actions/workflows/swift.yml)

Simple script to create a packaged version of Ghidra, including Apple Silicon support.

# Dependencies
Probably the Xcode command line tools for git, but the script downloads
everything else it needs like a Java runtime. Nothing is intentionally
installed or written outside the script's directory.

# Usage
Clone the repository and run the `build.swift` script.
```
$ git clone https://github.com/nickg-ca/Ghidra.app-builder.git
$ cd Ghidra.app-builder
$ ./build.swift
```

At this point, you should have `Ghidra.app` in the `Ghidra.app-builder` directory.

The script will download Ghidra (currently version 10.1 which is the most
recent at time of writing, 2021-12-16) and Azul Zulu JDK 17 binaries.

I'm no longer building BinExport from BinDiff because the Ghidra plugin is now included in the latest BinDiff.

The downloads will be cached for future use in the `cache` directory. You may
delete this directory after building if you wish.

# Apple Silicon decompile/sleigh

On an arm64 mac the script will also download Gradle and recompile the decompile/sleigh binaries to target arm64.
