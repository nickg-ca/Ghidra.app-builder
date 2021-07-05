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

The script will download Ghidra (currently version 10.0 which is the most
recent at time of writing, 2021-07-04) and Azul Zulu JDK 11 binaries.

I'm no longer building BinExport from BinDiff because the Ghidra plugin now included in the latest BinDiff.

The downloads will be cached for future use in the `cache` directory. You may
delete this directory after building if you wish.

# Apple Silicon decompile/sleigh

On an arm64 mac the script will also download a few extra things and recompile the decompile/sleigh binaries to target arm64. This worked on my machine, but I haven't tested it very much so you might wish to remove that bit if you run into issues, and wait for the NSA to implement something themselves.
