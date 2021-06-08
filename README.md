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
$ git clone https://github.com/nickg-ca/ghidra_app.git
$ cd ghidra_app
$ ./build.swift
```

At this point, you should have `Ghidra.app` in the `ghidra_app` directory.

The script will download Ghidra (currently version 10.0 beta which is the most
recent at time of writing, 2021-06-07) and the Azul OpenJDK 11 binaries.

If you're using BinDiff on Apple Silicon you probably need to process the diffs
via the command line:

```
/Applications/BinDiff/BinDiff.app/Contents/MacOS/bin/bindiff --output_dir OUTPUT_DIR file1.BinExport file2.BinExport
```

The downloads will be cached for future use in the `cache` directory. You may
delete this directory after building if you wish.
