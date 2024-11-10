Simple script to create a packaged version of Ghidra for Apple Silicon Macs.

# Dependencies
Probably the Xcode command line tools for git, but the script downloads
everything else it needs like a Java runtime. Nothing is intentionally
installed or written outside the script's directory.

# Usage
Clone the repository and run the `build.sh` script.
```
$ git clone https://github.com/nickg-ca/Ghidra.app-builder.git
$ cd Ghidra.app-builder
$ ./build.sh
```

At this point, you should have `Ghidra.app` in the `Ghidra.app-builder` directory.

The script will download the latest stable Ghidra and Adoptium Temurin JDK 21
binaries. It also builds BinExport.

The downloads will be cached for future use in the `cache` directory. You may
delete this directory after building if you wish. The script won't reuse the
downloads.
