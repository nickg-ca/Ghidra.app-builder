#!/usr/bin/swift -O

import Foundation
import Darwin
import CommonCrypto

print("Ghidra.app build")

//modified from https://stackoverflow.com/questions/25467082/using-sysctlbyname-from-swift 
func platform() -> String {
	var size = 0
	sysctlbyname("hw.optional.arm64", nil, &size, nil, 0)
	if size == 0 {
		return "intel"
	}
	var arm64 = [CChar](repeating: 0,  count: size)
	sysctlbyname("hw.optional.arm64", &arm64, &size, nil, 0)
	if arm64[0] == 1 {
		return "arm64"
	}
	return "intel"
}

let arch = platform()
print("Building for \(arch)")

let ghidraVersion = "10.1"
let ghidraDate = "20211210"
let ghidraUrl = URL(string: "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_\(ghidraVersion)_build/ghidra_\(ghidraVersion)_PUBLIC_\(ghidraDate).zip")!
let ghidraHash = "99139c4a63a81135b3b63fe9997a012a6394a766c2c7f2ac5115ab53912d2a6c"
let ghidraPath = "ghidra_\(ghidraVersion)_PUBLIC"

//Leaving this here in case I need to go back to JDK 11 for some reason
//let jdkVersion = "zulu11.50.19-ca-jdk11.0.12"
//let jdkHash = arch == "intel" ? "0b8c8b7cf89c7c55b7e2239b47201d704e8d2170884875b00f3103cf0662d6d7" :
//	"e908a0b4c0da08d41c3e19230f819b364ff2e5f1dafd62d2cf991a85a34d3a17"
let jdkVersion = "zulu17.30.15-ca-jdk17.0.1"
let jdkHash = arch == "intel" ? "09d64fe576373b4314422811bc8402fbb7700176822b0e1e2bf2ff8a6cad10eb" :
	"ce10425ce9cefdfb23ebeabebc0944cfb41531114a2d5bd89e3c19cc5cfa9913"

let jdkUrl = arch == "intel" ? URL(string: "https://cdn.azul.com/zulu/bin/\(jdkVersion)-macosx_x64.tar.gz")! :
       URL(string: "https://cdn.azul.com/zulu/bin/\(jdkVersion)-macosx_aarch64.tar.gz")!
let jdkPath = arch == "intel" ? "\(jdkVersion)-macosx_x64" :
       "\(jdkVersion)-macosx_aarch64"

var urls = [ghidraUrl: ghidraHash,
	jdkUrl: jdkHash]

let gradleVersion = "gradle-7.3.2"
let gradleUrl = URL(string: "https://services.gradle.org/distributions/\(gradleVersion)-bin.zip")!
let gradleHash = "23b89f8eac363f5f4b8336e0530c7295c55b728a9caa5268fdd4a532610d5392"
let ghidraSourceUrl = URL(string: "https://github.com/NationalSecurityAgency/ghidra/archive/refs/tags/Ghidra_\(ghidraVersion)_build.zip")!
let ghidraSourceHash = "4c67a316a1b5a73776f8cfbc3e1ae01d3d57ca515d0810d3823d90e985aa174c"
if arch == "arm64" {
	//For Apple Silicon I additionally rebuild the decompiler/sleigh so we get arm64 binaries
	//urls[ghidraSourceUrl] = ghidraSourceHash
	urls[gradleUrl] = gradleHash
}

guard let hostnameOutput = System("/bin/hostname", ["-s"]) else {
	print("Couldn't get hostname")
	exit(1)
}

let hostname = hostnameOutput.trimmingCharacters(in: .whitespacesAndNewlines)

if FileManager.default.fileExists(atPath: "Ghidra.app") {
	print("Ghidra.app already exists. Delete or rename it to rebuild")
	exit(1)
}
else {
        //Create app directories
        do {
                try FileManager.default.createDirectory(atPath: "Ghidra.app/Contents/MacOS", withIntermediateDirectories:true)
                try FileManager.default.createDirectory(atPath: "Ghidra.app/Contents/Resources", withIntermediateDirectories:true)
		try FileManager.default.copyItem(atPath: "ghidra.icns", toPath: "Ghidra.app/Contents/Resources/ghidra.icns")
        }
        catch {
                print(error.localizedDescription)
                exit(1)
        }
}

if !FileManager.default.fileExists(atPath: "cache") {
	//Create cache directory
	do {
		try FileManager.default.createDirectory(atPath: "cache", withIntermediateDirectories:false)
	}
	catch {
		print(error.localizedDescription)
		exit(1)
	}
}

//from https://stackoverflow.com/questions/25388747/sha256-in-swift
func sha256(_ data : Data) -> Data {
	var hash = [UInt8](repeating: 0,  count: Int(CC_SHA256_DIGEST_LENGTH))
	data.withUnsafeBytes {
		_ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash)
	}
	return Data(hash)
}

for (url, hash) in urls {
	let alreadyExists = FileManager.default.fileExists(atPath: "cache/"+hash)
	do {
		let localPath = URL(fileURLWithPath: "cache/"+hash)
		if !alreadyExists {
			print("Downloading \(url.absoluteString)")
			let data = try Data(contentsOf: url, options: [.uncached])
			print("Writing to \(localPath.absoluteString)")
			try data.write(to: localPath)
		}
		print("Verifying hash of \(localPath.absoluteString)")
		let data = try Data(contentsOf: localPath, options: [.uncached])
		print("data loaded")
		let downloadedHash = sha256(data).reduce("") { res, byte in
			res + String(format: "%02hhx", byte)
		}
		print("downloaded hash: \(downloadedHash)")
		if downloadedHash != hash {
			print("\(url.absoluteString) does not match \(localPath.absoluteString)")
			print("\(hash) expected, received \(downloadedHash)")
			exit(1)
		}
		print("hash verified")
	}
	catch {
		print(error.localizedDescription)
		exit(1)
	}
}
print("All hashes verified")

func noOutSystem(_ executable: String, _ arguments: [String]? = [], _ environment: [String: String]? = nil) {
	let process = Process()
	process.arguments = arguments
	process.qualityOfService = .background
	process.executableURL = URL(fileURLWithPath: executable)
	process.standardOutput = FileHandle.standardOutput
	process.standardInput = nil
	process.standardError = FileHandle.standardError
	if environment != nil && process.environment != nil {
		for (variable, value) in environment! {
			process.environment![variable] = value
		}
	}
	else if environment != nil {
		process.environment = environment!
	}

	do {
		
		try process.run()
		process.waitUntilExit()
	}
	catch {
		print("Error running process \(executable):")
		print(error.localizedDescription)
		exit(1)
	}
}
func System(_ executable: String, _ arguments: [String]? = [], _ environment: [String: String]? = nil) -> String? {
	let process = Process()
	process.arguments = arguments
	process.qualityOfService = .background
	process.executableURL = URL(fileURLWithPath: executable)
	let standardOutput = Pipe()
	process.standardOutput = standardOutput
	process.standardInput = nil
	process.standardError = FileHandle.standardError
	if environment != nil && process.environment != nil {
		for (variable, value) in environment! {
			process.environment![variable] = value
		}
	}
	else if environment != nil {
		process.environment = environment!
	}

	do {
		
		try process.run()
		process.waitUntilExit()
	}
	catch {
		print("Error running process \(executable):")
		print(error.localizedDescription)
		exit(1)
	}
	let output = String(decoding: standardOutput.fileHandleForReading.availableData, as: UTF8.self)
	if output == "" {
		return nil
	}
	return output
}


let plist = """
{
  "CFBundleDisplayName": "Ghidra",
  "CFBundleDevelopmentRegion": "English",
  "CFBundleExecutable": "ghidra",
  "CFBundleIconFile": "ghidra.icns",
  "CFBundleIdentifier": "local.\(hostname).ghidra_dot_app",
  "CFBundleInfoDictionaryVersion": "6.0",
  "CFBundleName": "Ghidra",
  "CFBundlePackageType": "APPL",
  "CFBundleShortVersionString": "\(ghidraPath)",
  "CFBundleVersion": "\(ghidraPath)",
  "LSMinimumSystemVersion": "11.6.2",
}
"""

let plistFilename = "Ghidra.app/Contents/Info.plist"
FileManager.default.createFile(atPath: plistFilename, contents: plist.data(using: .utf8)!)
let _ = System("/usr/bin/plutil", ["-convert", "binary1", plistFilename])

let platformCheck = """
INTEL=$(sysctl -q hw.optional.arm64 | grep 'hw.optional.arm64: 1'>/dev/null; echo $?)
if [ ! $INTEL = \(arch == "intel" ? "1" : "0") ]; then
	osascript -e 'display dialog "This Ghidra.app not built to support your platform (\(arch)).\nPlease rebuild it for your platform."'
	exit
fi
"""

let wrapperScript = """
#!/bin/zsh
\(platformCheck)
ROOT_DIR=`dirname $0`/../../
export JAVA_HOME="$ROOT_DIR/Contents/Resources/\(jdkPath)"
export PATH="${JAVA_HOME}/bin:${PATH}"
export MAXMEM=$(($(sysctl -n hw.memsize)/1024/1024/1024))G
exec "$ROOT_DIR/Contents/Resources/\(ghidraPath)/ghidraRun"
"""

print("Creating wrapper script")
let wrapperFilename = "Ghidra.app/Contents/Resources/ghidra.sh"
FileManager.default.createFile(atPath: wrapperFilename,
	contents: wrapperScript.data(using:.utf8)!,
	attributes: [.posixPermissions: 0o755])
print("Wrapper script created")

//This run binary is a bit weird because I used to just run a ghidra script directly.
//I do this because if you try to use a script as the CFBundleExecutable macOS asks to install Rosetta.
//If I (or someone else) ever have the time reversing the app loader to figure out how that works might
//be pretty interesting.
print("Compiling run binary")
let _ = noOutSystem("/usr/bin/swiftc",["ghidra.swift","-o","Ghidra.app/Contents/MacOS/ghidra"])
print("Run binary compiled")

print("Untaring the JDK")
let _ = System("/usr/bin/tar", ["Jxf", "cache/\(urls[jdkUrl]!)", "-C", "Ghidra.app/Contents/Resources"])
print("JDK extracted, unzipping Ghidra")
let _ = System("/usr/bin/unzip", ["-ouqq", "cache/\(urls[ghidraUrl]!)", "-d", "Ghidra.app/Contents/Resources"])
print("Ghidra extracted")

if arch == "intel" {
	//No need to rebuild native components, so just return
	exit(0)
}

print("Extracting gradle")
let _ = System("/usr/bin/unzip", ["-ouqq", "cache/\(urls[gradleUrl]!)", "-d", "cache/gradle"])
print("Gradle extracted")

let pwd = FileManager.default.currentDirectoryPath
let ghidraDir = "\(pwd)/Ghidra.app/Contents/Resources/ghidra_\(ghidraVersion)_PUBLIC/"
if !FileManager.default.changeCurrentDirectoryPath("\(ghidraDir)") {
	print("Couldn't cd to \(ghidraDir)")
	exit(1)
}

let newpwd = FileManager.default.currentDirectoryPath
print("pwd: \(newpwd)")

setenv("JAVA_HOME","\(pwd)/Ghidra.app/Contents/Resources/\(jdkPath)",1)
setenv("GRADLE_OPTIONS","-XX:+TieredCompilation -XX:TieredStopAtLevel=1",1)
let currentPath = String(utf8String: getenv("PATH")!)!
let newPath = "\(currentPath):\(pwd)/cache/gradle/\(gradleVersion)/bin"
print("Setting PATH=\(newPath)")
setenv("PATH",newPath,1)

print("Building for ARM64")
let _ = noOutSystem("\(ghidraDir)/support/buildNatives",[])
print("Native binaries built, all done")

