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

let ghidraVersion = "10.0.3"
let ghidraDate = "20210908"
let ghidraUrl = URL(string: "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_\(ghidraVersion)_build/ghidra_\(ghidraVersion)_PUBLIC_\(ghidraDate).zip")!
let ghidraHash = "1e1d363c18622b9477bddf0cc172ec55e56cac1416b332a5c53906a78eb87989"
let ghidraPath = "ghidra_\(ghidraVersion)_PUBLIC"

//Leaving this here in case I need to go back to JDK 11 for some reason
//let jdkVersion = "zulu11.50.19-ca-jdk11.0.12"
//let jdkHash = arch == "intel" ? "0b8c8b7cf89c7c55b7e2239b47201d704e8d2170884875b00f3103cf0662d6d7" :
//	"e908a0b4c0da08d41c3e19230f819b364ff2e5f1dafd62d2cf991a85a34d3a17"
let jdkVersion = "zulu16.32.15-ca-jdk16.0.2"
let jdkHash = arch == "intel" ? "3578018ff2a2c5392768261ba3707eacea35d4d2261f90835085342e14c2b4ca" :
	"ddb51f0dc2cbc9a84b7944450202c055aa41647beab5a9bc1876d64c0e8c4288"

let jdkUrl = arch == "intel" ? URL(string: "https://cdn.azul.com/zulu/bin/\(jdkVersion)-macosx_x64.tar.gz")! :
       URL(string: "https://cdn.azul.com/zulu/bin/\(jdkVersion)-macosx_aarch64.tar.gz")!
let jdkPath = arch == "intel" ? "\(jdkVersion)-macosx_x64" :
       "\(jdkVersion)-macosx_aarch64"

var urls = [ghidraUrl: ghidraHash,
	jdkUrl: jdkHash]

let gradleVersion = "gradle-7.2"
let gradleUrl = URL(string: "https://services.gradle.org/distributions/\(gradleVersion)-bin.zip")!
let gradleHash = "f581709a9c35e9cb92e16f585d2c4bc99b2b1a5f85d2badbd3dc6bff59e1e6dd"
let ghidraSourceUrl = URL(string: "https://github.com/NationalSecurityAgency/ghidra/archive/refs/tags/Ghidra_\(ghidraVersion)_build.zip")!
let ghidraSourceHash = "4c67a316a1b5a73776f8cfbc3e1ae01d3d57ca515d0810d3823d90e985aa174c"
if arch == "arm64" {
	//For Apple Silicon I additionally rebuild the decompiler/sleigh so we get arm64 binaries
	urls[ghidraSourceUrl] = ghidraSourceHash
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
		let downloadedHash = sha256(data).reduce("") { res, byte in
			res + String(format: "%02hhx", byte)
		}
		if downloadedHash != hash {
			print("\(url.absoluteString) does not match \(localPath.absoluteString)")
			print("\(hash) expected, received \(downloadedHash)")
			exit(1)
		}
	}
	catch {
		print(error.localizedDescription)
		exit(1)
	}
}

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
  "LSMinimumSystemVersion": "11.0",
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
#!/bin/bash
\(platformCheck)
ROOT_DIR=`dirname $0`/../../
export JAVA_HOME="$ROOT_DIR/Contents/Resources/\(jdkPath)"
export PATH="${JAVA_HOME}/bin:${PATH}"
export MAXMEM=16G
exec "$ROOT_DIR/Contents/Resources/\(ghidraPath)/ghidraRun"
"""

let wrapperFilename = "Ghidra.app/Contents/MacOS/ghidra"
FileManager.default.createFile(atPath: wrapperFilename,
	contents: wrapperScript.data(using:.utf8)!,
	attributes: [.posixPermissions: 0o755])

let _ = System("/usr/bin/tar", ["Jxf", "cache/\(urls[jdkUrl]!)", "-C", "Ghidra.app/Contents/Resources"])
let _ = System("/usr/bin/unzip", ["-ouqq", "cache/\(urls[ghidraUrl]!)", "-d", "Ghidra.app/Contents/Resources"])

if arch == "intel" {
	//No need to rebuild native components, so just return
	exit(0)
}

let _ = System("/usr/bin/unzip", ["-ouqq", "cache/\(urls[gradleUrl]!)", "-d", "cache/gradle"])
let _ = System("/usr/bin/unzip", ["-ouqq", "cache/\(urls[ghidraSourceUrl]!)", "-d", "cache/ghidraSource"])

let ghidraSourceDir = "cache/ghidraSource/ghidra-Ghidra_\(ghidraVersion)_build"

let pwd = FileManager.default.currentDirectoryPath
if !FileManager.default.changeCurrentDirectoryPath("\(pwd)/\(ghidraSourceDir)") {
	print("Couldn't cd to \(ghidraSourceDir)")
	exit(1)
}

let newpwd = FileManager.default.currentDirectoryPath
print("\(newpwd)")

setenv("JAVA_HOME","\(pwd)/Ghidra.app/Contents/Resources/\(jdkPath)",1)
setenv("GRADLE_OPTIONS","-XX:+TieredCompilation -XX:TieredStopAtLevel=1",1)

print("Installing Ghidra dependencies (this might take a while)")
let _ = noOutSystem("\(pwd)/cache/gradle/\(gradleVersion)/bin/gradle",
	["-q", "-I", "gradle/support/fetchDependencies.gradle", "init"])
print("Building native decompile/sleigh (this will take a while)")
let _ = noOutSystem("\(pwd)/cache/gradle/\(gradleVersion)/bin/gradle",
	["-q", "-i", "buildNatives_osx64"])
// TODO: change to this once the new build system currently in master is released
//	["-q", "-i", "buildNatives_mac_\(arch == "intel" ? "x86_64" : "arm_64" )"])

print("Native binaries built, copying")
let decompileDest = "\(pwd)/Ghidra.app/Contents/Resources/ghidra_\(ghidraVersion)_PUBLIC/Ghidra/Features/Decompiler/os/osx64/decompile"
try! FileManager.default.removeItem(at: URL(fileURLWithPath:decompileDest))
let sleighDest = "\(pwd)/Ghidra.app/Contents/Resources/ghidra_\(ghidraVersion)_PUBLIC/Ghidra/Features/Decompiler/os/osx64/sleigh"
try! FileManager.default.removeItem(at: URL(fileURLWithPath:sleighDest))
try! FileManager.default.copyItem(atPath: "\(newpwd)/Ghidra/Features/Decompiler/build/os/osx64/decompile", toPath: decompileDest)
try! FileManager.default.copyItem(atPath: "\(newpwd)/Ghidra/Features/Decompiler/build/os/osx64/sleigh", toPath: sleighDest)
