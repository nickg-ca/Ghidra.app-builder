#!/usr/bin/swift

import Foundation
import Darwin
import CommonCrypto

print("Ghidra.app build")

let dateFormatter = DateFormatter()
dateFormatter.dateFormat = "yyyyMMdd"
let date = Date()
let todaysDate = dateFormatter.string(from: date)
print("Today is \(todaysDate)")

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

let ghidraUrl = URL(string: "https://ghidra-sre.org/ghidra_10.0-BETA_PUBLIC_20210521.zip")!
let ghidraHash = "f549dfccd0f106f9befb0b5afb7f2f86050356631b29bc9dd15d7f0333acbc7e"
let ghidraPath = "ghidra_10.0-BETA_PUBLIC"

let gradleVersion = "gradle-7.1-rc-1"
let gradleUrl = URL(string: "https://services.gradle.org/distributions/gradle-7.1-rc-1-bin.zip")!
let gradleHash = "bac27c9878c4aa5b4b35f92105ca71de2ad39c323bc81117e611c65f2dffd941"

let binexportVersion = "4d03d2ab4fa20990befe36ce3eb8e2679a72e772"
let binexportUrl = URL(string: "https://github.com/google/binexport/archive/\(binexportVersion).zip")!
let binexportHash = "f98ff2bb95a2e78f72db1757f05b2ff7a390fc0abe707fdb7019f4c1236ee053"

let jdkVersion = "zulu11.48.21-ca-jdk11.0.11"
let jdkHash = arch == "intel" ? "866b25c47aa3bedddc57fbe38fd7d2e0f888d314b85d1e88b2fb12100f3c166c" :
"0c52621329b0d148c816b4c21e91386240bf57eb53ecfc4a6201f59ee983dc18"

let jdkUrl = arch == "intel" ? URL(string: "https://cdn.azul.com/zulu/bin/\(jdkVersion)-macosx_x64.tar.gz")! :
	URL(string: "https://cdn.azul.com/zulu/bin/\(jdkVersion)-macosx_aarch64.tar.gz")!
let jdkPath = arch == "intel" ? "\(jdkVersion)-macosx_x64" :
	"\(jdkVersion)-macosx_aarch64"


let urls = [gradleUrl: gradleHash,
	ghidraUrl: ghidraHash,
	binexportUrl: binexportHash,
	jdkUrl: jdkHash]

guard let hostnameOutput = System("/bin/hostname", ["-s"]) else {
	print("Couldn't get hostname")
	exit(1)
}
//
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

func System(_ executable: String, _ arguments: [String]? = [], _ environment: [String: String]? = [:]) -> String? {
	let process = Process()
	process.arguments = arguments
	process.qualityOfService = .background
	process.executableURL = URL(fileURLWithPath: executable)
	let standardOutput = Pipe()
	let standardError = Pipe()
	process.standardOutput = standardOutput
	process.standardInput = nil
	process.standardError = standardError
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
	let errorOutput = String(decoding: standardError.fileHandleForReading.availableData, as: UTF8.self)
	if errorOutput != "" {
		print("Process \(executable) error output:\n\(errorOutput)")
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
ROOT_DIR=`dirname $0`/../../../
export JAVA_HOME="$ROOT_DIR/Ghidra.app/Contents/Resources/\(jdkPath)"
export PATH="${JAVA_HOME}/bin:${PATH}"
export MAXMEM=16G
exec "$ROOT_DIR/Ghidra.app/Contents/Resources/\(ghidraPath)/ghidraRun"
"""

let wrapperFilename = "Ghidra.app/Contents/MacOS/ghidra"
FileManager.default.createFile(atPath: wrapperFilename,
	contents: wrapperScript.data(using:.utf8)!,
	attributes: [.posixPermissions: 0o755])

let _ = System("/usr/bin/tar", ["Jxf", "cache/\(urls[jdkUrl]!)", "-C", "Ghidra.app/Contents/Resources"])
let _ = System("/usr/bin/unzip", ["-ouqq", "cache/\(urls[ghidraUrl]!)", "-d", "Ghidra.app/Contents/Resources"])
let _ = System("/usr/bin/unzip", ["-ouqq", "cache/\(urls[gradleUrl]!)", "-d", "cache/gradle"])
let _ = System("/usr/bin/unzip", ["-ouqq", "cache/\(urls[binexportUrl]!)", "-d", "cache/binexport"])

let binexportBuildPath = "cache/binexport"
let binexportBuildDir="\(binexportBuildPath)/binexport-\(binexportVersion)/java"
let pwd = FileManager.default.currentDirectoryPath
print("Building binexport")

if arch == "arm64" {
	//no aarch64 builds of protoc for 3.13 so hack in a newer version for now
	let _ = System("/usr/bin/sed",
		["-i", "backupbuild",
		"s/protoc:3.13.0/protoc:3.17.3/g",
		"\(binexportBuildDir)/build.gradle"])
}

let _ = System("\(pwd)/cache/gradle/\(gradleVersion)/bin/gradle",
	["--info", "-PGHIDRA_INSTALL_DIR=\(pwd)/Ghidra.app/Contents/Resources/\(ghidraPath)", "-p", "\(binexportBuildDir)"],
	["JAVA_HOME":"\(pwd)/Ghidra.app/Contents/Resources/\(jdkPath)",
		"GHIDRA_INSTALL_DIR":"\(pwd)/Ghidra.app/Contents/Resources/\(ghidraPath)",
		"GRADLE_OPTS":"-Xms1024m -Xmx8192m"])


//Install to Ghidra.app
let _ = System("/usr/bin/unzip", ["-ouqq", "\(binexportBuildDir)/dist/\(ghidraPath)_\(todaysDate)_BinExport.zip", "-d", "\(pwd)/Ghidra.app/Contents/Resources/\(ghidraPath)/Ghidra/Extensions"])
