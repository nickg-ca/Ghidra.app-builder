import Foundation
import Darwin

func noOutSystem(_ executable: String, _ arguments: [String]? = [], _ environment: [String: String]? = nil) {
	let process = Process()
	process.arguments = arguments
	process.qualityOfService = .userInitiated
	process.executableURL = URL(fileURLWithPath: executable)
	process.standardOutput = nil
	process.standardInput = nil
	process.standardError = nil
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

let scriptPath = Bundle.main.path(forResource: "ghidra", ofType: "sh")!
let _ = noOutSystem(scriptPath,[])

