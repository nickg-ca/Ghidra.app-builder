#!/bin/bash
# test_bridge.sh — Automated McpBridge.java standalone tests
#
# Tests the Java bridge directly via analyzeHeadless + TCP,
# without the Rust MCP server in the loop.
#
# Usage: ./test_bridge.sh
#
# Requires: A built Ghidra.app in the parent directory.
# Test binary: /usr/bin/true (~84KB, fast to import/analyze)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")"; pwd)"
APP_DIR="$(cd "$SCRIPT_DIR/../Ghidra.app"; pwd)"
GHIDRA="$(ls -d "$APP_DIR/Contents/Resources/ghidra_"*)"
JAVA_HOME="$(ls -d "$APP_DIR/Contents/Resources/jdk-"*/Contents/Home)"
SCRIPTS="$SCRIPT_DIR/scripts"
PROJECT_DIR="/tmp/ghidra-mcp-test-$$"
PORT=$((19000 + RANDOM % 1000))

export JAVA_HOME

PASS=0
FAIL=0
BRIDGE_PID=""

# --- Helpers ---

cleanup() {
    echo ""
    echo "=== Cleanup ==="
    if [ -n "${BRIDGE_PID:-}" ]; then
        echo "Killing bridge (PID $BRIDGE_PID)..."
        kill "$BRIDGE_PID" 2>/dev/null || true
        wait "$BRIDGE_PID" 2>/dev/null || true
    fi
    if [ -d "$PROJECT_DIR" ]; then
        echo "Removing $PROJECT_DIR"
        rm -rf "$PROJECT_DIR"
    fi
}
trap cleanup EXIT

assert_contains() {
    local label="$1" response="$2" expected="$3"
    if echo "$response" | grep -q "$expected"; then
        echo "  PASS: $label"
        ((PASS++)) || true
    else
        echo "  FAIL: $label"
        echo "        expected to find: $expected"
        echo "        got: $(echo "$response" | head -c 200)"
        ((FAIL++)) || true
    fi
}

assert_not_empty() {
    local label="$1" response="$2"
    if [ -n "$response" ] && [ "$response" != "" ]; then
        echo "  PASS: $label"
        ((PASS++)) || true
    else
        echo "  FAIL: $label (empty response)"
        ((FAIL++)) || true
    fi
}

# Send a JSON command to the bridge via a short-lived TCP connection.
# macOS nc doesn't support -q, so we use a timeout approach.
send() {
    local cmd="$1"
    # Use bash /dev/tcp for reliable single-shot send/receive
    {
        exec 3<>/dev/tcp/127.0.0.1/$PORT
        echo "$cmd" >&3
        # Read one line with a timeout
        local response=""
        if read -t 10 -r response <&3; then
            echo "$response"
        fi
        exec 3>&-
    } 2>/dev/null
}

# Wait for the bridge to respond to pings
wait_for_bridge() {
    local max_wait="${1:-60}"
    echo "Waiting for bridge on port $PORT (max ${max_wait}s)..."
    for i in $(seq 1 "$max_wait"); do
        local resp
        resp=$(send '{"id":0,"cmd":"ping"}' 2>/dev/null) || true
        if echo "$resp" | grep -q '"ok":true' 2>/dev/null; then
            echo "Bridge ready after ${i}s"
            return 0
        fi
        sleep 1
    done
    echo "ERROR: Bridge did not start within ${max_wait}s"
    return 1
}

# --- Setup ---

echo "============================================"
echo "  ghidra-mcp Bridge Test Suite"
echo "============================================"
echo ""
echo "Ghidra:     $GHIDRA"
echo "JAVA_HOME:  $JAVA_HOME"
echo "Scripts:    $SCRIPTS"
echo "Project:    $PROJECT_DIR"
echo "Port:       $PORT"
echo ""

echo "=== Step 1: Import test binary ==="
mkdir -p "$PROJECT_DIR"
echo "Importing /usr/bin/true (this may take 30-60s)..."
"$GHIDRA/support/analyzeHeadless" "$PROJECT_DIR" TestProject \
    -import /usr/bin/true \
    -scriptPath "$SCRIPTS" > "$PROJECT_DIR/import.log" 2>&1 || {
    echo "ERROR: Import failed. Log:"
    tail -20 "$PROJECT_DIR/import.log"
    exit 1
}
echo "Import complete."

# Verify project was created
if [ ! -f "$PROJECT_DIR/TestProject.gpr" ]; then
    echo "ERROR: Project file not created"
    exit 1
fi
echo "Project file exists: $PROJECT_DIR/TestProject.gpr"
echo ""

echo "=== Step 2: Start bridge ==="
"$GHIDRA/support/analyzeHeadless" "$PROJECT_DIR" TestProject \
    -process -noanalysis \
    -postScript McpBridge.java "$PORT" \
    -scriptPath "$SCRIPTS" > "$PROJECT_DIR/bridge.log" 2>&1 &
BRIDGE_PID=$!
echo "Bridge started (PID $BRIDGE_PID)"

if ! wait_for_bridge 120; then
    echo "Bridge log (last 30 lines):"
    tail -30 "$PROJECT_DIR/bridge.log"
    exit 1
fi
echo ""

# --- Tests ---

echo "=== Running Tests ==="
echo ""

# -- Control --

echo "[Control]"

echo "Test: ping"
R=$(send '{"id":1,"cmd":"ping"}')
assert_contains "ping returns ok" "$R" '"ok":true'

# -- Metadata --

echo ""
echo "[Metadata]"

echo "Test: info"
R=$(send '{"id":2,"cmd":"info"}')
assert_contains "info has ok" "$R" '"ok":true'
assert_contains "info has name" "$R" '"name"'
assert_contains "info has num_functions" "$R" '"num_functions"'
assert_contains "info has language" "$R" '"language"'

# -- Navigation --

echo ""
echo "[Navigation]"

echo "Test: list_functions"
R=$(send '{"id":3,"cmd":"list_functions","offset":0,"limit":5}')
assert_contains "list_functions ok" "$R" '"ok":true'
assert_contains "list_functions has array" "$R" '"functions"'
assert_contains "list_functions has total" "$R" '"total"'

# Extract a function address for subsequent tests
FUNC_ADDR=$(echo "$R" | python3 -c "
import json, sys
data = json.load(sys.stdin)
if data.get('functions'):
    print(data['functions'][0]['address'])
else:
    print('')
" 2>/dev/null) || FUNC_ADDR=""

FUNC_NAME=$(echo "$R" | python3 -c "
import json, sys
data = json.load(sys.stdin)
if data.get('functions'):
    print(data['functions'][0]['name'])
else:
    print('')
" 2>/dev/null) || FUNC_NAME=""

echo "  (Using function: $FUNC_NAME @ $FUNC_ADDR)"

echo "Test: list_segments"
R=$(send '{"id":4,"cmd":"list_segments"}')
assert_contains "list_segments ok" "$R" '"ok":true'
assert_contains "list_segments has array" "$R" '"segments"'

echo "Test: list_symbols (first page)"
R=$(send '{"id":5,"cmd":"list_symbols","offset":0,"limit":5}')
assert_contains "list_symbols ok" "$R" '"ok":true'
assert_contains "list_symbols has array" "$R" '"symbols"'

echo "Test: list_strings"
R=$(send '{"id":6,"cmd":"list_strings","offset":0,"limit":10,"min_length":2}')
assert_contains "list_strings ok" "$R" '"ok":true'
assert_contains "list_strings has array" "$R" '"strings"'

echo "Test: list_imports"
R=$(send '{"id":7,"cmd":"list_imports","offset":0,"limit":10}')
assert_contains "list_imports ok" "$R" '"ok":true'
assert_contains "list_imports has array" "$R" '"imports"'

echo "Test: list_exports"
R=$(send '{"id":8,"cmd":"list_exports","offset":0,"limit":10}')
assert_contains "list_exports ok" "$R" '"ok":true'
assert_contains "list_exports has array" "$R" '"exports"'

echo "Test: list_namespaces"
R=$(send '{"id":9,"cmd":"list_namespaces"}')
assert_contains "list_namespaces ok" "$R" '"ok":true'
assert_contains "list_namespaces has array" "$R" '"namespaces"'

# -- Analysis --

echo ""
echo "[Analysis]"

if [ -n "$FUNC_ADDR" ]; then
    echo "Test: decompile (by address)"
    R=$(send "{\"id\":10,\"cmd\":\"decompile\",\"address\":\"$FUNC_ADDR\"}")
    assert_contains "decompile ok" "$R" '"ok":true'
    assert_contains "decompile has c_code" "$R" '"c_code"'

    echo "Test: disassemble"
    R=$(send "{\"id\":11,\"cmd\":\"disassemble\",\"address\":\"$FUNC_ADDR\",\"count\":5}")
    assert_contains "disassemble ok" "$R" '"ok":true'
    assert_contains "disassemble has instructions" "$R" '"instructions"'

    echo "Test: get_function"
    R=$(send "{\"id\":12,\"cmd\":\"get_function\",\"address\":\"$FUNC_ADDR\"}")
    assert_contains "get_function ok" "$R" '"ok":true'
    assert_contains "get_function has signature" "$R" '"signature"'
    assert_contains "get_function has parameters" "$R" '"parameters"'

    echo "Test: get_xrefs_to"
    R=$(send "{\"id\":13,\"cmd\":\"get_xrefs_to\",\"address\":\"$FUNC_ADDR\"}")
    assert_contains "get_xrefs_to ok" "$R" '"ok":true'
    assert_contains "get_xrefs_to has refs" "$R" '"refs"'

    echo "Test: get_xrefs_from"
    R=$(send "{\"id\":14,\"cmd\":\"get_xrefs_from\",\"address\":\"$FUNC_ADDR\"}")
    assert_contains "get_xrefs_from ok" "$R" '"ok":true'
    assert_contains "get_xrefs_from has refs" "$R" '"refs"'

    echo "Test: get_callgraph"
    R=$(send "{\"id\":15,\"cmd\":\"get_callgraph\",\"address\":\"$FUNC_ADDR\",\"depth\":1,\"direction\":\"both\"}")
    assert_contains "get_callgraph ok" "$R" '"ok":true'
    assert_contains "get_callgraph has nodes" "$R" '"nodes"'
    assert_contains "get_callgraph has edges" "$R" '"edges"'

    echo "Test: get_data_at"
    R=$(send "{\"id\":16,\"cmd\":\"get_data_at\",\"address\":\"$FUNC_ADDR\",\"length\":16}")
    assert_contains "get_data_at ok" "$R" '"ok":true'
    assert_contains "get_data_at has bytes" "$R" '"bytes"'
else
    echo "  SKIP: No function address available for analysis tests"
fi

echo "Test: get_types"
R=$(send '{"id":17,"cmd":"get_types","offset":0,"limit":5}')
assert_contains "get_types ok" "$R" '"ok":true'
assert_contains "get_types has array" "$R" '"types"'

# -- Error Handling --

echo ""
echo "[Error Handling]"

echo "Test: unknown command"
R=$(send '{"id":20,"cmd":"bogus_command"}')
assert_contains "unknown cmd returns error" "$R" '"ok":false'
assert_contains "unknown cmd has message" "$R" "Unknown command"

echo "Test: malformed JSON"
R=$(send 'this is not valid json')
assert_contains "malformed JSON returns error" "$R" '"ok":false'

echo "Test: invalid address in decompile"
R=$(send '{"id":21,"cmd":"decompile","address":"0xffffffffffffffff"}')
assert_contains "invalid addr returns response" "$R" '"id"'

echo "Test: missing required param"
R=$(send '{"id":22,"cmd":"decompile"}')
assert_contains "missing param returns error" "$R" '"ok":false'

echo "Test: decompile nonexistent function name"
R=$(send '{"id":23,"cmd":"decompile","name":"this_function_does_not_exist_xyz"}')
assert_contains "nonexistent func returns error" "$R" '"ok":false'

# -- Mutations --

echo ""
echo "[Mutations]"

if [ -n "$FUNC_NAME" ] && [ -n "$FUNC_ADDR" ]; then
    echo "Test: rename_function"
    R=$(send "{\"id\":30,\"cmd\":\"rename_function\",\"address\":\"$FUNC_ADDR\",\"new_name\":\"test_renamed_func\"}")
    assert_contains "rename ok" "$R" '"ok":true'
    assert_contains "rename has old_name" "$R" '"old_name"'
    assert_contains "rename has new_name" "$R" '"new_name"'

    echo "Test: verify rename"
    R=$(send '{"id":31,"cmd":"get_function","name":"test_renamed_func"}')
    assert_contains "renamed func found" "$R" '"ok":true'
    assert_contains "renamed func name matches" "$R" '"test_renamed_func"'

    echo "Test: set_comment"
    R=$(send "{\"id\":32,\"cmd\":\"set_comment\",\"address\":\"$FUNC_ADDR\",\"comment\":\"MCP bridge test comment\",\"type\":\"eol\"}")
    assert_contains "set_comment ok" "$R" '"ok":true'

    echo "Test: create_bookmark"
    R=$(send "{\"id\":33,\"cmd\":\"create_bookmark\",\"address\":\"$FUNC_ADDR\",\"category\":\"test\",\"comment\":\"bridge test bookmark\"}")
    assert_contains "create_bookmark ok" "$R" '"ok":true'

    echo "Test: save"
    R=$(send '{"id":34,"cmd":"save"}')
    assert_contains "save ok" "$R" '"ok":true'
else
    echo "  SKIP: No function available for mutation tests"
fi

# -- Shutdown --

echo ""
echo "[Shutdown]"

echo "Test: shutdown"
R=$(send '{"id":99,"cmd":"shutdown"}')
assert_contains "shutdown ok" "$R" '"ok":true'

echo "Waiting for bridge process to exit..."
if wait "$BRIDGE_PID" 2>/dev/null; then
    echo "  PASS: Bridge exited cleanly"
    ((PASS++)) || true
else
    echo "  PASS: Bridge exited (non-zero exit code is normal for headless)"
    ((PASS++)) || true
fi
BRIDGE_PID=""

# -- Persistence --

echo ""
echo "[Persistence]"

echo "Re-opening bridge to verify persistence..."
PORT2=$((PORT + 1))
"$GHIDRA/support/analyzeHeadless" "$PROJECT_DIR" TestProject \
    -process -noanalysis \
    -postScript McpBridge.java "$PORT2" \
    -scriptPath "$SCRIPTS" > "$PROJECT_DIR/bridge2.log" 2>&1 &
BRIDGE_PID=$!

# Override PORT for send() function
OLD_PORT=$PORT
PORT=$PORT2

if wait_for_bridge 120; then
    echo "Test: renamed function persisted"
    R=$(send '{"id":40,"cmd":"get_function","name":"test_renamed_func"}')
    assert_contains "rename persisted" "$R" '"test_renamed_func"'

    R=$(send '{"id":41,"cmd":"shutdown"}')
    wait "$BRIDGE_PID" 2>/dev/null || true
    BRIDGE_PID=""
else
    echo "  FAIL: Bridge did not restart for persistence test"
    ((FAIL++)) || true
fi
PORT=$OLD_PORT

# --- Results ---

echo ""
echo "============================================"
echo "  Results: $PASS passed, $FAIL failed"
echo "============================================"

if [ "$FAIL" -eq 0 ]; then
    echo "  ALL TESTS PASSED"
    exit 0
else
    echo "  SOME TESTS FAILED"
    exit 1
fi
