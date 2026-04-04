// McpBridge.java — Persistent GhidraScript bridge for ghidra-mcp
// Runs inside analyzeHeadless, opens a TCP socket, serves JSON commands.
//
// Usage: analyzeHeadless <project> <name> -process -noanalysis -postScript McpBridge.java <port>
//
// @category MCP

import java.io.*;
import java.net.*;
import java.util.*;

import com.google.gson.*;

import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;

public class McpBridge extends GhidraScript {

    private DecompInterface decompiler;
    private Gson gson;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("Usage: McpBridge.java <port>");
            return;
        }

        int port = Integer.parseInt(args[0]);
        gson = new GsonBuilder().serializeNulls().create();

        // Initialize decompiler
        decompiler = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        decompiler.setOptions(options);
        decompiler.openProgram(currentProgram);

        println("McpBridge: Starting on port " + port);

        try (ServerSocket serverSocket = new ServerSocket(port, 1, InetAddress.getByName("127.0.0.1"))) {
            serverSocket.setSoTimeout(0); // Wait indefinitely for connection

            boolean shutdown = false;
            while (!shutdown && !monitor.isCancelled()) {
                println("McpBridge: Waiting for connection...");

                try (Socket client = serverSocket.accept()) {
                    println("McpBridge: Client connected");
                    BufferedReader reader = new BufferedReader(new InputStreamReader(client.getInputStream(), "UTF-8"));
                    BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(client.getOutputStream(), "UTF-8"));

                    String line;
                    while ((line = reader.readLine()) != null) {
                        if (monitor.isCancelled()) { shutdown = true; break; }

                        JsonObject response;
                        String cmd = "";
                        try {
                            JsonObject request = gson.fromJson(line, JsonObject.class);
                            cmd = request.has("cmd") ? request.get("cmd").getAsString() : "";
                            response = handleCommand(request);
                        } catch (Exception e) {
                            response = new JsonObject();
                            response.addProperty("id", 0);
                            response.addProperty("ok", false);
                            response.addProperty("error", "Parse error: " + e.getMessage());
                        }

                        writer.write(gson.toJson(response));
                        writer.newLine();
                        writer.flush();

                        if ("shutdown".equals(cmd)) {
                            shutdown = true;
                            break;
                        }
                    }
                } catch (Exception e) {
                    println("McpBridge: Connection error: " + e.getMessage());
                }
            }
        } finally {
            if (decompiler != null) {
                decompiler.dispose();
            }
        }

        println("McpBridge: Shutting down");
    }

    private static final Set<String> MUTATION_COMMANDS = new HashSet<>(Arrays.asList(
        "rename_function", "rename_symbol", "set_comment",
        "set_function_prototype", "set_data_type", "create_function", "create_bookmark"
    ));

    private JsonObject handleCommand(JsonObject request) {
        int id = request.has("id") ? request.get("id").getAsInt() : 0;
        String cmd = request.has("cmd") ? request.get("cmd").getAsString() : "";

        try {
            // Wrap mutation commands in an explicit transaction
            if (MUTATION_COMMANDS.contains(cmd)) {
                return runInTransaction(cmd, id, request);
            }

            switch (cmd) {
                case "ping": return ok(id);
                case "shutdown": return ok(id);
                case "save": return cmdSave(id);
                case "info": return cmdInfo(id);
                case "list_functions": return cmdListFunctions(id, request);
                case "get_function": return cmdGetFunction(id, request);
                case "decompile": return cmdDecompile(id, request);
                case "disassemble": return cmdDisassemble(id, request);
                case "get_xrefs_to": return cmdGetXrefs(id, request, true);
                case "get_xrefs_from": return cmdGetXrefs(id, request, false);
                case "get_xrefs_both": return cmdGetXrefsBoth(id, request);
                case "get_callgraph": return cmdGetCallgraph(id, request);
                case "list_strings": return cmdListStrings(id, request);
                case "list_symbols": return cmdListSymbols(id, request);
                case "list_segments": return cmdListSegments(id);
                case "list_imports": return cmdListImports(id, request);
                case "list_exports": return cmdListExports(id, request);
                case "list_namespaces": return cmdListNamespaces(id, request);
                case "search_memory": return cmdSearchMemory(id, request);
                case "get_data_at": return cmdGetDataAt(id, request);
                case "get_types": return cmdGetTypes(id, request);
                case "get_type_detail": return cmdGetTypeDetail(id, request);
                default: return error(id, "Unknown command: " + cmd);
            }
        } catch (Exception e) {
            return error(id, e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private JsonObject runInTransaction(String cmd, int id, JsonObject request) {
        int txId = currentProgram.startTransaction("McpBridge: " + cmd);
        boolean success = false;
        try {
            JsonObject result;
            switch (cmd) {
                case "rename_function": result = cmdRenameFunction(id, request); break;
                case "rename_symbol": result = cmdRenameSymbol(id, request); break;
                case "set_comment": result = cmdSetComment(id, request); break;
                case "set_function_prototype": result = cmdSetFunctionPrototype(id, request); break;
                case "set_data_type": result = cmdSetDataType(id, request); break;
                case "create_function": result = cmdCreateFunction(id, request); break;
                case "create_bookmark": result = cmdCreateBookmark(id, request); break;
                default: result = error(id, "Unknown mutation: " + cmd); break;
            }
            // Check if the command succeeded
            if (result.has("ok") && result.get("ok").getAsBoolean()) {
                success = true;
            }
            return result;
        } catch (Exception e) {
            return error(id, e.getClass().getSimpleName() + ": " + e.getMessage());
        } finally {
            currentProgram.endTransaction(txId, success);
        }
    }

    // -- Helpers --

    private JsonObject ok(int id) {
        JsonObject r = new JsonObject();
        r.addProperty("id", id);
        r.addProperty("ok", true);
        return r;
    }

    private JsonObject error(int id, String msg) {
        JsonObject r = new JsonObject();
        r.addProperty("id", id);
        r.addProperty("ok", false);
        r.addProperty("error", msg);
        return r;
    }

    private Address resolveAddress(String addr) throws Exception {
        if (addr == null || addr.isEmpty()) return null;
        // Strip "0x" prefix if present
        String clean = addr.startsWith("0x") ? addr.substring(2) : addr;
        Address a = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(clean);
        if (a == null) throw new Exception("Invalid address: " + addr);
        return a;
    }

    private String getString(JsonObject obj, String key) {
        return obj.has(key) && !obj.get(key).isJsonNull() ? obj.get(key).getAsString() : null;
    }

    private int getInt(JsonObject obj, String key, int def) {
        return obj.has(key) && !obj.get(key).isJsonNull() ? obj.get(key).getAsInt() : def;
    }

    private long getLong(JsonObject obj, String key, long def) {
        return obj.has(key) && !obj.get(key).isJsonNull() ? obj.get(key).getAsLong() : def;
    }

    private Function findFunction(JsonObject request) throws Exception {
        String address = getString(request, "address");
        String name = getString(request, "name");

        if (address != null) {
            Address addr = resolveAddress(address);
            Function func = getFunctionAt(addr);
            if (func == null) func = getFunctionContaining(addr);
            if (func == null) throw new Exception("No function at address " + address);
            return func;
        }

        if (name != null) {
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                if (f.getName().equals(name)) return f;
            }
            throw new Exception("No function named '" + name + "'");
        }

        throw new Exception("Must specify 'address' or 'name'");
    }

    // -- Command Implementations --

    private JsonObject cmdSave(int id) throws Exception {
        // In headless mode, the analyzeHeadless framework wraps script execution
        // in a transaction and auto-saves when the script exits. Explicit save
        // within the transaction is not possible. Changes are persisted when the
        // bridge shuts down (via the "shutdown" command) and analyzeHeadless
        // completes its normal save cycle.
        //
        // We acknowledge the save request and note that changes will be persisted
        // on session close.
        JsonObject r = ok(id);
        r.addProperty("message", "Changes will be saved when the session closes. Use ghidra_close to save and close.");
        return r;
    }

    private JsonObject cmdInfo(int id) {
        JsonObject r = ok(id);
        r.addProperty("name", currentProgram.getName());
        r.addProperty("language", currentProgram.getLanguageID().toString());
        r.addProperty("compiler", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        r.addProperty("base_address", currentProgram.getImageBase().toString());
        r.addProperty("min_address", currentProgram.getMinAddress().toString());
        r.addProperty("max_address", currentProgram.getMaxAddress().toString());
        r.addProperty("num_functions", currentProgram.getFunctionManager().getFunctionCount());
        r.addProperty("num_symbols", currentProgram.getSymbolTable().getNumSymbols());
        r.addProperty("executable_path", currentProgram.getExecutablePath());
        r.addProperty("executable_format", currentProgram.getExecutableFormat());
        return r;
    }

    private JsonObject cmdListFunctions(int id, JsonObject request) {
        String filter = getString(request, "filter");
        long offset = getLong(request, "offset", 0);
        long limit = getLong(request, "limit", 100);

        JsonArray functions = new JsonArray();
        FunctionManager fm = currentProgram.getFunctionManager();
        long total = 0;
        long skipped = 0;

        for (Function f : fm.getFunctions(true)) {
            if (filter != null && !f.getName().toLowerCase().contains(filter.toLowerCase())) {
                continue;
            }
            total++;
            if (skipped < offset) {
                skipped++;
                continue;
            }
            if (functions.size() >= limit) continue; // Keep counting total

            JsonObject func = new JsonObject();
            func.addProperty("address", f.getEntryPoint().toString());
            func.addProperty("name", f.getName());
            func.addProperty("size", f.getBody().getNumAddresses());
            func.addProperty("param_count", f.getParameterCount());
            func.addProperty("return_type", f.getReturnType().getDisplayName());
            functions.add(func);
        }

        JsonObject r = ok(id);
        r.add("functions", functions);
        r.addProperty("total", total);
        r.addProperty("has_more", total > offset + limit);
        return r;
    }

    private JsonObject cmdGetFunction(int id, JsonObject request) throws Exception {
        Function f = findFunction(request);

        JsonObject r = ok(id);
        r.addProperty("address", f.getEntryPoint().toString());
        r.addProperty("name", f.getName());
        r.addProperty("signature", f.getPrototypeString(true, false));
        r.addProperty("calling_convention", f.getCallingConventionName());
        r.addProperty("return_type", f.getReturnType().getDisplayName());
        r.addProperty("size", f.getBody().getNumAddresses());
        r.addProperty("is_thunk", f.isThunk());
        r.addProperty("is_external", f.isExternal());

        // Parameters
        JsonArray params = new JsonArray();
        for (Parameter p : f.getParameters()) {
            JsonObject param = new JsonObject();
            param.addProperty("name", p.getName());
            param.addProperty("type", p.getDataType().getDisplayName());
            param.addProperty("storage", p.getVariableStorage().toString());
            param.addProperty("ordinal", p.getOrdinal());
            params.add(param);
        }
        r.add("parameters", params);

        // Local variables
        JsonArray locals = new JsonArray();
        for (Variable v : f.getLocalVariables()) {
            JsonObject local = new JsonObject();
            local.addProperty("name", v.getName());
            local.addProperty("type", v.getDataType().getDisplayName());
            local.addProperty("storage", v.getVariableStorage().toString());
            locals.add(local);
        }
        r.add("local_variables", locals);

        // Address ranges (body)
        JsonArray ranges = new JsonArray();
        for (AddressRange range : f.getBody()) {
            JsonObject rng = new JsonObject();
            rng.addProperty("start", range.getMinAddress().toString());
            rng.addProperty("end", range.getMaxAddress().toString());
            ranges.add(rng);
        }
        r.add("body_ranges", ranges);

        return r;
    }

    private JsonObject cmdDecompile(int id, JsonObject request) throws Exception {
        Function func = findFunction(request);
        int timeout = getInt(request, "timeout", 60);

        DecompileResults results = decompiler.decompileFunction(func, timeout, monitor);

        JsonObject r = ok(id);
        r.addProperty("address", func.getEntryPoint().toString());
        r.addProperty("name", func.getName());

        if (results.decompileCompleted()) {
            ClangTokenGroup markup = results.getCCodeMarkup();
            if (markup != null) {
                r.addProperty("c_code", markup.toString());
            } else {
                r.addProperty("c_code", "// Decompilation produced no output");
            }
            r.addProperty("signature", func.getPrototypeString(true, false));
        } else {
            r.addProperty("ok", false);
            r.addProperty("error", "Decompilation failed: " + results.getErrorMessage());
        }

        return r;
    }

    private JsonObject cmdDisassemble(int id, JsonObject request) throws Exception {
        Address addr = resolveAddress(getString(request, "address"));
        int count = getInt(request, "count", 50);

        JsonArray instructions = new JsonArray();
        Listing listing = currentProgram.getListing();
        Instruction inst = listing.getInstructionAt(addr);
        if (inst == null) {
            inst = listing.getInstructionAfter(addr);
        }

        for (int i = 0; i < count && inst != null; i++) {
            JsonObject item = new JsonObject();
            item.addProperty("address", inst.getAddress().toString());
            item.addProperty("mnemonic", inst.getMnemonicString());

            StringBuilder operands = new StringBuilder();
            for (int j = 0; j < inst.getNumOperands(); j++) {
                if (j > 0) operands.append(", ");
                operands.append(inst.getDefaultOperandRepresentation(j));
            }
            item.addProperty("operands", operands.toString());

            // Bytes as hex
            byte[] bytes = inst.getBytes();
            StringBuilder hex = new StringBuilder();
            for (byte b : bytes) {
                hex.append(String.format("%02x ", b));
            }
            item.addProperty("bytes", hex.toString().trim());
            item.addProperty("length", inst.getLength());

            instructions.add(item);
            inst = inst.getNext();
        }

        JsonObject r = ok(id);
        r.add("instructions", instructions);
        return r;
    }

    private JsonObject cmdGetXrefs(int id, JsonObject request, boolean isTo) throws Exception {
        Address addr = resolveAddress(getString(request, "address"));

        Reference[] refs = isTo ? getReferencesTo(addr) : getReferencesFrom(addr);

        JsonArray xrefs = new JsonArray();
        for (Reference ref : refs) {
            JsonObject xref = new JsonObject();
            xref.addProperty("from_address", ref.getFromAddress().toString());
            xref.addProperty("to_address", ref.getToAddress().toString());
            xref.addProperty("ref_type", ref.getReferenceType().getName());
            xref.addProperty("is_call", ref.getReferenceType().isCall());
            xrefs.add(xref);
        }

        JsonObject r = ok(id);
        r.add("refs", xrefs);
        return r;
    }

    private JsonObject cmdGetXrefsBoth(int id, JsonObject request) throws Exception {
        Address addr = resolveAddress(getString(request, "address"));

        JsonArray xrefs = new JsonArray();

        for (Reference ref : getReferencesTo(addr)) {
            JsonObject xref = new JsonObject();
            xref.addProperty("direction", "to");
            xref.addProperty("from_address", ref.getFromAddress().toString());
            xref.addProperty("to_address", ref.getToAddress().toString());
            xref.addProperty("ref_type", ref.getReferenceType().getName());
            xref.addProperty("is_call", ref.getReferenceType().isCall());
            xrefs.add(xref);
        }

        for (Reference ref : getReferencesFrom(addr)) {
            JsonObject xref = new JsonObject();
            xref.addProperty("direction", "from");
            xref.addProperty("from_address", ref.getFromAddress().toString());
            xref.addProperty("to_address", ref.getToAddress().toString());
            xref.addProperty("ref_type", ref.getReferenceType().getName());
            xref.addProperty("is_call", ref.getReferenceType().isCall());
            xrefs.add(xref);
        }

        JsonObject r = ok(id);
        r.add("refs", xrefs);
        return r;
    }

    private JsonObject cmdGetCallgraph(int id, JsonObject request) throws Exception {
        Function root = findFunction(request);
        int depth = getInt(request, "depth", 1);
        String direction = getString(request, "direction");
        if (direction == null) direction = "both";

        JsonArray nodes = new JsonArray();
        JsonArray edges = new JsonArray();
        Set<String> visited = new HashSet<>();

        Queue<Function> queue = new LinkedList<>();
        Map<Function, Integer> depths = new HashMap<>();
        queue.add(root);
        depths.put(root, 0);

        while (!queue.isEmpty()) {
            Function func = queue.poll();
            String key = func.getEntryPoint().toString();
            if (visited.contains(key)) continue;
            visited.add(key);

            JsonObject node = new JsonObject();
            node.addProperty("address", key);
            node.addProperty("name", func.getName());
            nodes.add(node);

            int d = depths.get(func);
            if (d >= depth) continue;

            // Callees
            if (direction.equals("both") || direction.equals("callees")) {
                for (Function callee : func.getCalledFunctions(monitor)) {
                    JsonObject edge = new JsonObject();
                    edge.addProperty("from", key);
                    edge.addProperty("to", callee.getEntryPoint().toString());
                    edges.add(edge);

                    if (!visited.contains(callee.getEntryPoint().toString())) {
                        queue.add(callee);
                        depths.putIfAbsent(callee, d + 1);
                    }
                }
            }

            // Callers
            if (direction.equals("both") || direction.equals("callers")) {
                for (Function caller : func.getCallingFunctions(monitor)) {
                    JsonObject edge = new JsonObject();
                    edge.addProperty("from", caller.getEntryPoint().toString());
                    edge.addProperty("to", key);
                    edges.add(edge);

                    if (!visited.contains(caller.getEntryPoint().toString())) {
                        queue.add(caller);
                        depths.putIfAbsent(caller, d + 1);
                    }
                }
            }
        }

        JsonObject r = ok(id);
        r.add("nodes", nodes);
        r.add("edges", edges);
        return r;
    }

    private JsonObject cmdListStrings(int id, JsonObject request) {
        long offset = getLong(request, "offset", 0);
        long limit = getLong(request, "limit", 100);
        int minLength = getInt(request, "min_length", 4);

        JsonArray strings = new JsonArray();
        DataIterator dataIter = currentProgram.getListing().getDefinedData(true);
        long total = 0;
        long skipped = 0;

        while (dataIter.hasNext()) {
            Data data = dataIter.next();
            if (data.hasStringValue()) {
                String val = (String) data.getValue();
                if (val != null && val.length() >= minLength) {
                    total++;
                    if (skipped < offset) {
                        skipped++;
                        continue;
                    }
                    if (strings.size() >= limit) continue;

                    JsonObject s = new JsonObject();
                    s.addProperty("address", data.getAddress().toString());
                    s.addProperty("value", val);
                    s.addProperty("length", val.length());
                    s.addProperty("type", data.getDataType().getDisplayName());
                    strings.add(s);
                }
            }
        }

        JsonObject r = ok(id);
        r.add("strings", strings);
        r.addProperty("total", total);
        r.addProperty("has_more", total > offset + limit);
        return r;
    }

    private JsonObject cmdListSymbols(int id, JsonObject request) {
        String namespace = getString(request, "namespace");
        String filter = getString(request, "filter");
        long offset = getLong(request, "offset", 0);
        long limit = getLong(request, "limit", 100);

        JsonArray symbols = new JsonArray();
        SymbolTable st = currentProgram.getSymbolTable();
        SymbolIterator iter = st.getAllSymbols(true);
        long total = 0;
        long skipped = 0;

        while (iter.hasNext()) {
            Symbol sym = iter.next();

            if (namespace != null) {
                String ns = sym.getParentNamespace().getName(true);
                if (!ns.contains(namespace)) continue;
            }

            if (filter != null && !sym.getName().toLowerCase().contains(filter.toLowerCase())) {
                continue;
            }

            total++;
            if (skipped < offset) {
                skipped++;
                continue;
            }
            if (symbols.size() >= limit) continue;

            JsonObject s = new JsonObject();
            s.addProperty("address", sym.getAddress().toString());
            s.addProperty("name", sym.getName());
            s.addProperty("type", sym.getSymbolType().toString());
            s.addProperty("namespace", sym.getParentNamespace().getName(true));
            s.addProperty("is_primary", sym.isPrimary());
            symbols.add(s);
        }

        JsonObject r = ok(id);
        r.add("symbols", symbols);
        r.addProperty("total", total);
        r.addProperty("has_more", total > offset + limit);
        return r;
    }

    private JsonObject cmdListSegments(int id) {
        JsonArray segments = new JsonArray();
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            JsonObject seg = new JsonObject();
            seg.addProperty("name", block.getName());
            seg.addProperty("start", block.getStart().toString());
            seg.addProperty("end", block.getEnd().toString());
            seg.addProperty("size", block.getSize());
            seg.addProperty("permissions",
                (block.isRead() ? "r" : "-") +
                (block.isWrite() ? "w" : "-") +
                (block.isExecute() ? "x" : "-"));
            seg.addProperty("is_initialized", block.isInitialized());
            seg.addProperty("source", block.getSourceName());
            segments.add(seg);
        }

        JsonObject r = ok(id);
        r.add("segments", segments);
        return r;
    }

    private JsonObject cmdListImports(int id, JsonObject request) {
        long offset = getLong(request, "offset", 0);
        long limit = getLong(request, "limit", 100);

        JsonArray imports = new JsonArray();
        SymbolTable st = currentProgram.getSymbolTable();
        SymbolIterator iter = st.getExternalSymbols();
        long total = 0;
        long skipped = 0;

        while (iter.hasNext()) {
            Symbol sym = iter.next();
            total++;
            if (skipped < offset) {
                skipped++;
                continue;
            }
            if (imports.size() >= limit) continue;

            JsonObject imp = new JsonObject();
            imp.addProperty("address", sym.getAddress().toString());
            imp.addProperty("name", sym.getName());
            imp.addProperty("namespace", sym.getParentNamespace().getName(true));
            imports.add(imp);
        }

        JsonObject r = ok(id);
        r.add("imports", imports);
        r.addProperty("total", total);
        r.addProperty("has_more", total > offset + limit);
        return r;
    }

    private JsonObject cmdListExports(int id, JsonObject request) {
        long offset = getLong(request, "offset", 0);
        long limit = getLong(request, "limit", 100);

        JsonArray exports = new JsonArray();
        SymbolTable st = currentProgram.getSymbolTable();
        SymbolIterator iter = st.getAllSymbols(true);
        long total = 0;
        long skipped = 0;

        while (iter.hasNext()) {
            Symbol sym = iter.next();
            if (!sym.isExternalEntryPoint()) continue;

            total++;
            if (skipped < offset) {
                skipped++;
                continue;
            }
            if (exports.size() >= limit) continue;

            JsonObject exp = new JsonObject();
            exp.addProperty("address", sym.getAddress().toString());
            exp.addProperty("name", sym.getName());
            exports.add(exp);
        }

        JsonObject r = ok(id);
        r.add("exports", exports);
        r.addProperty("total", total);
        r.addProperty("has_more", total > offset + limit);
        return r;
    }

    private JsonObject cmdListNamespaces(int id, JsonObject request) {
        String filter = getString(request, "filter");

        JsonArray namespaces = new JsonArray();
        SymbolTable st = currentProgram.getSymbolTable();

        for (Symbol sym : st.getDefinedSymbols()) {
            // Only collect namespace symbols
            if (sym.getSymbolType() == SymbolType.NAMESPACE ||
                sym.getSymbolType() == SymbolType.CLASS) {
                String name = sym.getName(true);
                if (filter != null && !name.toLowerCase().contains(filter.toLowerCase())) continue;

                JsonObject ns = new JsonObject();
                ns.addProperty("name", sym.getName());
                ns.addProperty("path", name);
                ns.addProperty("type", sym.getSymbolType().toString());
                namespaces.add(ns);
            }
        }

        JsonObject r = ok(id);
        r.add("namespaces", namespaces);
        return r;
    }

    private JsonObject cmdSearchMemory(int id, JsonObject request) throws Exception {
        String bytesStr = getString(request, "bytes");
        long offset = getLong(request, "offset", 0);
        long limit = getLong(request, "limit", 100);

        if (bytesStr == null || bytesStr.isEmpty()) {
            return error(id, "Missing 'bytes' parameter");
        }

        // Parse hex string (e.g., "48 89 e5" or "4889e5")
        String cleaned = bytesStr.replaceAll("\\s+", "");
        if (cleaned.length() % 2 != 0) {
            return error(id, "Invalid hex string: odd number of characters");
        }

        byte[] pattern = new byte[cleaned.length() / 2];
        for (int i = 0; i < pattern.length; i++) {
            pattern[i] = (byte) Integer.parseInt(cleaned.substring(i * 2, i * 2 + 2), 16);
        }

        JsonArray matches = new JsonArray();
        Memory memory = currentProgram.getMemory();
        Address start = currentProgram.getMinAddress();
        long total = 0;
        long skipped = 0;

        while (start != null && total < offset + limit + 10000) { // Safety limit
            Address found = memory.findBytes(start, pattern, null, true, monitor);
            if (found == null) break;

            total++;
            if (skipped < offset) {
                skipped++;
            } else if (matches.size() < limit) {
                JsonObject m = new JsonObject();
                m.addProperty("address", found.toString());
                matches.add(m);
            }

            start = found.add(1);
        }

        JsonObject r = ok(id);
        r.add("matches", matches);
        r.addProperty("total", total);
        r.addProperty("has_more", total > offset + limit);
        return r;
    }

    private JsonObject cmdGetDataAt(int id, JsonObject request) throws Exception {
        Address addr = resolveAddress(getString(request, "address"));
        int length = getInt(request, "length", 256);

        JsonObject r = ok(id);
        r.addProperty("address", addr.toString());

        // Check for defined data
        Data data = getDataAt(addr);
        if (data != null) {
            r.addProperty("data_type", data.getDataType().getDisplayName());
            Object value = data.getValue();
            r.addProperty("value", value != null ? value.toString() : null);
            r.addProperty("defined_size", data.getLength());
        }

        // Raw bytes
        byte[] bytes = new byte[length];
        int bytesRead = currentProgram.getMemory().getBytes(addr, bytes, 0, length);
        StringBuilder hex = new StringBuilder();
        for (int i = 0; i < bytesRead; i++) {
            hex.append(String.format("%02x ", bytes[i]));
        }
        r.addProperty("bytes", hex.toString().trim());
        r.addProperty("bytes_read", bytesRead);

        return r;
    }

    private JsonObject cmdGetTypes(int id, JsonObject request) {
        String filter = getString(request, "filter");
        String category = getString(request, "category");
        long offset = getLong(request, "offset", 0);
        long limit = getLong(request, "limit", 100);

        JsonArray types = new JsonArray();
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        Iterator<DataType> iter = dtm.getAllDataTypes();
        long total = 0;
        long skipped = 0;

        while (iter.hasNext()) {
            DataType dt = iter.next();

            if (filter != null && !dt.getName().toLowerCase().contains(filter.toLowerCase())) {
                continue;
            }

            if (category != null) {
                CategoryPath cp = dt.getCategoryPath();
                if (!cp.getPath().contains(category)) continue;
            }

            total++;
            if (skipped < offset) {
                skipped++;
                continue;
            }
            if (types.size() >= limit) continue;

            JsonObject t = new JsonObject();
            t.addProperty("name", dt.getName());
            t.addProperty("category", dt.getCategoryPath().getPath());
            t.addProperty("size", dt.getLength());
            t.addProperty("kind", dt.getClass().getSimpleName());
            types.add(t);
        }

        JsonObject r = ok(id);
        r.add("types", types);
        r.addProperty("total", total);
        r.addProperty("has_more", total > offset + limit);
        return r;
    }

    private JsonObject cmdGetTypeDetail(int id, JsonObject request) throws Exception {
        String name = getString(request, "name");
        String category = getString(request, "category");

        if (name == null) return error(id, "Missing 'name' parameter");

        DataTypeManager dtm = currentProgram.getDataTypeManager();
        DataType found = null;

        Iterator<DataType> iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            DataType dt = iter.next();
            if (dt.getName().equals(name)) {
                if (category != null && !dt.getCategoryPath().getPath().contains(category)) {
                    continue;
                }
                found = dt;
                break;
            }
        }

        if (found == null) {
            return error(id, "Data type not found: " + name);
        }

        JsonObject r = ok(id);
        r.addProperty("name", found.getName());
        r.addProperty("category", found.getCategoryPath().getPath());
        r.addProperty("size", found.getLength());
        r.addProperty("kind", found.getClass().getSimpleName());
        r.addProperty("description", found.getDescription());

        if (found instanceof Structure) {
            Structure struct_ = (Structure) found;
            JsonArray fields = new JsonArray();
            for (DataTypeComponent comp : struct_.getComponents()) {
                JsonObject field = new JsonObject();
                field.addProperty("offset", comp.getOffset());
                field.addProperty("name", comp.getFieldName());
                field.addProperty("type", comp.getDataType().getDisplayName());
                field.addProperty("size", comp.getLength());
                field.addProperty("comment", comp.getComment());
                fields.add(field);
            }
            r.add("fields", fields);
        } else if (found instanceof ghidra.program.model.data.Enum) {
            ghidra.program.model.data.Enum enum_ = (ghidra.program.model.data.Enum) found;
            JsonArray values = new JsonArray();
            for (String valueName : enum_.getNames()) {
                JsonObject v = new JsonObject();
                v.addProperty("name", valueName);
                v.addProperty("value", enum_.getValue(valueName));
                values.add(v);
            }
            r.add("values", values);
        }

        return r;
    }

    // -- Mutation Commands --

    private JsonObject cmdRenameFunction(int id, JsonObject request) throws Exception {
        String newName = getString(request, "new_name");
        if (newName == null) return error(id, "Missing 'new_name' parameter");

        Function func;
        String oldName = getString(request, "old_name");
        String address = getString(request, "address");

        if (address != null) {
            Address addr = resolveAddress(address);
            func = getFunctionAt(addr);
            if (func == null) func = getFunctionContaining(addr);
        } else if (oldName != null) {
            func = null;
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                if (f.getName().equals(oldName)) {
                    func = f;
                    break;
                }
            }
        } else {
            return error(id, "Must specify 'address' or 'old_name'");
        }

        if (func == null) return error(id, "Function not found");

        String previousName = func.getName();
        func.setName(newName, SourceType.USER_DEFINED);

        JsonObject r = ok(id);
        r.addProperty("address", func.getEntryPoint().toString());
        r.addProperty("old_name", previousName);
        r.addProperty("new_name", newName);
        return r;
    }

    private JsonObject cmdRenameSymbol(int id, JsonObject request) throws Exception {
        String address = getString(request, "address");
        String newName = getString(request, "new_name");

        if (address == null) return error(id, "Missing 'address' parameter");
        if (newName == null) return error(id, "Missing 'new_name' parameter");

        Address addr = resolveAddress(address);
        Symbol sym = getSymbolAt(addr);
        if (sym == null) return error(id, "No symbol at address " + address);

        String previousName = sym.getName();
        sym.setName(newName, SourceType.USER_DEFINED);

        JsonObject r = ok(id);
        r.addProperty("address", addr.toString());
        r.addProperty("old_name", previousName);
        r.addProperty("new_name", newName);
        return r;
    }

    private JsonObject cmdSetComment(int id, JsonObject request) throws Exception {
        String address = getString(request, "address");
        String comment = getString(request, "comment");
        String type = getString(request, "type");
        if (type == null) type = "eol";

        if (address == null) return error(id, "Missing 'address' parameter");
        if (comment == null) return error(id, "Missing 'comment' parameter");

        Address addr = resolveAddress(address);

        // Use comment type constants directly to avoid deprecation
        // EOL=0, PRE=1, POST=2, PLATE=3, REPEATABLE=4
        switch (type) {
            case "pre": setPreComment(addr, comment); break;
            case "post": setPostComment(addr, comment); break;
            case "plate": setPlateComment(addr, comment); break;
            case "repeatable": setRepeatableComment(addr, comment); break;
            default: setEOLComment(addr, comment); break;
        }

        JsonObject r = ok(id);
        r.addProperty("address", addr.toString());
        r.addProperty("comment", comment);
        r.addProperty("type", type);
        return r;
    }

    private JsonObject cmdSetFunctionPrototype(int id, JsonObject request) throws Exception {
        Function func = findFunction(request);
        String prototype = getString(request, "prototype");

        if (prototype == null) return error(id, "Missing 'prototype' parameter");

        String oldSig = func.getPrototypeString(true, false);

        // Use CParserUtils to parse the C-style prototype
        // Cast null explicitly to resolve overload ambiguity
        FunctionDefinitionDataType sig = ghidra.app.util.cparser.C.CParserUtils.parseSignature(
            (ghidra.app.services.DataTypeManagerService) null, currentProgram, prototype);
        if (sig == null) {
            return error(id, "Failed to parse prototype: " + prototype);
        }

        ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd =
            new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
                func.getEntryPoint(), sig, SourceType.USER_DEFINED);
        cmd.applyTo(currentProgram);

        JsonObject r = ok(id);
        r.addProperty("address", func.getEntryPoint().toString());
        r.addProperty("old_signature", oldSig);
        r.addProperty("new_signature", func.getPrototypeString(true, false));
        return r;
    }

    private JsonObject cmdSetDataType(int id, JsonObject request) throws Exception {
        String address = getString(request, "address");
        String typeName = getString(request, "data_type");

        if (address == null) return error(id, "Missing 'address' parameter");
        if (typeName == null) return error(id, "Missing 'data_type' parameter");

        Address addr = resolveAddress(address);

        // Find the data type
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        DataType dt = null;
        Iterator<DataType> iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            DataType candidate = iter.next();
            if (candidate.getName().equals(typeName)) {
                dt = candidate;
                break;
            }
        }

        // Try built-in types
        if (dt == null) {
            DataTypeManager builtIn = ghidra.program.model.data.BuiltInDataTypeManager.getDataTypeManager();
            Iterator<DataType> builtInIter = builtIn.getAllDataTypes();
            while (builtInIter.hasNext()) {
                DataType candidate = builtInIter.next();
                if (candidate.getName().equals(typeName)) {
                    dt = candidate;
                    break;
                }
            }
        }

        if (dt == null) return error(id, "Data type not found: " + typeName);

        Data oldData = getDataAt(addr);
        String oldType = oldData != null ? oldData.getDataType().getDisplayName() : "undefined";

        createData(addr, dt);

        JsonObject r = ok(id);
        r.addProperty("address", addr.toString());
        r.addProperty("old_type", oldType);
        r.addProperty("new_type", dt.getDisplayName());
        return r;
    }

    private JsonObject cmdCreateFunction(int id, JsonObject request) throws Exception {
        String address = getString(request, "address");
        if (address == null) return error(id, "Missing 'address' parameter");

        Address addr = resolveAddress(address);
        Function existing = getFunctionAt(addr);
        if (existing != null) {
            return error(id, "Function already exists at " + address + ": " + existing.getName());
        }

        createFunction(addr, null);
        Function func = getFunctionAt(addr);
        if (func == null) {
            return error(id, "Failed to create function at " + address);
        }

        JsonObject r = ok(id);
        r.addProperty("address", addr.toString());
        r.addProperty("name", func.getName());
        return r;
    }

    private JsonObject cmdCreateBookmark(int id, JsonObject request) throws Exception {
        String address = getString(request, "address");
        String category = getString(request, "category");
        String comment = getString(request, "comment");

        if (address == null) return error(id, "Missing 'address' parameter");
        if (category == null) return error(id, "Missing 'category' parameter");
        if (comment == null) return error(id, "Missing 'comment' parameter");

        Address addr = resolveAddress(address);
        createBookmark(addr, "Note", category + ": " + comment);

        JsonObject r = ok(id);
        r.addProperty("address", addr.toString());
        r.addProperty("category", category);
        r.addProperty("comment", comment);
        return r;
    }
}
