/* @ts-self-types="./binb_web.d.ts" */

export class Emulator {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(Emulator.prototype);
        obj.__wbg_ptr = ptr;
        EmulatorFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        EmulatorFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_emulator_free(ptr, 0);
    }
    /**
     * Add a breakpoint at the given address.
     * @param {number} addr
     * @returns {boolean}
     */
    add_breakpoint(addr) {
        const ret = wasm.emulator_add_breakpoint(this.__wbg_ptr, addr);
        return ret !== 0;
    }
    /**
     * Add a library file to the VFS (for dynamic linking support).
     * @param {string} path
     * @param {Uint8Array} data
     */
    add_library(path, data) {
        const ptr0 = passStringToWasm0(path, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        wasm.emulator_add_library(this.__wbg_ptr, ptr0, len0, ptr1, len1);
    }
    /**
     * Add a breakpoint on syscall number (e.g. 0 = read, 1 = write).
     * JS numbers are f64; we round so i386 numbers (e.g. 4 for write) are not truncated to 3.
     * @param {number} nr
     * @returns {boolean}
     */
    add_syscall_breakpoint(nr) {
        const ret = wasm.emulator_add_syscall_breakpoint(this.__wbg_ptr, nr);
        return ret !== 0;
    }
    /**
     * Add a file to the VFS at the given guest path (e.g. /lib/x86_64-linux-gnu/libc.so.6).
     * Use for libraries or any file the emulated program may open. Overwrites if path exists.
     * @param {string} path
     * @param {Uint8Array} data
     */
    add_vfs_file(path, data) {
        const ptr0 = passStringToWasm0(path, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        wasm.emulator_add_library(this.__wbg_ptr, ptr0, len0, ptr1, len1);
    }
    /**
     * Clear all collected xrefs.
     */
    clear_xrefs() {
        wasm.emulator_clear_xrefs(this.__wbg_ptr);
    }
    /**
     * Continue execution until breakpoint, exit, halt, or instruction limit.
     * Like `run` but stops at breakpoints.
     * @returns {string}
     */
    continue_execution() {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.emulator_continue_execution(this.__wbg_ptr);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * Disassemble the current instruction.
     * @returns {string}
     */
    current_disasm() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.emulator_current_disasm(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Disassemble `count` instructions starting at `addr`.
     * Returns JSON array of { addr, len, text, is_current, has_bp, branch_target?, region? }.
     * @param {number} addr
     * @param {number} count
     * @returns {string}
     */
    disasm_range(addr, count) {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.emulator_disasm_range(this.__wbg_ptr, addr, count);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Get all xrefs as flat JSON array (for bulk processing).
     * Returns JSON: [{from, to, kind, count}]
     * @returns {string}
     */
    get_all_xrefs() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.emulator_get_all_xrefs(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * True if breaking on every syscall is enabled.
     * @returns {boolean}
     */
    get_break_on_any_syscall() {
        const ret = wasm.emulator_get_break_on_any_syscall(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
     * Get all breakpoint addresses as a JSON array of hex strings.
     * @returns {string}
     */
    get_breakpoints() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.emulator_get_breakpoints(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Get the current call stack as JSON.
     * Returns an array of frames: [{call_site, target, sp}, ...] (innermost last).
     * @returns {string}
     */
    get_call_stack() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.emulator_get_call_stack(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Get the exit code, or -1 if not exited.
     * @returns {number}
     */
    get_exit_code() {
        const ret = wasm.emulator_get_exit_code(this.__wbg_ptr);
        return ret;
    }
    /**
     * Get the current instruction count.
     * @returns {number}
     */
    get_instruction_count() {
        const ret = wasm.emulator_get_instruction_count(this.__wbg_ptr);
        return ret;
    }
    /**
     * Get memory map summary (for debugging).
     * @returns {string}
     */
    get_memory_map() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.emulator_get_memory_map(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Get all mapped memory regions as JSON: [{start, size, perms}].
     * @returns {string}
     */
    get_memory_regions() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.emulator_get_memory_regions(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Get the current register state as JSON.
     * @returns {string}
     */
    get_registers() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.emulator_get_registers(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Get current RIP as hex string.
     * @returns {string}
     */
    get_rip() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.emulator_get_rip(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Get RIP as a numeric value (for disasm_range).
     * @returns {number}
     */
    get_rip_num() {
        const ret = wasm.emulator_get_rip_num(this.__wbg_ptr);
        return ret;
    }
    /**
     * Get stderr output as a string.
     * @returns {string}
     */
    get_stderr() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.emulator_get_stderr(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Get stdout output as a string.
     * @returns {string}
     */
    get_stdout() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.emulator_get_stdout(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Get all syscall breakpoint numbers as a JSON array of numbers.
     * @returns {string}
     */
    get_syscall_breakpoints() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.emulator_get_syscall_breakpoints(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Get the syscall trace log as a newline-separated string.
     * @returns {string}
     */
    get_syscall_trace() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.emulator_get_syscall_trace(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Get the base (global) index of the first stored trace entry.
     * @returns {number}
     */
    get_trace_base_index() {
        const ret = wasm.emulator_get_trace_base_index(this.__wbg_ptr);
        return ret;
    }
    /**
     * Get a sampled daddr-access timeline for visualization.
     * Returns JSON array of [local_index, is_write] for entries touching [addr, addr+size).
     * @param {number} addr
     * @param {number} size
     * @param {number} max_points
     * @returns {string}
     */
    get_trace_daddr_timeline(addr, size, max_points) {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.emulator_get_trace_daddr_timeline(this.__wbg_ptr, addr, size, max_points);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Get sampled daddr-access timeline within a sub-range [start, end).
     * Returns JSON array of [local_index, is_write].
     * @param {number} addr
     * @param {number} size
     * @param {number} range_start
     * @param {number} range_end
     * @param {number} max_points
     * @returns {string}
     */
    get_trace_daddr_timeline_ranged(addr, size, range_start, range_end, max_points) {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.emulator_get_trace_daddr_timeline_ranged(this.__wbg_ptr, addr, size, range_start, range_end, max_points);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Get disassembly text for a trace entry's RIP.
     * @param {number} local_index
     * @returns {string}
     */
    get_trace_disasm(local_index) {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.emulator_get_trace_disasm(this.__wbg_ptr, local_index);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Get trace entries for a range (for list display).
     * Returns JSON array of {idx, rip, disasm}.
     * @param {number} start
     * @param {number} count
     * @returns {string}
     */
    get_trace_entries(start, count) {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.emulator_get_trace_entries(this.__wbg_ptr, start, count);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * True if the trace entry at the given local index is a syscall instruction.
     * @param {number} local_index
     * @returns {boolean}
     */
    get_trace_entry_is_syscall(local_index) {
        const ret = wasm.emulator_get_trace_entry_is_syscall(this.__wbg_ptr, local_index);
        return ret !== 0;
    }
    /**
     * Get the number of recorded trace entries.
     * @returns {number}
     */
    get_trace_length() {
        const ret = wasm.emulator_get_trace_length(this.__wbg_ptr);
        return ret;
    }
    /**
     * Get memory accesses for a given trace entry (local index).
     * Returns JSON array of {addr, size, is_write}.
     * @param {number} local_index
     * @returns {string}
     */
    get_trace_mem_accesses(local_index) {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.emulator_get_trace_mem_accesses(this.__wbg_ptr, local_index);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Get sampled memory activity timeline within a sub-range [start, end).
     * Returns JSON array of [local_index, activity] where activity is:
     *   0 = none, 1 = read only, 2 = write only, 3 = read + write.
     * @param {number} range_start
     * @param {number} range_end
     * @param {number} max_points
     * @returns {string}
     */
    get_trace_mem_activity_ranged(range_start, range_end, max_points) {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.emulator_get_trace_mem_activity_ranged(this.__wbg_ptr, range_start, range_end, max_points);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Get all accesses to [addr, addr+size) across the trace with instruction index, RIP, and value.
     * Returns JSON array of { local_index, rip, is_write, addr, size, data } (data hex or null).
     * Capped at max_entries for performance.
     * @param {number} addr
     * @param {number} size
     * @param {number} max_entries
     * @returns {string}
     */
    get_trace_region_history(addr, size, max_entries) {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.emulator_get_trace_region_history(this.__wbg_ptr, addr, size, max_entries);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Get register state at a given trace index (local index).
     * Returns JSON RegisterState or null if index is out of range.
     * @param {number} local_index
     * @returns {string}
     */
    get_trace_registers(local_index) {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.emulator_get_trace_registers(this.__wbg_ptr, local_index);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Get execution breakpoint hits: all indices where RIP==target within [start, end).
     * Returns JSON array of local indices.
     * @param {number} target_rip
     * @param {number} range_start
     * @param {number} range_end
     * @param {number} max_results
     * @returns {string}
     */
    get_trace_rip_hits(target_rip, range_start, range_end, max_results) {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.emulator_get_trace_rip_hits(this.__wbg_ptr, target_rip, range_start, range_end, max_results);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Get a sampled RIP timeline for the canvas visualization.
     * Returns JSON array of [global_index, rip] pairs (up to max_points).
     * @param {number} max_points
     * @returns {string}
     */
    get_trace_timeline(max_points) {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.emulator_get_trace_timeline(this.__wbg_ptr, max_points);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Get sampled RIP timeline over a sub-range [start, end) of local indices.
     * Returns JSON array of [local_index, rip] pairs.
     * @param {number} range_start
     * @param {number} range_end
     * @param {number} max_points
     * @returns {string}
     */
    get_trace_timeline_ranged(range_start, range_end, max_points) {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.emulator_get_trace_timeline_ranged(this.__wbg_ptr, range_start, range_end, max_points);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Get the content of a VFS file by path. Returns null if not found (or empty array in some bindings).
     * @param {string} path
     * @returns {Uint8Array | undefined}
     */
    get_vfs_file_content(path) {
        const ptr0 = passStringToWasm0(path, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.emulator_get_vfs_file_content(this.__wbg_ptr, ptr0, len0);
        let v2;
        if (ret[0] !== 0) {
            v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v2;
    }
    /**
     * List all files in the VFS (in-memory store). Returns JSON array of { path, size, modified }.
     * @returns {string}
     */
    get_vfs_files() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.emulator_get_vfs_files(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Get xref count.
     * @returns {number}
     */
    get_xref_count() {
        const ret = wasm.emulator_get_xref_count(this.__wbg_ptr);
        return ret;
    }
    /**
     * Get summary: total xref count and top-referenced addresses.
     * Returns JSON: {total, calls, jumps, data_refs, top_targets: [{addr, count, kinds}]}
     * @returns {string}
     */
    get_xref_summary() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.emulator_get_xref_summary(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Get all xrefs originating from the given address.
     * Returns JSON: [{from, to, kind, count}]
     * @param {number} addr
     * @returns {string}
     */
    get_xrefs_from(addr) {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.emulator_get_xrefs_from(this.__wbg_ptr, addr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Get all xrefs that target the given address.
     * Returns JSON: [{from, to, kind, count}]
     * @param {number} addr
     * @returns {string}
     */
    get_xrefs_to(addr) {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.emulator_get_xrefs_to(this.__wbg_ptr, addr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Check if an address has a breakpoint.
     * @param {number} addr
     * @returns {boolean}
     */
    has_breakpoint(addr) {
        const ret = wasm.emulator_has_breakpoint(this.__wbg_ptr, addr);
        return ret !== 0;
    }
    /**
     * Check if we break on syscall nr.
     * @param {number} nr
     * @returns {boolean}
     */
    has_syscall_breakpoint(nr) {
        const ret = wasm.emulator_has_syscall_breakpoint(this.__wbg_ptr, nr);
        return ret !== 0;
    }
    /**
     * Check whether the emulated process has exited.
     * @returns {boolean}
     */
    is_exited() {
        const ret = wasm.emulator_is_exited(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
     * Check if trace recording is active.
     * @returns {boolean}
     */
    is_trace_recording() {
        const ret = wasm.emulator_is_trace_recording(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
     * Restore VM state from a previously saved snapshot blob.
     * @param {Uint8Array} data
     */
    load_snapshot(data) {
        const ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.emulator_load_snapshot(this.__wbg_ptr, ptr0, len0);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Create a new emulator from raw ELF binary bytes.
     * @param {Uint8Array} elf_bytes
     */
    constructor(elf_bytes) {
        const ptr0 = passArray8ToWasm0(elf_bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.emulator_new(ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        this.__wbg_ptr = ret[0] >>> 0;
        EmulatorFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * Create a new emulator from a Windows PE binary (EXE). No DLLs; use new_from_pe_with_libs_and_args for VFS DLLs.
     * @param {Uint8Array} pe_bytes
     * @returns {Emulator}
     */
    static new_from_pe(pe_bytes) {
        const ptr0 = passArray8ToWasm0(pe_bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.emulator_new_from_pe(ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return Emulator.__wrap(ret[0]);
    }
    /**
     * Create a new emulator from a PE binary with program arguments. `args` is a JS array of strings (argv[0], argv[1], ...).
     * @param {Uint8Array} pe_bytes
     * @param {Array<any>} args
     * @returns {Emulator}
     */
    static new_from_pe_with_args(pe_bytes, args) {
        const ptr0 = passArray8ToWasm0(pe_bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.emulator_new_from_pe_with_args(ptr0, len0, args);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return Emulator.__wrap(ret[0]);
    }
    /**
     * Create a new emulator from a PE binary with DLLs (VFS) and arguments.
     * `lib_paths` is a JS array of guest paths (e.g. "/Windows/System32/ntdll.dll"), `lib_data` is a JS array of Uint8Arrays.
     * @param {Uint8Array} pe_bytes
     * @param {Array<any>} lib_paths
     * @param {Array<any>} lib_data
     * @param {Array<any>} args
     * @returns {Emulator}
     */
    static new_from_pe_with_libs_and_args(pe_bytes, lib_paths, lib_data, args) {
        const ptr0 = passArray8ToWasm0(pe_bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.emulator_new_from_pe_with_libs_and_args(ptr0, len0, lib_paths, lib_data, args);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return Emulator.__wrap(ret[0]);
    }
    /**
     * Create a new emulator from shellcode (raw bytes or hex-encoded).
     * `arch` must be "x86_64" (or "x64") or "arm64" (or "aarch64").
     * If `code` looks like hex (C-style `\xNN` or plain hex), it is decoded first.
     * @param {Uint8Array} code
     * @param {string} arch
     * @returns {Emulator}
     */
    static new_shellcode(code, arch) {
        const ptr0 = passArray8ToWasm0(code, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(arch, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.emulator_new_shellcode(ptr0, len0, ptr1, len1);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return Emulator.__wrap(ret[0]);
    }
    /**
     * Create a new emulator with program arguments (argv). `args` is a JS array of strings (argv[0], argv[1], ...).
     * If empty, argv[0] is "program".
     * @param {Uint8Array} elf_bytes
     * @param {Array<any>} args
     * @returns {Emulator}
     */
    static new_with_args(elf_bytes, args) {
        const ptr0 = passArray8ToWasm0(elf_bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.emulator_new_with_args(ptr0, len0, args);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return Emulator.__wrap(ret[0]);
    }
    /**
     * Create a new emulator with pre-loaded library files for dynamic linking.
     * `lib_paths` is a JS array of strings, `lib_data` is a JS array of Uint8Arrays.
     * @param {Uint8Array} elf_bytes
     * @param {Array<any>} lib_paths
     * @param {Array<any>} lib_data
     * @returns {Emulator}
     */
    static new_with_libs(elf_bytes, lib_paths, lib_data) {
        const ptr0 = passArray8ToWasm0(elf_bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.emulator_new_with_libs(ptr0, len0, lib_paths, lib_data);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return Emulator.__wrap(ret[0]);
    }
    /**
     * Create a new emulator with libraries and program arguments.
     * `lib_paths` / `lib_data` as in new_with_libs; `args` is a JS array of strings (argv[0], argv[1], ...).
     * @param {Uint8Array} elf_bytes
     * @param {Array<any>} lib_paths
     * @param {Array<any>} lib_data
     * @param {Array<any>} args
     * @returns {Emulator}
     */
    static new_with_libs_and_args(elf_bytes, lib_paths, lib_data, args) {
        const ptr0 = passArray8ToWasm0(elf_bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.emulator_new_with_libs_and_args(ptr0, len0, lib_paths, lib_data, args);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return Emulator.__wrap(ret[0]);
    }
    /**
     * Find next trace index (>= start) that accesses the given data address.
     * @param {number} addr
     * @param {number} size
     * @param {number} start
     * @returns {number}
     */
    next_trace_by_addr(addr, size, start) {
        const ret = wasm.emulator_next_trace_by_addr(this.__wbg_ptr, addr, size, start);
        return ret;
    }
    /**
     * Seek forwards: find next trace index (> start) where the instruction writes gpr[gpr_index].
     * Returns local index or -1 if not found.
     * @param {number} gpr_index
     * @param {number} start
     * @returns {number}
     */
    next_trace_by_register(gpr_index, start) {
        const ret = wasm.emulator_next_trace_by_register(this.__wbg_ptr, gpr_index, start);
        return ret;
    }
    /**
     * Find next trace index (>= start) where RIP matches.
     * Returns local index or -1 if not found.
     * @param {number} target_rip
     * @param {number} start
     * @returns {number}
     */
    next_trace_by_rip(target_rip, start) {
        const ret = wasm.emulator_next_trace_by_rip(this.__wbg_ptr, target_rip, start);
        return ret;
    }
    /**
     * Find previous trace index (<= start) that accesses the given data address.
     * @param {number} addr
     * @param {number} size
     * @param {number} start
     * @returns {number}
     */
    prev_trace_by_addr(addr, size, start) {
        const ret = wasm.emulator_prev_trace_by_addr(this.__wbg_ptr, addr, size, start);
        return ret;
    }
    /**
     * Seek backwards: find previous trace index (<= start) where the instruction wrote gpr[gpr_index]
     * and left it with the same value it has at start. "Which instruction set this register to its current value?"
     * Returns local index or -1 if not found.
     * @param {number} gpr_index
     * @param {number} start
     * @returns {number}
     */
    prev_trace_by_register(gpr_index, start) {
        const ret = wasm.emulator_prev_trace_by_register(this.__wbg_ptr, gpr_index, start);
        return ret;
    }
    /**
     * Find previous trace index (<= start) where RIP matches.
     * @param {number} target_rip
     * @param {number} start
     * @returns {number}
     */
    prev_trace_by_rip(target_rip, start) {
        const ret = wasm.emulator_prev_trace_by_rip(this.__wbg_ptr, target_rip, start);
        return ret;
    }
    /**
     * Read a range of memory as raw bytes (returns Uint8Array + a validity bitmask).
     * Returns a flat buffer: first `len` bytes are data, next `len` bytes are
     * validity flags (0x00=unmapped, 0xff=valid).
     * @param {number} addr
     * @param {number} len
     * @returns {Uint8Array}
     */
    read_memory_bytes(addr, len) {
        const ret = wasm.emulator_read_memory_bytes(this.__wbg_ptr, addr, len);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * Read a range of memory as hex string (for memory viewer).
     * @param {number} addr
     * @param {number} len
     * @returns {string}
     */
    read_memory_hex(addr, len) {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.emulator_read_memory_hex(this.__wbg_ptr, addr, len);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Remove a breakpoint at the given address.
     * @param {number} addr
     * @returns {boolean}
     */
    remove_breakpoint(addr) {
        const ret = wasm.emulator_remove_breakpoint(this.__wbg_ptr, addr);
        return ret !== 0;
    }
    /**
     * Remove a syscall breakpoint.
     * @param {number} nr
     * @returns {boolean}
     */
    remove_syscall_breakpoint(nr) {
        const ret = wasm.emulator_remove_syscall_breakpoint(this.__wbg_ptr, nr);
        return ret !== 0;
    }
    /**
     * Run until the process exits or hits the instruction limit.
     * @returns {string}
     */
    run() {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.emulator_run(this.__wbg_ptr);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * Run up to `n` instructions. Returns JSON with step info.
     * @param {number} n
     * @returns {string}
     */
    run_n(n) {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.emulator_run_n(this.__wbg_ptr, n);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * Save a snapshot of the VM state as a binary blob (Uint8Array).
     * Contains CPU registers, memory, breakpoints, syscall state, and regions.
     * @returns {Uint8Array}
     */
    save_snapshot() {
        const ret = wasm.emulator_save_snapshot(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * Search all readable memory for `needle` (byte pattern).
     * `query` is the search string, `mode` is "hex", "string", or "regex".
     * Returns JSON array: [[addr, length], ...].
     * Capped at 2000 matches.
     * @param {string} query
     * @param {string} mode
     * @returns {string}
     */
    search_memory(query, mode) {
        let deferred3_0;
        let deferred3_1;
        try {
            const ptr0 = passStringToWasm0(query, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(mode, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            const ret = wasm.emulator_search_memory(this.__wbg_ptr, ptr0, len0, ptr1, len1);
            deferred3_0 = ret[0];
            deferred3_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
        }
    }
    /**
     * Find all trace indices that access the given data address range.
     * Returns JSON array of local indices.
     * @param {number} addr
     * @param {number} size
     * @param {number} max_results
     * @returns {string}
     */
    search_trace_by_addr(addr, size, max_results) {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.emulator_search_trace_by_addr(this.__wbg_ptr, addr, size, max_results);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Find all trace indices where RIP == target_rip (up to max_results).
     * Returns JSON array of local indices.
     * @param {number} target_rip
     * @param {number} max_results
     * @returns {string}
     */
    search_trace_by_rip(target_rip, max_results) {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.emulator_search_trace_by_rip(this.__wbg_ptr, target_rip, max_results);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Restore VM state (CPU + memory) to the point after trace entry `local_index`,
     * so the memory view shows values at that instruction. No-op if no snapshot.
     * @param {number} local_index
     */
    seek_trace_index(local_index) {
        wasm.emulator_seek_trace_index(this.__wbg_ptr, local_index);
    }
    /**
     * Enable or disable real network I/O. Must be explicitly authorized by the user.
     * @param {boolean} enabled
     */
    set_allow_network(enabled) {
        wasm.emulator_set_allow_network(this.__wbg_ptr, enabled);
    }
    /**
     * Enable or disable breaking on every syscall (any syscall number).
     * @param {boolean} enabled
     */
    set_break_on_any_syscall(enabled) {
        wasm.emulator_set_break_on_any_syscall(this.__wbg_ptr, enabled);
    }
    /**
     * Set the maximum number of instructions before stopping.
     * @param {number} max
     */
    set_max_instructions(max) {
        wasm.emulator_set_max_instructions(this.__wbg_ptr, max);
    }
    /**
     * Set a GPR by index (0–31). Value is hex string (e.g. "0x401000" or "401000").
     * @param {number} gpr_index
     * @param {string} value_hex
     */
    set_register(gpr_index, value_hex) {
        const ptr0 = passStringToWasm0(value_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.emulator_set_register(this.__wbg_ptr, gpr_index, ptr0, len0);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Set RFLAGS/PSTATE. Value is hex string (e.g. "0x246" or "246").
     * @param {string} value_hex
     */
    set_rflags(value_hex) {
        const ptr0 = passStringToWasm0(value_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.emulator_set_rflags(this.__wbg_ptr, ptr0, len0);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Set stdin data for the emulated process.
     * @param {Uint8Array} data
     */
    set_stdin(data) {
        const ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.emulator_set_stdin(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Enable or disable syscall tracing.
     * @param {boolean} enabled
     */
    set_syscall_trace(enabled) {
        wasm.emulator_set_syscall_trace(this.__wbg_ptr, enabled);
    }
    /**
     * Enable or disable trace recording.
     * @param {boolean} enabled
     */
    set_trace_recording(enabled) {
        wasm.emulator_set_trace_recording(this.__wbg_ptr, enabled);
    }
    /**
     * Enable/disable xref collection.
     * @param {boolean} enabled
     */
    set_xref_collection(enabled) {
        wasm.emulator_set_xref_collection(this.__wbg_ptr, enabled);
    }
    /**
     * Execute a single instruction. Returns JSON with step info.
     * @returns {string}
     */
    step() {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.emulator_step(this.__wbg_ptr);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * Execute one instruction without checking syscall breakpoints (e.g. "step over" when stopped at a syscall breakpoint).
     * Use this to run the current syscall and stop at the next instruction.
     * @returns {string}
     */
    step_over() {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.emulator_step_over(this.__wbg_ptr);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * Write a single byte to memory at the given address.
     * @param {number} addr
     * @param {number} value
     */
    write_memory_byte(addr, value) {
        const ret = wasm.emulator_write_memory_byte(this.__wbg_ptr, addr, value);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Write multiple bytes to memory starting at addr.
     * `data` is a Uint8Array of bytes to write.
     * @param {number} addr
     * @param {Uint8Array} data
     */
    write_memory_bytes(addr, data) {
        const ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.emulator_write_memory_bytes(this.__wbg_ptr, addr, ptr0, len0);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Scan emulator memory with YARA-style rules.
     * Supports: text strings (plain and case-insensitive), hex byte patterns
     * (with ?? wildcards), and conditions (any of them, all of them, N of them, $name).
     * Returns JSON array of matches: [{rule, pattern, addr, len, preview}].
     * @param {string} rules_source
     * @returns {string}
     */
    yara_scan(rules_source) {
        let deferred3_0;
        let deferred3_1;
        try {
            const ptr0 = passStringToWasm0(rules_source, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ret = wasm.emulator_yara_scan(this.__wbg_ptr, ptr0, len0);
            var ptr2 = ret[0];
            var len2 = ret[1];
            if (ret[3]) {
                ptr2 = 0; len2 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred3_0 = ptr2;
            deferred3_1 = len2;
            return getStringFromWasm0(ptr2, len2);
        } finally {
            wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
        }
    }
}
if (Symbol.dispose) Emulator.prototype[Symbol.dispose] = Emulator.prototype.free;

export function init() {
    wasm.init();
}

/**
 * Parse ELF bytes and return structure (header, program headers, section headers) as JSON.
 * @param {Uint8Array} elf_bytes
 * @returns {string}
 */
export function parse_elf_structure(elf_bytes) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passArray8ToWasm0(elf_bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.parse_elf_structure(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Parse PE bytes (EXE or DLL) and return structure (header, sections, exports, imports) as JSON.
 * @param {Uint8Array} pe_bytes
 * @returns {string}
 */
export function parse_pe_structure(pe_bytes) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passArray8ToWasm0(pe_bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.parse_pe_structure(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Set the log level from JavaScript.
 * Levels: "off", "error", "warn", "info", "debug", "trace"
 * @param {string} level
 */
export function set_log_level(level) {
    const ptr0 = passStringToWasm0(level, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    wasm.set_log_level(ptr0, len0);
}

function __wbg_get_imports() {
    const import0 = {
        __proto__: null,
        __wbg_Error_8c4e43fe74559d73: function(arg0, arg1) {
            const ret = Error(getStringFromWasm0(arg0, arg1));
            return ret;
        },
        __wbg___wbindgen_string_get_72fb696202c56729: function(arg0, arg1) {
            const obj = arg1;
            const ret = typeof(obj) === 'string' ? obj : undefined;
            var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_throw_be289d5034ed271b: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbg_error_7534b8e9a36f1ab4: function(arg0, arg1) {
            let deferred0_0;
            let deferred0_1;
            try {
                deferred0_0 = arg0;
                deferred0_1 = arg1;
                console.error(getStringFromWasm0(arg0, arg1));
            } finally {
                wasm.__wbindgen_free(deferred0_0, deferred0_1, 1);
            }
        },
        __wbg_error_9a7fe3f932034cde: function(arg0) {
            console.error(arg0);
        },
        __wbg_get_9b94d73e6221f75c: function(arg0, arg1) {
            const ret = arg0[arg1 >>> 0];
            return ret;
        },
        __wbg_info_148d043840582012: function(arg0) {
            console.info(arg0);
        },
        __wbg_length_32ed9a279acd054c: function(arg0) {
            const ret = arg0.length;
            return ret;
        },
        __wbg_length_35a7bace40f36eac: function(arg0) {
            const ret = arg0.length;
            return ret;
        },
        __wbg_log_6b5ca2e6124b2808: function(arg0) {
            console.log(arg0);
        },
        __wbg_new_8a6f238a6ece86ea: function() {
            const ret = new Error();
            return ret;
        },
        __wbg_new_dd2b680c8bf6ae29: function(arg0) {
            const ret = new Uint8Array(arg0);
            return ret;
        },
        __wbg_prototypesetcall_bdcdcc5842e4d77d: function(arg0, arg1, arg2) {
            Uint8Array.prototype.set.call(getArrayU8FromWasm0(arg0, arg1), arg2);
        },
        __wbg_stack_0ed75d68575b0f3c: function(arg0, arg1) {
            const ret = arg1.stack;
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg_warn_f7ae1b2e66ccb930: function(arg0) {
            console.warn(arg0);
        },
        __wbindgen_cast_0000000000000001: function(arg0, arg1) {
            // Cast intrinsic for `Ref(String) -> Externref`.
            const ret = getStringFromWasm0(arg0, arg1);
            return ret;
        },
        __wbindgen_init_externref_table: function() {
            const table = wasm.__wbindgen_externrefs;
            const offset = table.grow(4);
            table.set(0, undefined);
            table.set(offset + 0, undefined);
            table.set(offset + 1, null);
            table.set(offset + 2, true);
            table.set(offset + 3, false);
        },
    };
    return {
        __proto__: null,
        "./binb_web_bg.js": import0,
    };
}

const EmulatorFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_emulator_free(ptr >>> 0, 1));

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}

let cachedDataViewMemory0 = null;
function getDataViewMemory0() {
    if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || (cachedDataViewMemory0.buffer.detached === undefined && cachedDataViewMemory0.buffer !== wasm.memory.buffer)) {
        cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
    }
    return cachedDataViewMemory0;
}

function getStringFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return decodeText(ptr, len);
}

let cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function isLikeNone(x) {
    return x === undefined || x === null;
}

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1, 1) >>> 0;
    getUint8ArrayMemory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}

function passStringToWasm0(arg, malloc, realloc) {
    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }
    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = cachedTextEncoder.encodeInto(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

function takeFromExternrefTable0(idx) {
    const value = wasm.__wbindgen_externrefs.get(idx);
    wasm.__externref_table_dealloc(idx);
    return value;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
cachedTextDecoder.decode();
const MAX_SAFARI_DECODE_BYTES = 2146435072;
let numBytesDecoded = 0;
function decodeText(ptr, len) {
    numBytesDecoded += len;
    if (numBytesDecoded >= MAX_SAFARI_DECODE_BYTES) {
        cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
        cachedTextDecoder.decode();
        numBytesDecoded = len;
    }
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

const cachedTextEncoder = new TextEncoder();

if (!('encodeInto' in cachedTextEncoder)) {
    cachedTextEncoder.encodeInto = function (arg, view) {
        const buf = cachedTextEncoder.encode(arg);
        view.set(buf);
        return {
            read: arg.length,
            written: buf.length
        };
    };
}

let WASM_VECTOR_LEN = 0;

let wasmModule, wasm;
function __wbg_finalize_init(instance, module) {
    wasm = instance.exports;
    wasmModule = module;
    cachedDataViewMemory0 = null;
    cachedUint8ArrayMemory0 = null;
    wasm.__wbindgen_start();
    return wasm;
}

async function __wbg_load(module, imports) {
    if (typeof Response === 'function' && module instanceof Response) {
        if (typeof WebAssembly.instantiateStreaming === 'function') {
            try {
                return await WebAssembly.instantiateStreaming(module, imports);
            } catch (e) {
                const validResponse = module.ok && expectedResponseType(module.type);

                if (validResponse && module.headers.get('Content-Type') !== 'application/wasm') {
                    console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve Wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                } else { throw e; }
            }
        }

        const bytes = await module.arrayBuffer();
        return await WebAssembly.instantiate(bytes, imports);
    } else {
        const instance = await WebAssembly.instantiate(module, imports);

        if (instance instanceof WebAssembly.Instance) {
            return { instance, module };
        } else {
            return instance;
        }
    }

    function expectedResponseType(type) {
        switch (type) {
            case 'basic': case 'cors': case 'default': return true;
        }
        return false;
    }
}

function initSync(module) {
    if (wasm !== undefined) return wasm;


    if (module !== undefined) {
        if (Object.getPrototypeOf(module) === Object.prototype) {
            ({module} = module)
        } else {
            console.warn('using deprecated parameters for `initSync()`; pass a single object instead')
        }
    }

    const imports = __wbg_get_imports();
    if (!(module instanceof WebAssembly.Module)) {
        module = new WebAssembly.Module(module);
    }
    const instance = new WebAssembly.Instance(module, imports);
    return __wbg_finalize_init(instance, module);
}

async function __wbg_init(module_or_path) {
    if (wasm !== undefined) return wasm;


    if (module_or_path !== undefined) {
        if (Object.getPrototypeOf(module_or_path) === Object.prototype) {
            ({module_or_path} = module_or_path)
        } else {
            console.warn('using deprecated parameters for the initialization function; pass a single object instead')
        }
    }

    if (module_or_path === undefined) {
        module_or_path = new URL('binb_web_bg.wasm', import.meta.url);
    }
    const imports = __wbg_get_imports();

    if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
        module_or_path = fetch(module_or_path);
    }

    const { instance, module } = await __wbg_load(await module_or_path, imports);

    return __wbg_finalize_init(instance, module);
}

export { initSync, __wbg_init as default };
