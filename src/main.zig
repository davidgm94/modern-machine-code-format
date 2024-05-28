const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

// Layout of the format:
// HEADER
// EXTERNAL SYMBOL TABLE
// library: u32
// symbol: u32

const Header = extern struct{
    magic: [3]u8 = "NAT".*,
    arch: Arch,
    os: Os,
    abi: Abi,
    description: packed struct (u16) {
        kind: Kind,
        relocations_resolved: bool,
        reserved: u14 = 0,
    },
    section_count: u16,
    unit_size: u32,
    entry_point: u32,

    const Arch = enum(u8) {
        x86_64 = 0,
    };

    const Os = enum(u8) {
        linux = 0,
    };

    const Abi = enum(u8) {
        system_v = 0,
    };

    const Kind = enum(u1) {
        executable = 0,
        library = 1,
    };

    const Linkage = enum(u1) {
        static = 0,
        dynamic = 1,
    };
};


const SectionSymbolOffsetHeader = extern struct{
    // This offset marks the start of the symbols that a section has
    // with respect to the symbol table section
    symbol_offset: u32,
    symbol_count: u32,
};

const Section = extern struct{
    unit_offset: u32,
    unit_size: u32,
    description: Description,
    reserved: [3]u8 = .{0} ** 3,

    pub const Description = packed struct(u8){
        type: Section.Type,
        // This does not mean the section cannot be read by the CPU,
        // but if it should be loaded into memory when a piece of code
        // of the binary must be executed
        read: bool,
        write: bool,
        execute: bool,
    };

    const Type = enum(u5){
        code,
        data,
        internal_table,
        external_table,
        relocations,
        symbol_table,
        string_table,
        library,
    };
};

fn prot_flag(flag: u32, b: bool) u32 {
    const result = flag & @as(u32, 0) -% @intFromBool(b);
    return result;
}

fn mmap(address: ?[*]align(std.mem.page_size) u8, size: usize, permissions: struct {
    executable: bool,
    writable: bool,
}) ![]u8{
    const flags = std.posix.PROT.READ | prot_flag(std.posix.PROT.WRITE, permissions.writable) | prot_flag(std.posix.PROT.EXEC, permissions.executable);
    const result = try std.posix.mmap(address, size, flags, .{
        .TYPE = .PRIVATE,
        .ANONYMOUS = true,
    }, -1, 0);
    return result;
}

const mov_rsp_rdi = [_]u8{0x48, 0x89, 0xfc};

const xor_eax_eax = [_]u8{0x31, 0xc0};
const ret = [1]u8{0xc3};

const ret0 = xor_eax_eax ++ ret;
const ret0_function_type = fn () callconv(.C) i32;

fn call(operand: i32) [5]u8{
    return [_]u8{ 0xe8 } ++ @as([4]u8, @bitCast(operand));
}
fn mov_eax_imm32(imm32: u32) [5]u8 {
    return [1]u8{0xb8} ++ @as(*const [4]u8, @ptrCast(&imm32)).*;
}

fn mov_edi_imm32(imm32: u32) [5]u8 {
    return [1]u8{0xbf} ++ @as(*const [4]u8, @ptrCast(&imm32)).*;
}

fn mov_rip_mem_eax(operand: i32) [6]u8{
    return .{0x89, 0x5} ++ @as([4]u8, @bitCast(operand));
}

fn sub_eax_imm8(imm8: u8) [3]u8{
    return [_]u8{0x83, 0xe8, imm8};
}

const number = 5;
const mov_eax_edi = [_]u8{0x89, 0xf8};
const mov_edi_eax = [_]u8{0x89, 0xc7};
const syscall = [_]u8{0x0f, 0x05};
const xor_edi_edi = [_]u8{0x31, 0xff};
const inc_edi = [_]u8{0xff, 0xc7};
const exit = mov_eax_imm32(231) ++ syscall;
const call_relocatable = call(0);

fn lea_rsi_rip_mem(offset: i32) [7]u8{
    return .{0x48, 0x8d, 0x35} ++ @as([4]u8, @bitCast(offset));
}

/////////////////

const program =
    mov_rsp_rdi ++
    call_relocatable ++
    sub_eax_imm8(number) ++
    mov_edi_eax ++
    exit;

////////////////


const Relocation = extern struct{
    destination: Destination,
    source: Source,

    const Destination = Symbol.Reference;

    const Source = extern struct {
        reference: Symbol.Reference,
        offset_from_symbol: u16,
        write_offset: u8,
        relative_offset: u8,
    };
};

const Symbol = extern struct {
    const Reference = extern struct {
        symbol: u32,
        reference_to_parent: u32,
    };
    const Information = extern struct{
        reference_to_parent: u32,
        section: u32,
        name: NameReference,
    };
};

const FileReference = extern struct {
    offset_in_section: u32,
    section_index: u32,
};

// This struct refers to a spot in the string table section,
// the offset being with respect to the start of the section
const NameReference = extern struct {
    offset: u32,
    length: u32,
};

const Library = extern struct {
    name: NameReference,
    symbol_count: u32,
    symbol_offset: u32,
};

const LibrarySymbol = extern struct{
    name: NameReference,
};

fn mov_edx_imm32(imm32: u32) [5]u8{
    return [_]u8{ 0xba } ++ @as([4]u8, @bitCast(imm32));
}

fn add_eax_imm8(imm8: u8) [3]u8 {
    return [_]u8{ 0x83, 0xc0, imm8 };
}

// These two are assumed to be concatenated so RIP-relative addressing works
const main_print_library_code = 
    // -11 -> 5 call instruction + 3 mov rsp, rdi + 1 ret + 5 call instruction
    // Set up the stack
    mov_rsp_rdi ++
    // Call the function to get the number
    call(0) ++
    add_eax_imm8('0') ++
    // Mov the 32-bit into the data section so that it can be printed
    mov_rip_mem_eax(0) ++ 
    // 1 - write syscall id
    mov_eax_imm32(1) ++
    // 1 - file descriptor: stdout
    mov_edi_imm32(1) ++
    // Move that character buffer pointer as first argument
    lea_rsi_rip_mem(0) ++ 
    // 1 - stdout file descriptor
    mov_edx_imm32(1) ++
    // write(stdout, &buffer, 1);
    syscall ++
    // exit(0);
    xor_edi_edi ++
    mov_eax_imm32(231) ++
    syscall;

const library_code_function = mov_eax_imm32(number) ++ ret;
const main_print_library_code_relocations = [_]Relocation{
    .{
        .destination = .{
            .reference_to_parent = 0,
            .symbol = 1,
        },
        .source = .{
            .reference = .{
                .reference_to_parent = 0,
                .symbol = 0,
            },
            .offset_from_symbol = mov_rsp_rdi.len,
            .write_offset = 1,
            .relative_offset = 5,
        },
    },
    .{
        .destination = .{
            .reference_to_parent = 1,
            .symbol = 0,
        },
        .source = .{
            .reference = .{
                .reference_to_parent = 0,
                .symbol = 0,
            },
            .offset_from_symbol = @intCast(mov_rsp_rdi.len + call(0).len + add_eax_imm8(0).len),
            .write_offset = 2,
            .relative_offset = 6,
        },
    },
    .{
        .destination = .{
            .reference_to_parent = 1,
            .symbol = 0,
        },
        .source = .{
            .reference = .{
                .reference_to_parent = 0,
                .symbol = 0,
            },
            .offset_from_symbol = @intCast(mov_rsp_rdi.len + call(0).len + add_eax_imm8(0).len + mov_rip_mem_eax(0).len + mov_eax_imm32(1).len + mov_edi_imm32(1).len),
            .write_offset = 3,
            .relative_offset = 7,
        },
    },
};

const FileWriter = std.ArrayListAlignedUnmanaged(u8, std.mem.page_size);
fn add_struct(file_writer: *FileWriter, comptime T: type) *T {
    const byte_slice = file_writer.addManyAsSliceAssumeCapacity(@sizeOf(T));
    const result: *T = @alignCast(@ptrCast(byte_slice.ptr));
    return result;
}

fn add_structs(file_writer: *FileWriter, comptime T: type, count: usize) []T {
    const byte_slice = file_writer.addManyAsSliceAssumeCapacity(@sizeOf(T) * count);
    const result: [*]T = @alignCast(@ptrCast(byte_slice.ptr));
    return result[0..count];
}

const WriteBinaryOptions = struct {
    path: []const u8,
    sections: []const SectionData,
    internal_relocations: []const Relocation,
    libraries: []const LibraryData,
    external_relocations: []const Relocation,
    entry_point: Symbol.Reference,
    kind: Header.Kind,
    linkage: Header.Linkage,

    const SectionData = struct {
        symbols: []const SymbolData,
        description: Section.Description,
        start_alignment: u32 = 4,
    };

    const SymbolData = struct {
        bytes: []const u8,
        name: []const u8,
    };

    const LibraryData = struct {
        name: []const u8,
        symbols: []const []const u8,
    };
};

fn write_binary(allocator: Allocator, options: WriteBinaryOptions) !void {
    if (options.sections.len == 0) {
        @panic("Executable must contain at least one section");
    }
    const relocations_resolved = options.linkage == .static or options.libraries.len == 0;
    const buffer = try mmap(null, 0x1000, .{ .writable = true, .executable = false });
    var array_list = FileWriter.initBuffer(@alignCast(buffer));
    const header = add_struct(&array_list, Header);
    const section_headers = add_structs(&array_list, Section,
        options.sections.len +
        1 + // internal (symbol) table 
        @intFromBool(options.linkage == .dynamic and options.libraries.len > 0) + // external (symbol) table
        @intFromBool(options.linkage == .dynamic and options.libraries.len > 0) + // relocation table
        1 + // general symbol table
        1 // string table
    );
    var string_table = std.ArrayListUnmanaged(u8){};
    var section_symbol_tables = std.ArrayListUnmanaged(SectionSymbolOffsetHeader){};
    var symbol_table_symbols = std.ArrayListUnmanaged(Symbol.Information){};

    for (options.sections, section_headers[0..options.sections.len], 0..) |section, *section_header, section_index| {
        array_list.items.len = std.mem.alignForward(usize, array_list.items.len, section.start_alignment);
        const section_start = array_list.items.len;

        try section_symbol_tables.append(allocator, .{
            .symbol_offset = @intCast(symbol_table_symbols.items.len),
            .symbol_count = @intCast(section.symbols.len),
        });
                           
        for (section.symbols) |symbol| {
            const symbol_info = Symbol.Information{
                .section = @intCast(section_index),
                // section offset
                .reference_to_parent = @intCast(array_list.items.len - section_start),
                .name = .{
                    .offset = @intCast(string_table.items.len),
                    .length = @intCast(symbol.name.len),
                },
            };
            std.debug.print("{s} symbol (section {}): {s}\n", .{options.path, section_index, symbol.name});
            try symbol_table_symbols.append(allocator, symbol_info);
            try string_table.appendSlice(allocator, symbol.name);
            array_list.appendSliceAssumeCapacity(symbol.bytes);
        }

        section_header.* = .{
            .unit_offset = @intCast(section_start),
            .unit_size = @intCast(array_list.items.len - section_start),
            .description = section.description,
        };
    }

    array_list.items.len = std.mem.alignForward(usize, array_list.items.len, 4);
    const section_symbol_table_bytes = std.mem.sliceAsBytes(section_symbol_tables.items);
    var section_index: usize = options.sections.len;
    section_headers[section_index] = .{
        .unit_offset = @intCast(array_list.items.len),
        .unit_size = @intCast(section_symbol_table_bytes.len),
        .description = .{
            .type = .internal_table,
            .read = false,
            .write = false,
            .execute = false,
        },
    };
    section_index += 1;
    array_list.appendSliceAssumeCapacity(section_symbol_table_bytes);

    switch (options.linkage) {
        .dynamic => {
            var libraries = std.ArrayListUnmanaged(Library){};

            if (options.libraries.len > 0) {
                array_list.items.len = std.mem.alignForward(usize, array_list.items.len, 4);
                assert(options.external_relocations.len > 0);


                for (options.libraries, 0..) |library, library_i| {
                    const lib = Library{
                        .name = .{
                            .offset = @intCast(string_table.items.len),
                            .length = @intCast(library.name.len),
                        },
                        .symbol_offset = @intCast(symbol_table_symbols.items.len),
                        .symbol_count = @intCast(library.symbols.len),
                    };
                    try libraries.append(allocator, lib);

                    try string_table.appendSlice(allocator, library.name);

                    for (library.symbols) |symbol| {
                        std.debug.print("(relocation) {s} symbol (library {}, symbol {}): {s}\n", .{options.path, library_i, symbol_table_symbols.items.len, symbol});
                        try symbol_table_symbols.append(allocator, .{
                            // Unused field
                            .section = 0,
                            .reference_to_parent = @intCast(library_i),
                            .name = .{
                                .offset = @intCast(string_table.items.len),
                                .length = @intCast(symbol.len),
                            },
                        });
                        try string_table.appendSlice(allocator, symbol);
                    }
                }

                const library_bytes = std.mem.sliceAsBytes(libraries.items);

                section_headers[section_index] = .{
                    .unit_offset = @intCast(array_list.items.len),
                    .unit_size = @intCast(library_bytes.len),
                    .description = .{
                        .type = .external_table,
                        .read = false,
                        .write = false,
                        .execute = false,
                    },
                };
                section_index += 1;

                array_list.appendSliceAssumeCapacity(library_bytes);
            }

            if (options.external_relocations.len > 0) {
                array_list.items.len = std.mem.alignForward(usize, array_list.items.len, 4);
                assert(options.libraries.len > 0);

                const external_relocation_bytes = std.mem.sliceAsBytes(options.external_relocations);

                section_headers[section_index] = .{
                    .unit_offset = @intCast(array_list.items.len),
                    .unit_size = @intCast(external_relocation_bytes.len),
                    .description = .{
                        .type = .relocations,
                        .read = false,
                        .write = false,
                        .execute = false,
                    },
                };
                section_index += 1;

                array_list.appendSliceAssumeCapacity(external_relocation_bytes);
            }
        },
        .static => unreachable,
    }

    array_list.items.len = std.mem.alignForward(usize, array_list.items.len, 4);
    
    const symbol_table_bytes = std.mem.sliceAsBytes(symbol_table_symbols.items);
    section_headers[section_index] = .{
        .unit_offset = @intCast(array_list.items.len),
        .unit_size = @intCast(symbol_table_bytes.len),
        .description = .{
            .type = .symbol_table,
            .read = false,
            .write = false,
            .execute = false,
        },
    };
    section_index += 1;

    array_list.appendSliceAssumeCapacity(symbol_table_bytes);

    section_headers[section_index] = .{
        .unit_offset = @intCast(array_list.items.len),
        .unit_size = @intCast(string_table.items.len),
        .description = .{
            .type = .string_table,
            .read = false,
            .write = false,
            .execute = false,
        },
    };
    section_index += 1;

    array_list.appendSliceAssumeCapacity(string_table.items);

    assert(section_index == section_headers.len);

    // Relocations are assumed to be 32-bit only
    for (options.internal_relocations) |relocation| {
        const destination_section_symbol_offsets_header = section_symbol_tables.items[relocation.destination.reference_to_parent];
        const destination_symbol_information = symbol_table_symbols.items[ destination_section_symbol_offsets_header.symbol_offset + relocation.destination.symbol];
        const destination_section_header = section_headers[relocation.destination.reference_to_parent];
        const destination_symbol_unit_offset = destination_section_header.unit_offset + destination_symbol_information.reference_to_parent;

        const source_section_symbol_offsets_header = section_symbol_tables.items[relocation.source.reference.reference_to_parent];
        const source_symbol_information = symbol_table_symbols.items[source_section_symbol_offsets_header.symbol_offset + relocation.source.reference.symbol];
        const source_section_header = section_headers[relocation.source.reference.reference_to_parent];
        const source_symbol_unit_offset = source_section_header.unit_offset + source_symbol_information.reference_to_parent;
        
        const dst_i64: i64 = @intCast(destination_symbol_unit_offset);
        assert(dst_i64 < array_list.items.len);
        const source_offset = source_symbol_unit_offset + relocation.source.offset_from_symbol;
        const src_i64: i64 = @intCast(source_offset + relocation.source.relative_offset);
        const relative: i32 = @intCast(dst_i64 - src_i64);
        const ptr: *align(1) i32 = @ptrCast(&array_list.items[source_offset + relocation.source.write_offset]);
        assert(ptr.* == 0);
        ptr.* = relative;
    }

    const entry_point_section_index = options.entry_point.reference_to_parent;
    const entry_point_section_symbol_table = section_symbol_tables.items[entry_point_section_index];
    const entry_point_symbol = symbol_table_symbols.items[entry_point_section_symbol_table.symbol_offset + options.entry_point.symbol];
    const entry_point_section_header = section_headers[entry_point_section_index];
    const entry_point_unit_offset = entry_point_section_header.unit_offset + entry_point_symbol.reference_to_parent;

    header.* = .{
        .arch = .x86_64,
        .os = .linux,
        .abi = .system_v,
        .description = .{
            .kind = options.kind,
            .relocations_resolved = relocations_resolved,
        },
        .section_count = @intCast(section_index),
        .entry_point = entry_point_unit_offset,
        .unit_size = @intCast(array_list.items.len),
    };

    try std.fs.cwd().writeFile(.{
        .sub_path = options.path,
        .data = array_list.items,
    });
}

fn link(allocator: Allocator, options: struct {
    file_path: []const u8,
    linkage: Header.Linkage,
    output: ?[]const u8 = null,
}) ![]const u8 {
    if (options.linkage == .dynamic and options.output != null) {
        @panic("Can't specify output file when linking dynamically");
    }

    const file_descriptor = try std.fs.cwd().openFile(options.file_path, .{});
    const file_memory = try mmap(null, 0x1000 * 64, .{ .writable = true, .executable = true });
    const unit_size = try file_descriptor.getEndPos();
    var file_buffer = std.ArrayListUnmanaged(u8).initBuffer(file_memory);
    file_buffer.items.len = unit_size;
    _ = try file_descriptor.readAll(file_buffer.items);
    file_descriptor.close();

    const header = @as(*Header, @alignCast(@ptrCast(file_buffer.items.ptr))).*;
    const original_section_headers = @as([*]Section, @alignCast(@ptrCast(file_buffer.items.ptr + @sizeOf(Header))))[0..header.section_count];
    var relocation_section_header: Section = undefined;
    var external_table_section_header: Section = undefined;
    var internal_table_section_header: Section = undefined;
    var has_relocations = false;
    var has_external_table = false;

    var symbol_table_section_header: Section = undefined;
    var string_table_section_header:  Section = undefined;

    for (original_section_headers) |section_header| {
        switch (section_header.description.type) {
            .string_table => {
                string_table_section_header = section_header;
            },
            .symbol_table => {
                symbol_table_section_header = section_header;
            },
            else => {},
            .relocations => {
                has_relocations = true;
                relocation_section_header = section_header;
            },
            .internal_table => {
                internal_table_section_header = section_header;
            },
            .external_table => {
                has_external_table = true;
                external_table_section_header = section_header;
            },
        }
    }

    if (has_relocations != has_external_table) {
        @panic("Relocations must match an external table");
    }

    if (has_relocations) {
        const section_headers = try allocator.dupe(Section, original_section_headers);
        var libraries_loaded = std.BoundedArray([]const u8, 32){};
        var libraries_bytes = std.BoundedArray([]const u8, 32){};

        const internal_count = @divExact(internal_table_section_header.unit_size, @sizeOf(SectionSymbolOffsetHeader));
        const internal_table = try allocator.dupe(SectionSymbolOffsetHeader, @as([*]SectionSymbolOffsetHeader, @alignCast(@ptrCast(&file_buffer.items[internal_table_section_header.unit_offset])))[0..internal_count]);
        const library_count = @divExact(external_table_section_header.unit_size, @sizeOf(Library));
        const libraries = try allocator.dupe(Library, @as([*]Library, @alignCast(@ptrCast(&file_buffer.items[external_table_section_header.unit_offset])))[0..library_count]);
        const relocation_count = @divExact(relocation_section_header.unit_size, @sizeOf(Relocation));
        const relocations = try allocator.dupe(Relocation, @as([*]Relocation, @alignCast(@ptrCast(&file_buffer.items[relocation_section_header.unit_offset])))[0..relocation_count]);
        const symbol_count = @divExact(symbol_table_section_header.unit_size, @sizeOf(Symbol.Information));
        const symbol_table = try allocator.dupe(Symbol.Information, @as([*]Symbol.Information, @alignCast(@ptrCast(&file_buffer.items[symbol_table_section_header.unit_offset])))[0..symbol_count]);
        const string_table = try allocator.dupe(u8, file_buffer.items[string_table_section_header.unit_offset..][0..string_table_section_header.unit_size]);

        for (relocations) |relocation| {
            const destination_library_index = relocation.destination.reference_to_parent;
            const destination_symbol_index = relocation.destination.symbol;
            const library = libraries[destination_library_index];
            const library_name = string_table[library.name.offset..][0..library.name.length];

            const library_bytes = for (libraries_loaded.constSlice(), 0..) |library_string, i| {
                if (std.mem.eql(u8, library_string, library_name)) {
                    break libraries_bytes.constSlice()[i];
                }
            } else block: {
                // If the library is not found, the dynamic linker appends it to the end of the file
                const library_file_descriptor = try std.fs.cwd().openFile(library_name, .{}); 
                const library_size = try library_file_descriptor.getEndPos();
                const library_offset = std.mem.alignForward(usize, file_buffer.items.len, 16);
                file_buffer.items.len = library_offset + library_size;
                const library_file = file_buffer.items[library_offset..][0..library_size];
                _ = try library_file_descriptor.readAll(library_file);
                const library_header: *Header = @alignCast(@ptrCast(library_file.ptr));
                assert(library_header.description.relocations_resolved);

                libraries_loaded.appendAssumeCapacity(library_name);
                libraries_bytes.appendAssumeCapacity(library_file);

                break :block library_file;
            };

            const library_offset = @intFromPtr(library_bytes.ptr) - @intFromPtr(file_buffer.items.ptr);

            const library_header: *const Header = @alignCast(@ptrCast(library_bytes.ptr));
            const library_section_count = library_header.section_count;
            const library_sections = @as([*]const Section, @alignCast(@ptrCast(library_bytes.ptr + @sizeOf(Header))))[0..library_section_count];
            const library_symbol_section_header = for (library_sections) |library_section| {
                if (library_section.description.type == .symbol_table) {
                    break library_section;
                }
            } else unreachable;
            const library_string_table_header = for (library_sections) |library_section| {
                if (library_section.description.type == .string_table) {
                    break library_section;
                }
            } else unreachable;
            const library_string_table = library_bytes[library_string_table_header.unit_offset..][0..library_string_table_header.unit_size];
            const library_symbols = std.mem.bytesAsSlice(Symbol.Information, library_bytes[library_symbol_section_header.unit_offset..][0..library_symbol_section_header.unit_size]);

            const wanted_symbol_information = symbol_table[library.symbol_offset + destination_symbol_index];
            const wanted_symbol_name = string_table[wanted_symbol_information.name.offset..][0..wanted_symbol_information.name.length];

            for (library_symbols) |symbol| {
                const symbol_name = library_string_table[symbol.name.offset..][0..symbol.name.length];
                if (std.mem.eql(u8, symbol_name, wanted_symbol_name)) {
                    const destination_library_symbol_section_index = symbol.section;
                    const destination_section_offset = symbol.reference_to_parent;
                    const destination_library_section = library_sections[destination_library_symbol_section_index];
                    const destination_offset_wrt_library = destination_library_section.unit_offset + destination_section_offset;
                    const destination_file_offset = library_offset + destination_offset_wrt_library;

                    const source_section_symbol_offsets_header = internal_table[relocation.source.reference.reference_to_parent];
                    const source_symbol_information = symbol_table[source_section_symbol_offsets_header.symbol_offset + relocation.source.reference.symbol];
                    const source_section_header = section_headers[relocation.source.reference.reference_to_parent];
                    const source_symbol_unit_offset = source_section_header.unit_offset + source_symbol_information.reference_to_parent;

                    const dst_i64: i64 = @intCast(destination_file_offset);
                    const source_offset = source_symbol_unit_offset + relocation.source.offset_from_symbol;
                    const src_i64: i64 = @intCast(source_offset + relocation.source.relative_offset);
                    const relative: i32 = @intCast(dst_i64 - src_i64);
                    const ptr: *align(1) i32 = @ptrCast(&file_buffer.items[source_offset + relocation.source.write_offset]);
                    assert(ptr.* == 0);
                    ptr.* = relative;
                    break;
                }
            } else {
                @panic("Symbol not found");
            }
        }
    }

    if (options.output) |output_file_path| {
        try std.fs.cwd().writeFile(.{
            .sub_path = output_file_path,
            .data = file_buffer.items,
        });
    }

    return file_buffer.items;
}

fn load_from_file(file_path: []const u8) !noreturn {
    const file_descriptor = try std.fs.cwd().openFile(file_path, .{});
    const bytes = try mmap(null, 0x1000, .{ .writable = true, .executable = true });
    _ = try file_descriptor.readAll(bytes);
    const stack = try mmap(null, 0x1000, .{ .writable = true, .executable = false });
    const header = @as(*Header, @alignCast(@ptrCast(bytes.ptr))).*;
    const entry_point: *const fn (stack_top: u64) callconv(.C) noreturn = @ptrCast(bytes.ptr + header.entry_point);
    entry_point(@intFromPtr(stack.ptr + stack.len));
}

fn load_from_memory(bytes: []const u8) !noreturn {
    const stack = try mmap(null, 0x1000, .{ .writable = true, .executable = false });
    const header = @as(*Header, @alignCast(@ptrCast(bytes.ptr))).*;
    const entry_point: *const fn (stack_top: u64) callconv(.C) noreturn = @ptrCast(bytes.ptr + header.entry_point);
    entry_point(@intFromPtr(stack.ptr + stack.len));
}

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const allocator = arena.allocator();
    const library_file_path = "library.nat";

    const library_function_name = "library_function";
    try write_binary(allocator, .{
        .path = library_file_path,
        .kind = .executable,
        .linkage = .dynamic,
        .sections = &.{
            .{ 
                .symbols = &.{
                    .{
                        .bytes = &main_print_library_code,
                        .name = "_start",
                    },
                    .{
                        .bytes = &library_code_function,
                        .name = library_function_name,
                    },
                },
                .description = .{
                    .type = .code,
                    .read = true,
                    .write = false,
                    .execute = true,
                },
            },
            .{ 
                .symbols = &.{
                    .{
                        .bytes = &.{0},
                        .name = "buffer",
                    },
                },
                .description = .{
                    .type = .data,
                    .read = true,
                    .write = true,
                    .execute = false,
                },
            },
        },
        .internal_relocations = &main_print_library_code_relocations,
        .libraries = &.{},
        .external_relocations = &.{},
        .entry_point = .{
            .reference_to_parent = 0,
            .symbol = 0,
        },
    });

    const executable_file_path = "executable.nat";
    try write_binary(allocator, .{
        .path = executable_file_path,
        .sections = &.{
            .{
                .symbols = &.{
                    .{
                        .bytes = &main_print_library_code,
                        .name = "_start",
                    },
                },
                .description = .{
                    .type = .code,
                    .read = true,
                    .write = false,
                    .execute = true,
                },
            },
            .{ 
                .symbols = &.{
                    .{
                        .bytes = &.{0},
                        .name = "buffer",
                    },
                },
                .description = .{
                    .type = .data,
                    .read = true,
                    .write = true,
                    .execute = false,
                },
            },
        },
        // Avoid the first internal relocation since it's relocating the call and we want to relocate to a library symbol
        .internal_relocations = main_print_library_code_relocations[1..],
        .libraries = &.{
            .{
                .name = library_file_path,
                .symbols = &.{
                    library_function_name,
                },
            },
        },
        .external_relocations = &.{
            .{
                .destination = .{
                    .symbol = 0,
                    // This is the library index
                    .reference_to_parent = 0,
                },
                .source = .{
                    .reference = .{
                        .symbol = 0,
                        .reference_to_parent = 0,
                    },
                    .offset_from_symbol = mov_rsp_rdi.len,
                    .write_offset = 1,
                    .relative_offset = 5,
                },
            },
        },
        .entry_point = .{
            .symbol = 0,
            .reference_to_parent = 0,
        },
        .kind = .executable,
        .linkage = .dynamic,
    });

    const dynamic = try link(allocator, .{
        .file_path = executable_file_path,
        .linkage = .dynamic,
    });
    _ = dynamic; // autofix

    const static_file_path = "static.nat";
    const static = try link(allocator, .{
        .file_path = executable_file_path,
        .linkage = .static,
        .output = static_file_path,
    });
    _ = static; // autofix
    try load_from_file(static_file_path);
}
