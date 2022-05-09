module uint64_le_native_transform (
    input wire [63:0] uint64_in,
    output wire [63:0] uint64_out
);
    assign uint64_out = {
        uint64_in[ 7: 0],
        uint64_in[15: 8],
        uint64_in[23:16],
        uint64_in[31:24],
        uint64_in[39:32],
        uint64_in[47:40],
        uint64_in[55:48],
        uint64_in[63:56]
    };
endmodule