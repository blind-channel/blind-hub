module test_sighash_aed_timeout(transaction, sighash);
    input [1815:0] transaction;
    output [255:0] sighash;

    sighash_aed_timeout zk_unit(
        .nversion(transaction[1815:1784]),
        .in_txid(transaction[1271:1016]),
        .in_vout(transaction[1015:0984]),
        .hash_sequence(transaction[1527:1272]),
        .script(transaction[0983:0408]),
        .in_amount(transaction[0407:0344]),
        .in_nseq(transaction[0343:0312]),
        .locktime(transaction[0311:0280]),
        .sighash_type(transaction[0279:0248]),
        .encoded_outputs(transaction[0247:0000]),
        .sighash(sighash)
    );
endmodule

module sighash_aed_timeout(nversion, in_txid, in_vout, hash_sequence, script, in_amount, in_nseq, locktime, sighash_type, encoded_outputs, sighash);
    input [31:0] nversion;
    input [255:0] in_txid;
    input [31:0] in_vout;
    input [255:0] hash_sequence;
    input [575:0] script;
    input [63:0] in_amount;
    input [31:0] in_nseq;
    input [31:0] locktime;
    input [31:0] sighash_type;
    input [247:0] encoded_outputs;
    output [255:0] sighash;

    localparam SHA256_H0 = 256'h6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19;
    wire [255:0] init_state;
    assign init_state = SHA256_H0;

    wire [255:0] hash_prevout_intermediate;
    sha256 hash_prevout_intermediate_round1(
        .data({in_txid, in_vout, 224'h80000000000000000000000000000000000000000000000000000120}),
        .state(init_state),
        .next_state(hash_prevout_intermediate)
    );

    wire [255:0] hash_prevouts;
    sha256 hash_prevout_final(
        .data({hash_prevout_intermediate, 256'h8000000000000000000000000000000000000000000000000000000000000100}),
        .state(init_state),
        .next_state(hash_prevouts)
    );

    wire [255:0] hash_outputs_intermediate;
    sha256 hash_outputs_intermediate_round1(
        .data({encoded_outputs, 264'h8000000000000000000000000000000000000000000000000000000000000000f8}),
        .state(init_state),
        .next_state(hash_outputs_intermediate)
    );

    wire [255:0] hash_outputs;
    sha256 hash_outputs_final(
        .data({hash_outputs_intermediate, 256'h8000000000000000000000000000000000000000000000000000000000000100}),
        .state(init_state),
        .next_state(hash_outputs)
    );

    wire [1823:0] hash_all_preimage;
    assign hash_all_preimage = {
        nversion,
        hash_prevouts,
        hash_sequence,
        in_txid,
        in_vout,
        script,
        in_amount,
        in_nseq,
        hash_outputs,
        locktime,
        sighash_type
    };

    wire [255:0] hash_all_intermediate_state1;
    sha256 hash_all_intermediate_round1(
        .data(hash_all_preimage[1823:1312]),
        .state(init_state),
        .next_state(hash_all_intermediate_state1)
    );

    wire [255:0] hash_all_intermediate_state2;
    sha256 hash_all_intermediate_round2(
        .data(hash_all_preimage[1311:800]),
        .state(hash_all_intermediate_state1),
        .next_state(hash_all_intermediate_state2)
    );

    wire [255:0] hash_all_intermediate_state3;
    sha256 hash_all_intermediate_round3(
        .data(hash_all_preimage[799:288]),
        .state(hash_all_intermediate_state2),
        .next_state(hash_all_intermediate_state3)
    );

    wire [255:0] hash_all_intermediate;
    sha256 hash_all_intermediate_round4(
        .data({hash_all_preimage[287:0], 224'h80000000000000000000000000000000000000000000000000000720}),
        .state(hash_all_intermediate_state3),
        .next_state(hash_all_intermediate)
    );

    wire [255:0] hash_all;
    sha256 hash_all_final(
        .data({hash_all_intermediate, 256'h8000000000000000000000000000000000000000000000000000000000000100}),
        .state(init_state),
        .next_state(hash_all)
    );

    assign sighash = hash_all;
endmodule