module test_zk_split_final(transaction, split_transaction_hash);
    input [3360:0] transaction;
    output [255:0] split_transaction_hash;

    sighash_split zk_unit(
        .nversion(transaction[3359:3328]),
        .hash_prevouts(transaction[3327:3072]),
        .hash_sequence(transaction[3071:2816]),
        .in_txid(transaction[2815:2560]),
        .in_vout(transaction[2559:2528]),
        .script(transaction[2527:0656]),
        .in_amount(transaction[0655:0592]),
        .in_nseq(transaction[0591:0560]),
        .locktime(transaction[0559:0528]),
        .sighash_type(transaction[0527:0496]),
        .encoded_outputs({
            transaction[0127:0064],
            transaction[0495:0312],
            transaction[0063:0000],
            transaction[0311:0128]
        }),
        .sighash(split_transaction_hash)
    );
endmodule

module sighash_split (nversion, hash_prevouts, hash_sequence, in_txid, in_vout, script, in_amount, in_nseq, locktime, sighash_type, encoded_outputs, sighash);
    input [31:0] nversion;
    input [255:0] hash_prevouts;
    input [255:0] hash_sequence;
    input [255:0] in_txid;
    input [31:0] in_vout;
    input [1871:0] script;
    input [63:0] in_amount;
    input [31:0] in_nseq;
    input [31:0] locktime;
    input [31:0] sighash_type;
    input [495:0] encoded_outputs;
    output [255:0] sighash;

    localparam SHA256_H0 = 256'h6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19;
    wire [255:0] init_state;
    assign init_state = SHA256_H0;

    wire [255:0] hash_outputs_state1;
    sha256 hash_outputs_intermediate_round1(
        .data({encoded_outputs, 16'h8000}),
        .state(init_state),
        .next_state(hash_outputs_state1)
    );

    wire [255:0] hash_outputs_intermediate;
    sha256 hash_outputs_intermediate_round2(
        .data(512'h1f0),
        .state(hash_outputs_state1),
        .next_state(hash_outputs_intermediate)
    );

    wire [255:0] hash_outputs;
    sha256 hash_outputs_final_round1(
        .data({hash_outputs_intermediate, 256'h8000000000000000000000000000000000000000000000000000000000000100}),
        .state(init_state),
        .next_state(hash_outputs)
    );

    wire [3119:0] hash_all_preimage;
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

    wire [255:0] hash_all_state1;
    sha256 hash_all_intermediate_round1(
        .data(hash_all_preimage[3119:2608]),
        .state(init_state),
        .next_state(hash_all_state1)
    );

    wire [255:0] hash_all_state2;
    sha256 hash_all_intermediate_round2(
        .data(hash_all_preimage[2607:2096]),
        .state(hash_all_state1),
        .next_state(hash_all_state2)
    );

    wire [255:0] hash_all_state3;
    sha256 hash_all_intermediate_round3(
        .data(hash_all_preimage[2095:1584]),
        .state(hash_all_state2),
        .next_state(hash_all_state3)
    );

    wire [255:0] hash_all_state4;
    sha256 hash_all_intermediate_round4(
        .data(hash_all_preimage[1583:1072]),
        .state(hash_all_state3),
        .next_state(hash_all_state4)
    );

    wire [255:0] hash_all_state5;
    sha256 hash_all_intermediate_round5(
        .data(hash_all_preimage[1071:560]),
        .state(hash_all_state4),
        .next_state(hash_all_state5)
    );

    wire [255:0] hash_all_state6;
    sha256 hash_all_intermediate_round6(
        .data(hash_all_preimage[559:48]),
        .state(hash_all_state5),
        .next_state(hash_all_state6)
    );

    wire [255:0] hash_all_intermediate;
    sha256 hash_all_intermediate_round7(
        .data({hash_all_preimage[47:0], 464'h80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c30}),
        .state(hash_all_state6),
        .next_state(hash_all_intermediate)
    );

    wire [255:0] hash_all_final;
    sha256 hash_all_final_round1(
        .data({hash_all_intermediate, 256'h8000000000000000000000000000000000000000000000000000000000000100}),
        .state(init_state),
        .next_state(hash_all_final)
    );

    assign sighash = hash_all_final;
endmodule