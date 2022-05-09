module test_zk_split(transaction, encoded_output);
    input [3703:0] transaction;
    output [703:0] encoded_output;

    wire [255:0] split_transaction_hash;
    sighash_split zk_unit(
        .nversion(transaction[3703:3672]),
        .hash_prevouts(transaction[3671:3416]),
        .hash_sequence(transaction[3415:3160]),
        .in_txid(transaction[3159:2904]),
        .in_vout(transaction[2903:2872]),
        .script(transaction[2871:1000]),
        .in_amount(transaction[0999:0936]),
        .in_nseq(transaction[0935:0904]),
        .locktime(transaction[0903:0872]),
        .sighash_type(transaction[0871:0840]),
        .encoded_outputs(transaction[0839:0000]),
        .sighash(split_transaction_hash)
    );

    wire [255:0] txaed_transaction_hash;
    wire [255:0] tmout_transaction_hash;

    wire [255:0] split_transaction_txid;
    txid_split txid_unit(
        .nvesion(transaction[3703:3672]),
        .txin({8'h1, transaction[3159:2904], transaction[2903:2872], 8'h0, transaction[935:904]}),
        .txout({8'h3, transaction[839:0]}),
        .locktime(transaction[903:872]),
        .hash_txid(split_transaction_txid)
    );

    assign encoded_output = (transaction > 0)
        ? {
            transaction[839:776],
            transaction[495:432],
            transaction[247:184],
            split_transaction_txid,
            split_transaction_hash
        }
        : 448'h0;
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
    input [839:0] encoded_outputs;
    output [255:0] sighash;

    localparam SHA256_H0 = 256'h6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19;
    wire [255:0] init_state;
    assign init_state = SHA256_H0;

    wire [255:0] hash_outputs_state1;
    sha256 hash_outputs_intermediate_round1(
        .data(encoded_outputs[839:328]),
        .state(init_state),
        .next_state(hash_outputs_state1)
    );

    wire [255:0] hash_outputs_intermediate;
    sha256 hash_outputs_intermediate_round2(
        .data({encoded_outputs[327:0], 184'h8000000000000000000000000000000000000000000348}),
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

module txid_split_test (hash_all_preimage, hash_txid);
    input [1247:0] hash_all_preimage;
    output [255:0] hash_txid;

    txid_split test(
        .nvesion(hash_all_preimage[1247:1216]),
        .txin(hash_all_preimage[1215:880]),
        .txout(hash_all_preimage[879:32]),
        .locktime(hash_all_preimage[31:0]),
        .hash_txid(hash_txid)
    );
endmodule

module txid_split (nvesion, txin, txout, locktime, hash_txid);
    input [31:0] nvesion;
    input [335:0] txin;
    input [847:0] txout;
    input [31:0] locktime;
    output [255:0] hash_txid;

    wire [1247:0] hash_all_preimage;
    assign hash_all_preimage = {nvesion, txin, txout, locktime};

    localparam SHA256_H0 = 256'h6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19;
    wire [255:0] init_state;
    assign init_state = SHA256_H0;

    wire [255:0] hash_all_state1;
    sha256 hash_all_intermediate_round1(
        .data(hash_all_preimage[1247:736]),
        .state(init_state),
        .next_state(hash_all_state1)
    );

    wire [255:0] hash_all_state2;
    sha256 hash_all_intermediate_round2(
        .data(hash_all_preimage[735:224]),
        .state(hash_all_state1),
        .next_state(hash_all_state2)
    );

    wire [255:0] hash_all_intermediate;
    sha256 hash_all_intermediate_round3(
        .data({hash_all_preimage[223:0], 288'h8000000000000000000000000000000000000000000000000000000000000000000004e0}),
        .state(hash_all_state2),
        .next_state(hash_all_intermediate)
    );

    wire [255:0] hash_all_final;
    sha256 hash_all_final_round1(
        .data({hash_all_intermediate, 256'h8000000000000000000000000000000000000000000000000000000000000100}),
        .state(init_state),
        .next_state(hash_all_final)
    );
    assign hash_txid = hash_all_final;

endmodule