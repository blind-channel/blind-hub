module zk_sat_all(encoded_sighash_transaction, satisfiable);
    input [6887:0] encoded_sighash_transaction;
    output satisfiable;
    wire [255:0] sighash_split_comp;
    wire [255:0] sighash_txaed_comp;
    wire [255:0] sighash_tmout_comp;
    wire [6119:0] encoded_transaction;
    wire [255:0] sighash_split;
    wire [255:0] sighash_txaed;
    wire [255:0] sighash_tmout;

    assign {encoded_transaction, sighash_split_comp, sighash_txaed_comp, sighash_tmout_comp} = encoded_sighash_transaction;

    zk_all zk_all_unit(
        .encoded_transaction(encoded_transaction),
        .sighash_all({sighash_split, sighash_txaed, sighash_tmout})
    );
    
    assign satisfiable = (sighash_split_comp == sighash_split && sighash_txaed_comp == sighash_txaed && sighash_tmout_comp == sighash_tmout)
        ? 1
        : 0;
endmodule

module zk_all(encoded_transaction, sighash_all);
    input [6119:0] encoded_transaction;
    output [767:0] sighash_all;
    wire [255:0] sighash_split;
    wire [255:0] sighash_txaed;
    wire [255:0] sighash_tmout;

    wire [63:0] amount_native;
    uint64_le_native_transform amount_to_native(
        .uint64_in(encoded_transaction[0191:0128]),
        .uint64_out(amount_native)
    );

    wire [63:0] fee_native;
    uint64_le_native_transform fee_to_native(
        .uint64_in(encoded_transaction[0255:0192]),
        .uint64_out(fee_native)
    );

    wire [63:0] amount_minus_fee_native;
    assign amount_minus_fee_native = amount_native - fee_native;

    wire [63:0] amount_minus_fee;
    uint64_le_native_transform amount_minus_fee_to_le(
        .uint64_in(amount_minus_fee_native),
        .uint64_out(amount_minus_fee)
    );


    wire [255:0] split_transaction_txid;
    txid_split txid_unit(
        .nvesion(encoded_transaction[6119:6088]),
        .txin({8'h1, encoded_transaction[5575:5320], encoded_transaction[5319:5288], 8'h0, encoded_transaction[3351:3320]}),
        .txout({
            8'h3,
            encoded_transaction[0191:0128],
            encoded_transaction[1271:0992],
            encoded_transaction[0127:0064],
            encoded_transaction[0991:0808],
            encoded_transaction[0063:0000],
            encoded_transaction[0807:0624]
        }),
        .locktime(encoded_transaction[3319:3288]),
        .hash_txid(split_transaction_txid)
    );

    sighash_split sighash_split_unit(
        .nversion(encoded_transaction[6119:6088]),
        .hash_prevouts(encoded_transaction[6087:5832]),
        .hash_sequence(encoded_transaction[5831:5576]),
        .in_txid(encoded_transaction[5575:5320]),
        .in_vout(encoded_transaction[5319:5288]),
        .script(encoded_transaction[5287:3416]),
        .in_amount(encoded_transaction[3415:3352]),
        .in_nseq(encoded_transaction[3351:3320]),
        .locktime(encoded_transaction[3319:3288]),
        .encoded_outputs({
            encoded_transaction[0191:0128],
            encoded_transaction[1271:0992],
            encoded_transaction[0127:0064],
            encoded_transaction[0991:0808],
            encoded_transaction[0063:0000],
            encoded_transaction[0807:0624]
        }),
        .sighash_type(encoded_transaction[3287:3256]),
        .sighash(sighash_split)
    );

    sighash_aed_timeout sighash_aed_unit(
        .nversion(encoded_transaction[3255:3224]),
        .hash_sequence(encoded_transaction[3223:2968]),
        .in_txid(split_transaction_txid),
        .in_vout(encoded_transaction[2967:2936]),
        .script(encoded_transaction[2935:2360]),
        .in_amount(encoded_transaction[0191:0128]),
        .in_nseq(encoded_transaction[2359:2328]),
        .locktime(encoded_transaction[2327:2296]),
        .encoded_outputs({
            amount_minus_fee,
            encoded_transaction[0623:0440]
        }),
        .sighash_type(encoded_transaction[2295:2264]),
        .sighash(sighash_txaed)
    );

    sighash_aed_timeout sighash_timeout_unit(
        .nversion(encoded_transaction[2263:2232]),
        .hash_sequence(encoded_transaction[2231:1976]),
        .in_txid(split_transaction_txid),
        .in_vout(encoded_transaction[1975:1944]),
        .script(encoded_transaction[1943:1368]),
        .in_amount(encoded_transaction[0191:0128]),
        .in_nseq(encoded_transaction[1367:1336]),
        .locktime(encoded_transaction[1335:1304]),
        .encoded_outputs({
            amount_minus_fee,
            encoded_transaction[0439:0256]
        }),
        .sighash_type(encoded_transaction[1303:1272]),
        .sighash(sighash_tmout)
    );

    assign sighash_all = {sighash_split, sighash_txaed, sighash_tmout};
endmodule