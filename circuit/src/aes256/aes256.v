module aes256(
    input wire [255:0] key,
    input wire [127:0] msg,
    output wire [127:0] out,
);
    raw_aes256 aes(
        .w0(key[0]),
        .w1(key[1]),
        .w2(key[2]),
        .w3(key[3]),
        .w4(key[4]),
        .w5(key[5]),
        .w6(key[6]),
        .w7(key[7]),
        .w8(key[8]),
        .w9(key[9]),
        .w10(key[10]),
        .w11(key[11]),
        .w12(key[12]),
        .w13(key[13]),
        .w14(key[14]),
        .w15(key[15]),
        .w16(key[16]),
        .w17(key[17]),
        .w18(key[18]),
        .w19(key[19]),
        .w20(key[20]),
        .w21(key[21]),
        .w22(key[22]),
        .w23(key[23]),
        .w24(key[24]),
        .w25(key[25]),
        .w26(key[26]),
        .w27(key[27]),
        .w28(key[28]),
        .w29(key[29]),
        .w30(key[30]),
        .w31(key[31]),
        .w32(key[32]),
        .w33(key[33]),
        .w34(key[34]),
        .w35(key[35]),
        .w36(key[36]),
        .w37(key[37]),
        .w38(key[38]),
        .w39(key[39]),
        .w40(key[40]),
        .w41(key[41]),
        .w42(key[42]),
        .w43(key[43]),
        .w44(key[44]),
        .w45(key[45]),
        .w46(key[46]),
        .w47(key[47]),
        .w48(key[48]),
        .w49(key[49]),
        .w50(key[50]),
        .w51(key[51]),
        .w52(key[52]),
        .w53(key[53]),
        .w54(key[54]),
        .w55(key[55]),
        .w56(key[56]),
        .w57(key[57]),
        .w58(key[58]),
        .w59(key[59]),
        .w60(key[60]),
        .w61(key[61]),
        .w62(key[62]),
        .w63(key[63]),
        .w64(key[64]),
        .w65(key[65]),
        .w66(key[66]),
        .w67(key[67]),
        .w68(key[68]),
        .w69(key[69]),
        .w70(key[70]),
        .w71(key[71]),
        .w72(key[72]),
        .w73(key[73]),
        .w74(key[74]),
        .w75(key[75]),
        .w76(key[76]),
        .w77(key[77]),
        .w78(key[78]),
        .w79(key[79]),
        .w80(key[80]),
        .w81(key[81]),
        .w82(key[82]),
        .w83(key[83]),
        .w84(key[84]),
        .w85(key[85]),
        .w86(key[86]),
        .w87(key[87]),
        .w88(key[88]),
        .w89(key[89]),
        .w90(key[90]),
        .w91(key[91]),
        .w92(key[92]),
        .w93(key[93]),
        .w94(key[94]),
        .w95(key[95]),
        .w96(key[96]),
        .w97(key[97]),
        .w98(key[98]),
        .w99(key[99]),
        .w100(key[100]),
        .w101(key[101]),
        .w102(key[102]),
        .w103(key[103]),
        .w104(key[104]),
        .w105(key[105]),
        .w106(key[106]),
        .w107(key[107]),
        .w108(key[108]),
        .w109(key[109]),
        .w110(key[110]),
        .w111(key[111]),
        .w112(key[112]),
        .w113(key[113]),
        .w114(key[114]),
        .w115(key[115]),
        .w116(key[116]),
        .w117(key[117]),
        .w118(key[118]),
        .w119(key[119]),
        .w120(key[120]),
        .w121(key[121]),
        .w122(key[122]),
        .w123(key[123]),
        .w124(key[124]),
        .w125(key[125]),
        .w126(key[126]),
        .w127(key[127]),
        .w128(key[128]),
        .w129(key[129]),
        .w130(key[130]),
        .w131(key[131]),
        .w132(key[132]),
        .w133(key[133]),
        .w134(key[134]),
        .w135(key[135]),
        .w136(key[136]),
        .w137(key[137]),
        .w138(key[138]),
        .w139(key[139]),
        .w140(key[140]),
        .w141(key[141]),
        .w142(key[142]),
        .w143(key[143]),
        .w144(key[144]),
        .w145(key[145]),
        .w146(key[146]),
        .w147(key[147]),
        .w148(key[148]),
        .w149(key[149]),
        .w150(key[150]),
        .w151(key[151]),
        .w152(key[152]),
        .w153(key[153]),
        .w154(key[154]),
        .w155(key[155]),
        .w156(key[156]),
        .w157(key[157]),
        .w158(key[158]),
        .w159(key[159]),
        .w160(key[160]),
        .w161(key[161]),
        .w162(key[162]),
        .w163(key[163]),
        .w164(key[164]),
        .w165(key[165]),
        .w166(key[166]),
        .w167(key[167]),
        .w168(key[168]),
        .w169(key[169]),
        .w170(key[170]),
        .w171(key[171]),
        .w172(key[172]),
        .w173(key[173]),
        .w174(key[174]),
        .w175(key[175]),
        .w176(key[176]),
        .w177(key[177]),
        .w178(key[178]),
        .w179(key[179]),
        .w180(key[180]),
        .w181(key[181]),
        .w182(key[182]),
        .w183(key[183]),
        .w184(key[184]),
        .w185(key[185]),
        .w186(key[186]),
        .w187(key[187]),
        .w188(key[188]),
        .w189(key[189]),
        .w190(key[190]),
        .w191(key[191]),
        .w192(key[192]),
        .w193(key[193]),
        .w194(key[194]),
        .w195(key[195]),
        .w196(key[196]),
        .w197(key[197]),
        .w198(key[198]),
        .w199(key[199]),
        .w200(key[200]),
        .w201(key[201]),
        .w202(key[202]),
        .w203(key[203]),
        .w204(key[204]),
        .w205(key[205]),
        .w206(key[206]),
        .w207(key[207]),
        .w208(key[208]),
        .w209(key[209]),
        .w210(key[210]),
        .w211(key[211]),
        .w212(key[212]),
        .w213(key[213]),
        .w214(key[214]),
        .w215(key[215]),
        .w216(key[216]),
        .w217(key[217]),
        .w218(key[218]),
        .w219(key[219]),
        .w220(key[220]),
        .w221(key[221]),
        .w222(key[222]),
        .w223(key[223]),
        .w224(key[224]),
        .w225(key[225]),
        .w226(key[226]),
        .w227(key[227]),
        .w228(key[228]),
        .w229(key[229]),
        .w230(key[230]),
        .w231(key[231]),
        .w232(key[232]),
        .w233(key[233]),
        .w234(key[234]),
        .w235(key[235]),
        .w236(key[236]),
        .w237(key[237]),
        .w238(key[238]),
        .w239(key[239]),
        .w240(key[240]),
        .w241(key[241]),
        .w242(key[242]),
        .w243(key[243]),
        .w244(key[244]),
        .w245(key[245]),
        .w246(key[246]),
        .w247(key[247]),
        .w248(key[248]),
        .w249(key[249]),
        .w250(key[250]),
        .w251(key[251]),
        .w252(key[252]),
        .w253(key[253]),
        .w254(key[254]),
        .w255(key[255]),
        .w256(msg[0]),
        .w257(msg[1]),
        .w258(msg[2]),
        .w259(msg[3]),
        .w260(msg[4]),
        .w261(msg[5]),
        .w262(msg[6]),
        .w263(msg[7]),
        .w264(msg[8]),
        .w265(msg[9]),
        .w266(msg[10]),
        .w267(msg[11]),
        .w268(msg[12]),
        .w269(msg[13]),
        .w270(msg[14]),
        .w271(msg[15]),
        .w272(msg[16]),
        .w273(msg[17]),
        .w274(msg[18]),
        .w275(msg[19]),
        .w276(msg[20]),
        .w277(msg[21]),
        .w278(msg[22]),
        .w279(msg[23]),
        .w280(msg[24]),
        .w281(msg[25]),
        .w282(msg[26]),
        .w283(msg[27]),
        .w284(msg[28]),
        .w285(msg[29]),
        .w286(msg[30]),
        .w287(msg[31]),
        .w288(msg[32]),
        .w289(msg[33]),
        .w290(msg[34]),
        .w291(msg[35]),
        .w292(msg[36]),
        .w293(msg[37]),
        .w294(msg[38]),
        .w295(msg[39]),
        .w296(msg[40]),
        .w297(msg[41]),
        .w298(msg[42]),
        .w299(msg[43]),
        .w300(msg[44]),
        .w301(msg[45]),
        .w302(msg[46]),
        .w303(msg[47]),
        .w304(msg[48]),
        .w305(msg[49]),
        .w306(msg[50]),
        .w307(msg[51]),
        .w308(msg[52]),
        .w309(msg[53]),
        .w310(msg[54]),
        .w311(msg[55]),
        .w312(msg[56]),
        .w313(msg[57]),
        .w314(msg[58]),
        .w315(msg[59]),
        .w316(msg[60]),
        .w317(msg[61]),
        .w318(msg[62]),
        .w319(msg[63]),
        .w320(msg[64]),
        .w321(msg[65]),
        .w322(msg[66]),
        .w323(msg[67]),
        .w324(msg[68]),
        .w325(msg[69]),
        .w326(msg[70]),
        .w327(msg[71]),
        .w328(msg[72]),
        .w329(msg[73]),
        .w330(msg[74]),
        .w331(msg[75]),
        .w332(msg[76]),
        .w333(msg[77]),
        .w334(msg[78]),
        .w335(msg[79]),
        .w336(msg[80]),
        .w337(msg[81]),
        .w338(msg[82]),
        .w339(msg[83]),
        .w340(msg[84]),
        .w341(msg[85]),
        .w342(msg[86]),
        .w343(msg[87]),
        .w344(msg[88]),
        .w345(msg[89]),
        .w346(msg[90]),
        .w347(msg[91]),
        .w348(msg[92]),
        .w349(msg[93]),
        .w350(msg[94]),
        .w351(msg[95]),
        .w352(msg[96]),
        .w353(msg[97]),
        .w354(msg[98]),
        .w355(msg[99]),
        .w356(msg[100]),
        .w357(msg[101]),
        .w358(msg[102]),
        .w359(msg[103]),
        .w360(msg[104]),
        .w361(msg[105]),
        .w362(msg[106]),
        .w363(msg[107]),
        .w364(msg[108]),
        .w365(msg[109]),
        .w366(msg[110]),
        .w367(msg[111]),
        .w368(msg[112]),
        .w369(msg[113]),
        .w370(msg[114]),
        .w371(msg[115]),
        .w372(msg[116]),
        .w373(msg[117]),
        .w374(msg[118]),
        .w375(msg[119]),
        .w376(msg[120]),
        .w377(msg[121]),
        .w378(msg[122]),
        .w379(msg[123]),
        .w380(msg[124]),
        .w381(msg[125]),
        .w382(msg[126]),
        .w383(msg[127]),
        .w50922(out[0]),
        .w50923(out[1]),
        .w50924(out[2]),
        .w50925(out[3]),
        .w50926(out[4]),
        .w50927(out[5]),
        .w50928(out[6]),
        .w50929(out[7]),
        .w50930(out[8]),
        .w50931(out[9]),
        .w50932(out[10]),
        .w50933(out[11]),
        .w50934(out[12]),
        .w50935(out[13]),
        .w50936(out[14]),
        .w50937(out[15]),
        .w50938(out[16]),
        .w50939(out[17]),
        .w50940(out[18]),
        .w50941(out[19]),
        .w50942(out[20]),
        .w50943(out[21]),
        .w50944(out[22]),
        .w50945(out[23]),
        .w50946(out[24]),
        .w50947(out[25]),
        .w50948(out[26]),
        .w50949(out[27]),
        .w50950(out[28]),
        .w50951(out[29]),
        .w50952(out[30]),
        .w50953(out[31]),
        .w50954(out[32]),
        .w50955(out[33]),
        .w50956(out[34]),
        .w50957(out[35]),
        .w50958(out[36]),
        .w50959(out[37]),
        .w50960(out[38]),
        .w50961(out[39]),
        .w50962(out[40]),
        .w50963(out[41]),
        .w50964(out[42]),
        .w50965(out[43]),
        .w50966(out[44]),
        .w50967(out[45]),
        .w50968(out[46]),
        .w50969(out[47]),
        .w50970(out[48]),
        .w50971(out[49]),
        .w50972(out[50]),
        .w50973(out[51]),
        .w50974(out[52]),
        .w50975(out[53]),
        .w50976(out[54]),
        .w50977(out[55]),
        .w50978(out[56]),
        .w50979(out[57]),
        .w50980(out[58]),
        .w50981(out[59]),
        .w50982(out[60]),
        .w50983(out[61]),
        .w50984(out[62]),
        .w50985(out[63]),
        .w50986(out[64]),
        .w50987(out[65]),
        .w50988(out[66]),
        .w50989(out[67]),
        .w50990(out[68]),
        .w50991(out[69]),
        .w50992(out[70]),
        .w50993(out[71]),
        .w50994(out[72]),
        .w50995(out[73]),
        .w50996(out[74]),
        .w50997(out[75]),
        .w50998(out[76]),
        .w50999(out[77]),
        .w51000(out[78]),
        .w51001(out[79]),
        .w51002(out[80]),
        .w51003(out[81]),
        .w51004(out[82]),
        .w51005(out[83]),
        .w51006(out[84]),
        .w51007(out[85]),
        .w51008(out[86]),
        .w51009(out[87]),
        .w51010(out[88]),
        .w51011(out[89]),
        .w51012(out[90]),
        .w51013(out[91]),
        .w51014(out[92]),
        .w51015(out[93]),
        .w51016(out[94]),
        .w51017(out[95]),
        .w51018(out[96]),
        .w51019(out[97]),
        .w51020(out[98]),
        .w51021(out[99]),
        .w51022(out[100]),
        .w51023(out[101]),
        .w51024(out[102]),
        .w51025(out[103]),
        .w51026(out[104]),
        .w51027(out[105]),
        .w51028(out[106]),
        .w51029(out[107]),
        .w51030(out[108]),
        .w51031(out[109]),
        .w51032(out[110]),
        .w51033(out[111]),
        .w51034(out[112]),
        .w51035(out[113]),
        .w51036(out[114]),
        .w51037(out[115]),
        .w51038(out[116]),
        .w51039(out[117]),
        .w51040(out[118]),
        .w51041(out[119]),
        .w51042(out[120]),
        .w51043(out[121]),
        .w51044(out[122]),
        .w51045(out[123]),
        .w51046(out[124]),
        .w51047(out[125]),
        .w51048(out[126]),
        .w51049(out[127]),
);
endmodule