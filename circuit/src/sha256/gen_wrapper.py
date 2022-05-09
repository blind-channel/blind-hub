if __name__ == '__main__':
    with open('sha256.v', 'w', encoding='utf-8') as fout:
        fout.write('module sha256(\n')
        fout.write('    input wire [511:0] data,\n')
        fout.write('    input wire [255:0] state,\n')
        fout.write('    output wire [255:0] next_state,\n')
        fout.write(');\n')

        fout.write('    raw_sha256 sha(\n')
        for i in range(512):
            fout.write('        .w{}(data[{}]),\n'.format(i, i))
        for i in range(256):
            fout.write('        .w{}(state[{}]),\n'.format(i+512, i))
        for i in range(256):
            fout.write('        .w{}(next_state[{}]),\n'.format(i+135585, i))
        fout.write(');\n')

        fout.write('endmodule')