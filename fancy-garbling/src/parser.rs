// -*- mode: rust; -*-
//
// This file is part of fancy-garbling.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Functions for parsing and running a circuit file based on the format given
//! here: <https://homes.esat.kuleuven.be/~nsmart/MPC/>.

use crate::{
    circuit::{Circuit, CircuitRef, Gate},
    errors::CircuitParserError as Error,
};
use regex::{Captures, Regex};
use std::{
    fs::File,
    io::{BufRead, BufReader},
    str::FromStr,
};

enum GateType {
    AndGate,
    XorGate,
}

fn cap2int(cap: &Captures, idx: usize) -> Result<usize, Error> {
    let s = cap.get(idx).ok_or(Error::ParseIntError)?;
    FromStr::from_str(s.as_str()).map_err(Error::from)
}

fn cap2typ(cap: &Captures, idx: usize) -> Result<GateType, Error> {
    let s = cap.get(idx).ok_or(Error::ParseIntError)?;
    let s = s.as_str();
    match s {
        "AND" => Ok(GateType::AndGate),
        "XOR" => Ok(GateType::XorGate),
        s => Err(Error::ParseGateError(s.to_string())),
    }
}

fn regex2captures<'t>(re: &Regex, line: &'t str) -> Result<Captures<'t>, Error> {
    re.captures(&line)
        .ok_or_else(|| Error::ParseLineError(line.to_string()))
}

impl Circuit {
    /// Generates a new `Circuit` from file `filename`. The file must follow the
    /// format given here: <https://homes.esat.kuleuven.be/~nsmart/MPC/>,
    /// otherwise a `CircuitParserError` is returned.
    pub fn parse(filename: &str) -> Result<Self, Error> {
        let f = File::open(filename)?;
        let mut reader = BufReader::with_capacity(1_048_576, f);

        // Parse first line: ngates nwires\n
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let re = Regex::new(r"(\d+)\s+(\d+)")?;
        let cap = regex2captures(&re, &line)?;
        let ngates = cap2int(&cap, 1)?;
        let nwires = cap2int(&cap, 2)?;

        // Parse second line: n1 n2 n3\n
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let re = Regex::new(r"(\d+)\s+(\d+)\s+(\d+)")?;
        let cap = regex2captures(&re, &line)?;
        let n1 = cap2int(&cap, 1)?; // Number of garbler inputs
        let n2 = cap2int(&cap, 2)?; // Number of evaluator inputs
        let n3 = cap2int(&cap, 3)?; // Number of outputs

        // Parse third line: \n
        let mut line = String::new();
        reader.read_line(&mut line)?;
        #[allow(clippy::trivial_regex)]
        let re = Regex::new(r"\n")?;
        let _ = regex2captures(&re, &line)?;

        let mut circ = Self::new(Some(ngates));

        let re1 = Regex::new(r"1 1 (\d+) (\d+) INV")?;
        let re2 = Regex::new(r"2 1 (\d+) (\d+) (\d+) ((AND|XOR))")?;

        let mut id = 0;

        // Process garbler inputs.
        for i in 0..n1 {
            circ.gates.push(Gate::GarblerInput { id: i });
            circ.garbler_input_refs
                .push(CircuitRef { ix: i, modulus: 2 });
        }
        // Process evaluator inputs.
        for i in 0..n2 {
            circ.gates.push(Gate::EvaluatorInput { id: i });
            circ.evaluator_input_refs.push(CircuitRef {
                ix: n1 + i,
                modulus: 2,
            });
        }
        // Create a constant wire for negations.
        circ.gates.push(Gate::Constant { val: 1 , out: Some(nwires)});
        let oneref = CircuitRef {
            ix: nwires,
            modulus: 2,
        };
        circ.const_refs.push(oneref);
        // Process outputs.
        for i in 0..n3 {
            circ.output_refs.push(CircuitRef {
                ix: nwires - n3 + i,
                modulus: 2,
            });
        }
        for line in reader.lines() {
            let line = line?;
            match line.chars().next() {
                Some('1') => {
                    let cap = regex2captures(&re1, &line)?;
                    let yref = cap2int(&cap, 1)?;
                    let out = cap2int(&cap, 2)?;
                    let yref = CircuitRef {
                        ix: yref,
                        modulus: 2,
                    };
                    circ.gates.push(Gate::Sub {
                        xref: oneref,
                        yref,
                        out: Some(out),
                    })
                }
                Some('2') => {
                    let cap = regex2captures(&re2, &line)?;
                    let xref = cap2int(&cap, 1)?;
                    let yref = cap2int(&cap, 2)?;
                    let out = cap2int(&cap, 3)?;
                    let typ = cap2typ(&cap, 4)?;
                    let xref = CircuitRef {
                        ix: xref,
                        modulus: 2,
                    };
                    let yref = CircuitRef {
                        ix: yref,
                        modulus: 2,
                    };
                    let gate = match typ {
                        GateType::AndGate => {
                            let gate = Gate::Mul {
                                xref,
                                yref,
                                id,
                                out: Some(out),
                            };
                            id += 1;
                            gate
                        }
                        GateType::XorGate => Gate::Add {
                            xref,
                            yref,
                            out: Some(out),
                        },
                    };
                    circ.gates.push(gate);
                }
                None => break,
                _ => {
                    return Err(Error::ParseLineError(line.to_string()));
                }
            }
        }
        circ.gate_moduli = vec![2u16; circ.gates.len()];
        Ok(circ)
    }
}

pub fn encode_boolean(data: &str, binary_high_address_head: bool) -> Result<Vec<u16>, ()> {
    let mut result = Vec::with_capacity(4 * data.len());
    for v in data.chars().into_iter() {
        result.extend(match v.to_ascii_lowercase() {
            '0' => [0u16, 0u16, 0u16, 0u16],
            '1' => [0u16, 0u16, 0u16, 1u16],
            '2' => [0u16, 0u16, 1u16, 0u16],
            '3' => [0u16, 0u16, 1u16, 1u16],
            '4' => [0u16, 1u16, 0u16, 0u16],
            '5' => [0u16, 1u16, 0u16, 1u16],
            '6' => [0u16, 1u16, 1u16, 0u16],
            '7' => [0u16, 1u16, 1u16, 1u16],
            '8' => [1u16, 0u16, 0u16, 0u16],
            '9' => [1u16, 0u16, 0u16, 1u16],
            'a' => [1u16, 0u16, 1u16, 0u16],
            'b' => [1u16, 0u16, 1u16, 1u16],
            'c' => [1u16, 1u16, 0u16, 0u16],
            'd' => [1u16, 1u16, 0u16, 1u16],
            'e' => [1u16, 1u16, 1u16, 0u16],
            'f' => [1u16, 1u16, 1u16, 1u16],
             _  => { return Err(()) },
         });
    }
    if binary_high_address_head{
        result.reverse();
    }
    Ok(result)
}

pub fn decode_boolean(data: &[u16], binary_high_address_head: bool) -> Result<String, ()> {
    if data.len() % 4 != 0 {
        return Err(());
    }
    let mut data_copy = data.to_owned();
    if binary_high_address_head {
        data_copy.reverse();
    }
    let mut data_iter = data_copy.iter();
    let mut result = String::with_capacity(data.len() / 4);
    loop {
        let v = match &[data_iter.next(), data_iter.next(), data_iter.next(), data_iter.next()] {
            &[Some(0u16), Some(0u16), Some(0u16), Some(0u16)] => '0',
            &[Some(0u16), Some(0u16), Some(0u16), Some(1u16)] => '1',
            &[Some(0u16), Some(0u16), Some(1u16), Some(0u16)] => '2',
            &[Some(0u16), Some(0u16), Some(1u16), Some(1u16)] => '3',
            &[Some(0u16), Some(1u16), Some(0u16), Some(0u16)] => '4',
            &[Some(0u16), Some(1u16), Some(0u16), Some(1u16)] => '5',
            &[Some(0u16), Some(1u16), Some(1u16), Some(0u16)] => '6',
            &[Some(0u16), Some(1u16), Some(1u16), Some(1u16)] => '7',
            &[Some(1u16), Some(0u16), Some(0u16), Some(0u16)] => '8',
            &[Some(1u16), Some(0u16), Some(0u16), Some(1u16)] => '9',
            &[Some(1u16), Some(0u16), Some(1u16), Some(0u16)] => 'a',
            &[Some(1u16), Some(0u16), Some(1u16), Some(1u16)] => 'b',
            &[Some(1u16), Some(1u16), Some(0u16), Some(0u16)] => 'c',
            &[Some(1u16), Some(1u16), Some(0u16), Some(1u16)] => 'd',
            &[Some(1u16), Some(1u16), Some(1u16), Some(0u16)] => 'e',
            &[Some(1u16), Some(1u16), Some(1u16), Some(1u16)] => 'f',
            &[None, None, None, None] => { break; },
             _  => { return Err(()) },
        };
        result.push(v)
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use crate::{circuit::Circuit, classic::garble, encode_boolean, decode_boolean};

    #[test]
    fn test_parser() {
        let circ = Circuit::parse("circuits/AES-non-expanded.txt").unwrap();
        let key = vec![0u16; 128];
        let pt = vec![0u16; 128];
        let output = circ.eval_plain(&pt, &key).unwrap();
        assert_eq!(output.iter().map(|i| i.to_string()).collect::<String>(),
                   "01100110111010010100101111010100111011111000101000101100001110111000100001001100111110100101100111001010001101000010101100101110");
        let key = vec![1u16; 128];
        let pt = vec![0u16; 128];
        let output = circ.eval_plain(&pt, &key).unwrap();
        assert_eq!(output.iter().map(|i| i.to_string()).collect::<String>(),
                   "10100001111101100010010110001100100001110111110101011111110011011000100101100100010010000100010100111000101111111100100100101100");
        let mut key = vec![0u16; 128];
        for i in 0..8 {
            key[i] = 1;
        }
        let pt = vec![0u16; 128];
        let output = circ.eval_plain(&pt, &key).unwrap();
        assert_eq!(output.iter().map(|i| i.to_string()).collect::<String>(),
                   "10110001110101110101100000100101011010110010100011111101100001010000101011010100100101000100001000001000110011110001000101010101");
        let mut key = vec![0u16; 128];
        key[7] = 1;
        let pt = vec![0u16; 128];
        let output = circ.eval_plain(&pt, &key).unwrap();
        assert_eq!(output.iter().map(|i| i.to_string()).collect::<String>(),
                   "11011100000011101101100001011101111110010110000100011010101110110111001001001001110011011101000101101000110001010100011001111110");
    }

    #[test]
    fn test_gc_eval1() {
        let msg = "00112233445566778899aabbccddeeff";
        let key = "000102030405060708090a0b0c0d0e0f";
        let out = "69c4e0d86a7b0430d8cdb78070b4c55a";

        let mut circ = Circuit::parse("circuits/AES-non-expanded.txt").unwrap();
        let (en, gc) = garble(&mut circ).unwrap();
        let gb = en.encode_garbler_inputs(&encode_boolean(&msg, false).unwrap());
        let ev = en.encode_evaluator_inputs(&encode_boolean(&key, false).unwrap());
        let result = gc.eval(&mut circ, &gb, &ev).unwrap();
        assert_eq!(decode_boolean(&result, false).unwrap(), out);
    }

    #[test]
    fn test_gc_eval2() {
        let msg = "f0112233445566778899aabbccddeeff";
        let key = "f00102030405060708090a0b0c0d0e0f";
        let out = "1c5b2185cf4ed58692068d7ff1ef20a0";

        let mut circ = Circuit::parse("circuits/AES-non-expanded.txt").unwrap();
        let (en, gc) = garble(&mut circ).unwrap();
        let gb = en.encode_garbler_inputs(&encode_boolean(&msg, false).unwrap());
        let ev = en.encode_evaluator_inputs(&encode_boolean(&key, false).unwrap());
        let result = gc.eval(&mut circ, &gb, &ev).unwrap();
        assert_eq!(decode_boolean(&result, false).unwrap(), out);
    }
}
