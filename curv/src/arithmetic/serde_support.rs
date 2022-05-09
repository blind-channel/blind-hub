use std::fmt;
use std::ops::Neg;

use num_traits::Zero;
use serde::de::{Error, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::traits::Converter;
use super::BigInt;

impl Serialize for BigInt {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let is_negative = self < &BigInt::zero();
        let mut bytes = self.to_bytes();
        bytes.push(match is_negative {
            true  => 1u8,
            false => 0u8
        });
        if !serializer.is_human_readable() {
            serializer.serialize_bytes(&bytes)
        } else {
            serializer.serialize_str(&hex::encode(bytes))
        }
    }
}

impl<'de> Deserialize<'de> for BigInt {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BigintVisitor;

        impl<'de> Visitor<'de> for BigintVisitor {
            type Value = BigInt;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "bigint")
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if bytes[bytes.len() - 1] == 1u8 {
                    Ok(BigInt::from_bytes(&bytes[..bytes.len() - 1]).neg())
                } else {
                    Ok(BigInt::from_bytes(&bytes[..bytes.len() - 1]))
                }
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut bytes = vec![];
                while let Some(byte) = seq.next_element::<u8>()? {
                    bytes.push(byte)
                }
                if bytes[bytes.len() - 1] == 1u8 {
                    Ok(BigInt::from_bytes(&bytes[..bytes.len() - 1]).neg())
                } else {
                    Ok(BigInt::from_bytes(&bytes[..bytes.len() - 1]))
                }
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                let bytes = hex::decode(v).map_err(|_| E::custom("malformed hex encoding"))?;
                if bytes[bytes.len() - 1] == 1u8 {
                    Ok(BigInt::from_bytes(&bytes[..bytes.len() - 1]).neg())
                } else {
                    Ok(BigInt::from_bytes(&bytes[..bytes.len() - 1]))
                }
            }
        }

        if !deserializer.is_human_readable() {
            deserializer.deserialize_bytes(BigintVisitor)
        } else {
            deserializer.deserialize_str(BigintVisitor)
        }
    }
}
