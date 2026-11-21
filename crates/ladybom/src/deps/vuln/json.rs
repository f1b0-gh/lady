//! Strict parsing for untrusted vulnerability documents, including OSV extensions.
use super::{MAX_INPUT_BYTES, MAX_RECORDS};
use crate::error::{Error, Result};
use serde::de::{DeserializeSeed, Deserializer, Error as DeError, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

struct UniqueKeys;
impl<'de> DeserializeSeed<'de> for UniqueKeys {
    type Value = Value;
    fn deserialize<D: Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> std::result::Result<Value, D::Error> {
        deserializer.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for UniqueKeys {
    type Value = Value;
    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("bounded JSON without duplicate keys")
    }
    fn visit_bool<E: DeError>(self, value: bool) -> std::result::Result<Value, E> {
        Ok(Value::Bool(value))
    }
    fn visit_i64<E: DeError>(self, value: i64) -> std::result::Result<Value, E> {
        Ok(Value::Number(value.into()))
    }
    fn visit_u64<E: DeError>(self, value: u64) -> std::result::Result<Value, E> {
        Ok(Value::Number(value.into()))
    }
    fn visit_f64<E: DeError>(self, value: f64) -> std::result::Result<Value, E> {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }
    fn visit_str<E: DeError>(self, value: &str) -> std::result::Result<Value, E> {
        Ok(Value::String(value.into()))
    }
    fn visit_string<E: DeError>(self, value: String) -> std::result::Result<Value, E> {
        Ok(Value::String(value))
    }
    fn visit_unit<E: DeError>(self) -> std::result::Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> std::result::Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(UniqueKeys)? {
            if values.len() >= MAX_RECORDS {
                return Err(A::Error::custom("JSON array item limit exceeded"));
            }
            values.push(value);
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<Value, A::Error> {
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.len() >= MAX_RECORDS {
                return Err(A::Error::custom("JSON object field limit exceeded"));
            }
            if values.contains_key(&key) {
                return Err(A::Error::custom("duplicate JSON key"));
            }
            values.insert(key, map.next_value_seed(UniqueKeys)?);
        }
        Ok(Value::Object(values))
    }
}

/// Reject duplicate keys at every nesting level before typed deserialization.
/// The 64 MiB and 100,000-item limits preserve the snapshot import contract;
/// serde_json's default recursion limit remains enabled. OSV validation applies
/// its own tighter bounds to individual advisory extension data afterwards.
pub fn parse_json(bytes: &[u8]) -> Result<Value> {
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(Error::InvalidInput {
            message: "Vulnerability JSON document exceeds 64 MiB".into(),
        });
    }
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let value = UniqueKeys.deserialize(&mut decoder)?;
    decoder.end()?;
    Ok(value)
}
