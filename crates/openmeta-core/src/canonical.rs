use serde::Serialize;
use serde_json::Value;

use crate::Error;

pub fn to_canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    let value = serde_json::to_value(value).map_err(|e| Error::NonCanonical(e.to_string()))?;
    let mut out = Vec::new();
    write_value(&value, &mut out)?;
    Ok(out)
}

fn write_value(value: &Value, out: &mut Vec<u8>) -> Result<(), Error> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => {
            if !(n.is_u64() || n.is_i64()) {
                return Err(Error::NonCanonical(format!(
                    "non-integer number {n} is not allowed"
                )));
            }
            out.extend_from_slice(n.to_string().as_bytes());
        }
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_value(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            out.push(b'{');
            for (i, (key, item)) in entries.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_string(key, out);
                out.push(b':');
                write_value(item, out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn write_string(s: &str, out: &mut Vec<u8>) {
    let encoded = serde_json::to_string(s).expect("serializing a str cannot fail");
    out.extend_from_slice(encoded.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn object_keys_are_sorted_and_whitespace_is_removed() {
        let a = json!({"b": 1, "a": {"z": true, "y": [1, 2]}});
        let bytes = to_canonical_json(&a).unwrap();
        assert_eq!(bytes, br#"{"a":{"y":[1,2],"z":true},"b":1}"#);
    }

    #[test]
    fn logically_equal_objects_encode_identically() {
        let a: Value = serde_json::from_str(r#"{ "x": "1", "y": 2 }"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"y":2,"x":"1"}"#).unwrap();
        assert_eq!(
            to_canonical_json(&a).unwrap(),
            to_canonical_json(&b).unwrap()
        );
    }

    #[test]
    fn floats_are_rejected() {
        let err = to_canonical_json(&json!({"v": 1.5})).unwrap_err();
        assert!(matches!(err, Error::NonCanonical(_)));
    }
}
