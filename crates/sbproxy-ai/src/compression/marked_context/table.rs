//! Reversible compact-table encoding for uniform JSON object rows.

use serde_json::{Map, Value};
use std::fmt;

/// Closed error returned when a body is not canonical SBproxy Table v1.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TableDecodeError(());

impl fmt::Debug for TableDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid_table")
    }
}

impl fmt::Display for TableDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid_table")
    }
}

impl std::error::Error for TableDecodeError {}

/// Encode uniform scalar object rows as canonical SBproxy Table v1.
///
/// Zero-column objects intentionally remain JSON. Their empty row lines are
/// indistinguishable from trailing blank lines, which this format rejects.
pub(crate) fn encode_table(value: &Value, min_rows: usize) -> Option<String> {
    let rows = value.as_array()?;
    if rows.is_empty() || rows.len() < min_rows {
        return None;
    }

    let first = rows.first()?.as_object()?;
    if first.is_empty() {
        return None;
    }
    let mut columns = first.keys().cloned().collect::<Vec<_>>();
    columns.sort_unstable();

    let mut body = serde_json::to_string(&columns).ok()?;
    for row in rows {
        let object = row.as_object()?;
        if object.len() != columns.len()
            || columns.iter().any(|column| !object.contains_key(column))
        {
            return None;
        }

        body.push('\n');
        for (index, column) in columns.iter().enumerate() {
            if index != 0 {
                body.push('\t');
            }
            let cell = object.get(column)?;
            if cell.is_array() || cell.is_object() {
                return None;
            }
            body.push_str(&serde_json::to_string(cell).ok()?);
        }
    }
    Some(body)
}

/// Decode one canonical SBproxy Table v1 body into its exact JSON value.
pub fn decode_sbproxy_table_v1(body: &str) -> Result<Value, TableDecodeError> {
    let invalid = || TableDecodeError(());
    if body.is_empty() || body.ends_with('\n') || body.contains('\r') {
        return Err(invalid());
    }

    let mut lines = body.split('\n');
    let header = lines.next().ok_or_else(invalid)?;
    let columns = serde_json::from_str::<Vec<String>>(header).map_err(|_| invalid())?;
    if columns.is_empty()
        || serde_json::to_string(&columns).map_err(|_| invalid())? != header
        || !columns.windows(2).all(|pair| pair[0] < pair[1])
    {
        return Err(invalid());
    }

    let mut decoded_rows = Vec::new();
    for line in lines {
        let cells = line.split('\t').collect::<Vec<_>>();
        if cells.len() != columns.len() {
            return Err(invalid());
        }

        let mut object = Map::new();
        for (column, cell) in columns.iter().zip(cells) {
            let value = serde_json::from_str::<Value>(cell).map_err(|_| invalid())?;
            if value.is_array()
                || value.is_object()
                || serde_json::to_string(&value).map_err(|_| invalid())? != cell
            {
                return Err(invalid());
            }
            object.insert(column.clone(), value);
        }
        decoded_rows.push(Value::Object(object));
    }
    if decoded_rows.is_empty() {
        return Err(invalid());
    }

    Ok(Value::Array(decoded_rows))
}

#[cfg(test)]
mod tests {
    use super::encode_table;
    use crate::compression::{decode_sbproxy_table_v1, TableDecodeError};
    use serde_json::{json, Map, Value};

    fn rows(count: usize) -> Value {
        Value::Array(
            (0..count)
                .map(|index| json!({"id": index, "ready": index % 2 == 0}))
                .collect(),
        )
    }

    #[test]
    fn encodes_sorted_columns_independent_of_source_object_order() {
        let value: Value = serde_json::from_str(
            r#"[
                {"z": 1, "a": "first"},
                {"a": "second", "z": 2}
            ]"#,
        )
        .expect("valid fixture");

        let body = encode_table(&value, 2).expect("uniform scalar rows encode");

        assert_eq!(body, "[\"a\",\"z\"]\n\"first\"\t1\n\"second\"\t2");
        assert_eq!(decode_sbproxy_table_v1(&body).unwrap(), value);
    }

    #[test]
    fn round_trips_canonical_json_scalars_without_separator_collisions() {
        let value = json!([
            {
                "active": true,
                "count": 7,
                "empty": null,
                "note": "tab\tline\nquote\"slash\\",
                "ratio": -12.5
            },
            {
                "ratio": 0.25,
                "note": "plain",
                "empty": null,
                "count": -3,
                "active": false
            }
        ]);

        let body = encode_table(&value, 2).expect("all JSON scalar kinds are safe");

        assert_eq!(
            body,
            concat!(
                r#"["active","count","empty","note","ratio"]"#,
                "\n",
                "true\t7\tnull\t",
                r#""tab\tline\nquote\"slash\\""#,
                "\t-12.5\n",
                "false\t-3\tnull\t\"plain\"\t0.25"
            )
        );
        assert_eq!(decode_sbproxy_table_v1(&body).unwrap(), value);
    }

    #[test]
    fn supports_empty_column_names_but_rejects_ambiguous_empty_object_rows() {
        let value = json!([{"": 1}, {"": 2}]);
        let body = encode_table(&value, 2).expect("an empty JSON object key is unambiguous");

        assert_eq!(body, "[\"\"]\n1\n2");
        assert_eq!(decode_sbproxy_table_v1(&body).unwrap(), value);
        assert!(encode_table(&json!([{}, {}]), 2).is_none());
        assert!(decode_sbproxy_table_v1("[]\n\n").is_err());
    }

    #[test]
    fn enforces_the_199_and_200_row_threshold_boundary() {
        let below = rows(199);
        let boundary = rows(200);

        assert!(encode_table(&below, 200).is_none());
        let body = encode_table(&boundary, 200).expect("the boundary row count is eligible");
        assert_eq!(body.lines().count(), 201);
        assert_eq!(decode_sbproxy_table_v1(&body).unwrap(), boundary);
    }

    #[test]
    fn encoder_rejects_unsafe_heterogeneous_and_undersized_shapes() {
        let cases = [
            (json!([]), 0, "empty array"),
            (json!({"a": 1}), 1, "non-array root"),
            (json!([{"a": 1}]), 2, "too few rows"),
            (json!([{"a": 1}, 2]), 2, "non-object row"),
            (json!([{"a": 1}, {"a": 2, "b": 3}]), 2, "heterogeneous keys"),
            (json!([{"a": [1]}, {"a": [2]}]), 2, "nested array cells"),
            (
                json!([{"a": {"b": 1}}, {"a": {"b": 2}}]),
                2,
                "nested object cells",
            ),
        ];

        for (value, min_rows, label) in cases {
            assert!(
                encode_table(&value, min_rows).is_none(),
                "{label} must not encode"
            );
        }
    }

    #[test]
    fn decoder_rejects_malformed_noncanonical_duplicate_and_unsorted_headers() {
        let cases = [
            "",
            "not-json\n1",
            "{}\n1",
            "[1]\n1",
            "[]\n",
            "[\"a\",\"a\"]\n1\t2",
            "[\"b\",\"a\"]\n1\t2",
            "[ \"a\" ]\n1",
            "[\"a\"] \n1",
            "[\"a\"]\r\n1",
        ];

        for body in cases {
            assert!(
                decode_sbproxy_table_v1(body).is_err(),
                "header form must be rejected: {body:?}"
            );
        }
    }

    #[test]
    fn decoder_rejects_wrong_width_nested_malformed_and_noncanonical_cells() {
        let cases = [
            "[\"a\",\"b\"]\n1",
            "[\"a\",\"b\"]\n1\t2\t3",
            "[\"a\"]\n",
            "[\"a\"]\nnot-json",
            "[\"a\"]\n[]",
            "[\"a\"]\n{}",
            "[\"a\"]\n 1",
            "[\"a\"]\n1 ",
            "[\"a\"]\n01",
            "[\"a\"]\n\"literal\ttab\"",
            "[\"a\"]\n\"unterminated",
        ];

        for body in cases {
            assert!(
                decode_sbproxy_table_v1(body).is_err(),
                "cell form must be rejected: {body:?}"
            );
        }
    }

    #[test]
    fn decoder_rejects_missing_rows_and_trailing_lines() {
        for body in [
            "[\"a\"]",
            "[\"a\"]\n1\n",
            "[\"a\"]\n1\n\n",
            "[\"a\"]\n1\n\t",
        ] {
            assert!(
                decode_sbproxy_table_v1(body).is_err(),
                "missing or trailing line must be rejected: {body:?}"
            );
        }
    }

    #[test]
    fn decoder_builds_objects_in_header_order_with_exact_scalar_values() {
        let body = concat!(
            "[\"a\",\"b\",\"c\",\"d\"]\n",
            "\"x\"\t9007199254740993\ttrue\tnull\n",
            "\"y\"\t-4.75\tfalse\tnull"
        );
        let expected: Value = serde_json::from_str(
            r#"[
                {"a":"x","b":9007199254740993,"c":true,"d":null},
                {"a":"y","b":-4.75,"c":false,"d":null}
            ]"#,
        )
        .unwrap();

        assert_eq!(decode_sbproxy_table_v1(body).unwrap(), expected);
    }

    #[test]
    fn decode_error_exposes_only_the_closed_invalid_table_label() {
        let error = decode_sbproxy_table_v1("sensitive malformed body").unwrap_err();
        let _: TableDecodeError = error;

        assert_eq!(format!("{error}"), "invalid_table");
        assert_eq!(format!("{error:?}"), "invalid_table");
        assert!(std::error::Error::source(&error).is_none());
    }

    #[test]
    fn object_construction_fixture_can_express_reverse_insertion_order() {
        let mut first = Map::new();
        first.insert("z".to_string(), json!(1));
        first.insert("a".to_string(), json!(2));
        let mut second = Map::new();
        second.insert("a".to_string(), json!(3));
        second.insert("z".to_string(), json!(4));
        let value = Value::Array(vec![Value::Object(first), Value::Object(second)]);

        assert_eq!(
            encode_table(&value, 2).unwrap(),
            "[\"a\",\"z\"]\n2\t1\n3\t4"
        );
    }
}
