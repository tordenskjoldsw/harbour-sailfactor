//! The part of protobuf's wire format the migration payload needs:
//! varints and length-delimited fields, every length checked against the
//! bytes left. Fixed-width fields are skipped, as protobuf requires for
//! fields a reader does not know; the deprecated group wire types are
//! refused.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Malformed;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Value<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
    /// A 32- or 64-bit field, read past.
    Fixed,
}

pub(super) struct Reader<'a> {
    bytes: &'a [u8],
}

// A varint carries at most 64 bits in ten bytes of seven.
const MAX_VARINT_BYTES: usize = 10;

impl<'a> Reader<'a> {
    pub(super) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// The next field number and its value; `None` once all bytes are read.
    pub(super) fn next_field(&mut self) -> Result<Option<(u64, Value<'a>)>, Malformed> {
        if self.bytes.is_empty() {
            return Ok(None);
        }
        let key = self.varint()?;
        let field = key >> 3;
        if field == 0 {
            return Err(Malformed);
        }
        let value = match key & 7 {
            0 => Value::Varint(self.varint()?),
            1 => {
                self.take(8)?;
                Value::Fixed
            }
            2 => {
                let length = usize::try_from(self.varint()?).map_err(|_| Malformed)?;
                Value::Bytes(self.take(length)?)
            }
            5 => {
                self.take(4)?;
                Value::Fixed
            }
            _ => return Err(Malformed),
        };
        Ok(Some((field, value)))
    }

    fn varint(&mut self) -> Result<u64, Malformed> {
        let mut value = 0u64;
        for (index, &byte) in self.bytes.iter().take(MAX_VARINT_BYTES).enumerate() {
            let bits = u64::from(byte & 0x7f);
            // The tenth byte holds only the 64th bit.
            if index == MAX_VARINT_BYTES - 1 && bits > 1 {
                return Err(Malformed);
            }
            value |= bits << (7 * index);
            if byte & 0x80 == 0 {
                self.bytes = &self.bytes[index + 1..];
                return Ok(value);
            }
        }
        Err(Malformed)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], Malformed> {
        if length > self.bytes.len() {
            return Err(Malformed);
        }
        let (taken, rest) = self.bytes.split_at(length);
        self.bytes = rest;
        Ok(taken)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(bytes: &[u8]) -> Result<Vec<(u64, Value<'_>)>, Malformed> {
        let mut reader = Reader::new(bytes);
        let mut fields = Vec::new();
        while let Some(field) = reader.next_field()? {
            fields.push(field);
        }
        Ok(fields)
    }

    #[test]
    fn reads_varints_and_length_delimited_fields() {
        // Field 1: 150 (the protobuf documentation's example); field 2:
        // "testing"; field 3: the largest 64-bit value.
        let bytes = [
            &[0x08, 0x96, 0x01][..],
            &[0x12, 0x07],
            b"testing",
            &[
                0x18, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01,
            ],
        ]
        .concat();

        assert_eq!(
            fields(&bytes).unwrap(),
            [
                (1, Value::Varint(150)),
                (2, Value::Bytes(b"testing")),
                (3, Value::Varint(u64::MAX)),
            ]
        );
    }

    #[test]
    fn skips_fixed_width_fields() {
        let bytes = [
            0x09, 1, 2, 3, 4, 5, 6, 7, 8, // field 1, 64 bits
            0x15, 1, 2, 3, 4, // field 2, 32 bits
            0x18, 0x05, // field 3: 5
        ];

        assert_eq!(
            fields(&bytes).unwrap(),
            [(1, Value::Fixed), (2, Value::Fixed), (3, Value::Varint(5))]
        );
    }

    #[test]
    fn an_empty_message_has_no_fields() {
        assert!(fields(&[]).unwrap().is_empty());
    }

    #[test]
    fn refuses_truncated_and_invalid_input() {
        for bytes in [
            &[0x08][..],                           // value missing
            &[0x08, 0x80],                         // varint unfinished
            &[0x12, 0x05, b'a'],                   // length beyond the end
            &[0x12, 0xff, 0xff, 0xff, 0xff, 0x0f], // huge length
            &[0x09, 1, 2, 3],                      // fixed64 cut short
            &[0x00, 0x01],                         // field number 0
            &[0x0b],                               // group start
            &[0x0c],                               // group end
            &[0x0e],                               // wire type 6
            &[
                0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02,
            ], // 65 bits
            &[
                0x08, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00,
            ], // 11 bytes
        ] {
            assert_eq!(fields(bytes), Err(Malformed), "{bytes:02x?}");
        }
    }
}
