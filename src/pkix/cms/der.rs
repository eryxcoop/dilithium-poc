//! Small DER helpers for the minimal CMS profile.

use der::asn1::ObjectIdentifier;
use der::{Decode, Encode};

use crate::error::{DilithiumError, DilithiumResult};

pub(crate) struct DerValue {
    bytes: Vec<u8>,
}

impl DerValue {
    pub(crate) fn sequence(elements: &[Vec<u8>]) -> Self {
        Self::constructed(0x30, concat(elements))
    }

    pub(crate) fn set_from_sorted(elements: &[Vec<u8>]) -> Self {
        Self::constructed(0x31, concat(elements))
    }

    pub(crate) fn set_from_value(value: &[u8]) -> Self {
        Self::constructed(0x31, value.to_vec())
    }

    pub(crate) fn oid(oid: ObjectIdentifier) -> DilithiumResult<Self> {
        Ok(Self {
            bytes: oid
                .to_der()
                .map_err(|_| DilithiumError::MalformedPkix("failed to encode object identifier"))?,
        })
    }

    pub(crate) fn integer(value: u8) -> Self {
        Self::constructed(0x02, vec![value])
    }

    pub(crate) fn octet_string(value: &[u8]) -> Self {
        Self::constructed(0x04, value.to_vec())
    }

    pub(crate) fn context_constructed(tag_number: u8, value: Vec<u8>) -> Self {
        Self::constructed(0xa0 + tag_number, value)
    }

    pub(crate) fn context_primitive(tag_number: u8, value: &[u8]) -> Self {
        Self::constructed(0x80 + tag_number, value.to_vec())
    }

    pub(crate) fn into_vec(self) -> Vec<u8> {
        self.bytes
    }

    fn constructed(tag: u8, value: Vec<u8>) -> Self {
        let mut bytes = vec![tag];
        bytes.extend_from_slice(&DerLength::new(value.len()).to_der());
        bytes.extend_from_slice(&value);
        Self { bytes }
    }
}

pub(crate) struct DerSet {
    elements: Vec<Vec<u8>>,
}

impl DerSet {
    pub(crate) fn from_unsorted(elements: &[Vec<u8>]) -> Self {
        let mut sorted = elements.to_vec();
        sorted.sort();
        Self { elements: sorted }
    }

    pub(crate) fn from_sorted(elements: &[Vec<u8>]) -> Self {
        Self {
            elements: elements.to_vec(),
        }
    }

    pub(crate) fn to_der(&self) -> Vec<u8> {
        DerValue::set_from_sorted(&self.elements).into_vec()
    }

    pub(crate) fn single_member(value: &[u8]) -> DilithiumResult<DerElement<'_>> {
        let mut reader = DerReader::new(value);
        let member = reader.next_element()?;
        reader.finish()?;
        Ok(member)
    }

    pub(crate) fn ensure_sorted_value(value: &[u8]) -> DilithiumResult<()> {
        let mut reader = DerReader::new(value);
        let mut previous: Option<&[u8]> = None;
        while !reader.is_empty() {
            let element = reader.next_element()?;
            if let Some(previous) = previous
                && previous > element.der
            {
                return Err(DilithiumError::MalformedPkix(
                    "SET OF elements are not DER sorted",
                ));
            }
            previous = Some(element.der);
        }
        Ok(())
    }
}

pub(crate) struct DerSequence;

impl DerSequence {
    pub(crate) fn value_from_der(sequence_der: &[u8]) -> DilithiumResult<Vec<u8>> {
        let sequence = DerElement::expect_single(sequence_der)?;
        if sequence.tag != 0x30 {
            return Err(DilithiumError::MalformedPkix("expected DER SEQUENCE"));
        }
        Ok(sequence.value.to_vec())
    }
}

struct DerLength(usize);

impl DerLength {
    fn new(len: usize) -> Self {
        Self(len)
    }

    fn to_der(&self) -> Vec<u8> {
        let len = self.0;
        if len < 128 {
            return vec![len as u8];
        }
        let bytes = len.to_be_bytes();
        let first = bytes
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(bytes.len() - 1);
        let significant = &bytes[first..];
        let mut out = vec![0x80 | significant.len() as u8];
        out.extend_from_slice(significant);
        out
    }
}

#[derive(Clone, Copy)]
pub(crate) struct DerElement<'a> {
    pub(crate) tag: u8,
    pub(crate) value: &'a [u8],
    pub(crate) der: &'a [u8],
}

impl<'a> DerElement<'a> {
    pub(crate) fn expect_single(input: &'a [u8]) -> DilithiumResult<Self> {
        let mut reader = DerReader::new(input);
        let element = reader.next_element()?;
        reader.finish()?;
        Ok(element)
    }
}

pub(crate) struct DerReader<'a> {
    input: &'a [u8],
}

impl<'a> DerReader<'a> {
    pub(crate) fn new(input: &'a [u8]) -> Self {
        Self { input }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.input.is_empty()
    }

    pub(crate) fn next_oid(&mut self) -> DilithiumResult<ObjectIdentifier> {
        let element = self.next_element()?;
        if element.tag != 0x06 {
            return Err(DilithiumError::MalformedPkix("expected OBJECT IDENTIFIER"));
        }
        ObjectIdentifier::from_der(element.der)
            .map_err(|_| DilithiumError::MalformedPkix("malformed object identifier"))
    }

    pub(crate) fn next_octet_string(&mut self) -> DilithiumResult<&'a [u8]> {
        let element = self.next_element()?;
        if element.tag != 0x04 {
            return Err(DilithiumError::MalformedPkix("expected OCTET STRING"));
        }
        Ok(element.value)
    }

    pub(crate) fn next_element(&mut self) -> DilithiumResult<DerElement<'a>> {
        if self.input.len() < 2 {
            return Err(DilithiumError::MalformedPkix("truncated DER element"));
        }
        let original = self.input;
        let tag = original[0];
        let (length, length_len) = der_read_length(&original[1..])?;
        let header_len = 1 + length_len;
        let end = header_len
            .checked_add(length)
            .ok_or(DilithiumError::MalformedPkix("DER element length overflow"))?;
        if original.len() < end {
            return Err(DilithiumError::MalformedPkix("truncated DER value"));
        }
        let der = &original[..end];
        let value = &original[header_len..end];
        self.input = &original[end..];
        Ok(DerElement { tag, value, der })
    }

    pub(crate) fn finish(self) -> DilithiumResult<()> {
        if self.input.is_empty() {
            Ok(())
        } else {
            Err(DilithiumError::MalformedPkix("trailing DER data"))
        }
    }
}

fn concat(elements: &[Vec<u8>]) -> Vec<u8> {
    let total = elements.iter().map(Vec::len).sum();
    let mut out = Vec::with_capacity(total);
    for element in elements {
        out.extend_from_slice(element);
    }
    out
}

fn der_read_length(input: &[u8]) -> DilithiumResult<(usize, usize)> {
    if input.is_empty() {
        return Err(DilithiumError::MalformedPkix("missing DER length"));
    }
    let first = input[0];
    if first & 0x80 == 0 {
        return Ok((first as usize, 1));
    }
    let count = (first & 0x7f) as usize;
    if count == 0 || count > core::mem::size_of::<usize>() || input.len() < 1 + count {
        return Err(DilithiumError::MalformedPkix("invalid DER length"));
    }
    if input[1] == 0 {
        return Err(DilithiumError::MalformedPkix(
            "DER length is not minimally encoded",
        ));
    }
    let mut len = 0usize;
    for byte in &input[1..=count] {
        len = (len << 8) | *byte as usize;
    }
    if len < 128 {
        return Err(DilithiumError::MalformedPkix(
            "DER long-form length used for short value",
        ));
    }
    Ok((len, 1 + count))
}
