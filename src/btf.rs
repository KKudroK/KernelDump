//! Read the running kernel's BTF layout. No version-specific member offsets.
use crate::Result;
use std::collections::HashMap;

pub fn read_running() -> Result<Vec<u8>> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open("/sys/kernel/btf/vmlinux")?
        .take(64 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 64 * 1024 * 1024 {
        return Err("BTF exceeds 64MiB limit".into());
    }
    Ok(bytes)
}

#[derive(Clone, Copy)]
struct Type {
    name: u32,
    info: u32,
    size: u32,
    data: usize,
}
impl Type {
    fn kind(self) -> u32 {
        (self.info >> 24) & 31
    }
    fn count(self) -> usize {
        (self.info & 65535) as usize
    }
}
#[derive(Clone, Copy, Debug)]
pub struct Field {
    pub offset: u64,
    pub size: usize,
    pub type_id: u32,
    pub bit: u8,
    pub bits: u8,
}
impl Field {
    pub fn value(self, bytes: &[u8]) -> Result<u64> {
        if bytes.len() != self.size || self.size == 0 || self.size > 8 {
            return Err("non-scalar BTF field".into());
        }
        let mut b = [0u8; 8];
        b[..bytes.len()].copy_from_slice(bytes);
        let v = u64::from_le_bytes(b);
        Ok(if self.bits == 0 {
            v
        } else {
            (v >> self.bit) & (u64::MAX >> (64 - self.bits))
        })
    }
}
pub struct Btf {
    bytes: Vec<u8>,
    types: Vec<Type>,
    strings: usize,
    strings_end: usize,
    names: HashMap<String, u32>,
}
fn u32_at(b: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        b.get(at..at.checked_add(4).ok_or("BTF overflow")?)
            .ok_or("truncated BTF")?
            .try_into()?,
    ))
}
impl Btf {
    pub fn parse(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() > 64 * 1024 * 1024 || bytes.get(..4) != Some(&[0x9f, 0xeb, 1, 0]) {
            return Err("unsupported BTF header".into());
        }
        let h = u32_at(&bytes, 4)? as usize;
        if h < 24 {
            return Err("invalid BTF header size".into());
        }
        let mut at = h
            .checked_add(u32_at(&bytes, 8)? as usize)
            .ok_or("BTF overflow")?;
        let end = at
            .checked_add(u32_at(&bytes, 12)? as usize)
            .ok_or("BTF overflow")?;
        let strings = h
            .checked_add(u32_at(&bytes, 16)? as usize)
            .ok_or("BTF overflow")?;
        let strings_end = strings
            .checked_add(u32_at(&bytes, 20)? as usize)
            .ok_or("BTF overflow")?;
        if end > bytes.len() || strings_end > bytes.len() || end > strings {
            return Err("BTF bounds".into());
        }
        let mut types = vec![Type {
            name: 0,
            info: 0,
            size: 0,
            data: 0,
        }];
        while at < end {
            if types.len() > 1_000_000 || at + 12 > end {
                return Err("BTF record bound".into());
            }
            let t = Type {
                name: u32_at(&bytes, at)?,
                info: u32_at(&bytes, at + 4)?,
                size: u32_at(&bytes, at + 8)?,
                data: at + 12,
            };
            let count = t.count();
            let extra = match t.kind() {
                1 | 14 | 17 => 4,
                2 | 7 | 8 | 9 | 10 | 11 | 12 | 16 | 18 => 0,
                3 => 12,
                4 | 5 | 15 | 19 => count * 12,
                6 | 13 => count * 8,
                _ => return Err("unsupported BTF kind".into()),
            };
            at = t.data + extra;
            if at > end {
                return Err("truncated BTF type".into());
            }
            types.push(t);
        }
        let mut result = Self {
            bytes,
            types,
            strings,
            strings_end,
            names: HashMap::new(),
        };
        for id in 1..result.types.len() {
            let t = result.types[id];
            if t.name != 0 && matches!(t.kind(), 4 | 5 | 8) {
                let name = result.name(t.name)?.to_string();
                result.names.entry(name).or_insert(id as u32);
            }
        }
        Ok(result)
    }
    fn name(&self, offset: u32) -> Result<&str> {
        let at = self
            .strings
            .checked_add(offset as usize)
            .ok_or("BTF string overflow")?;
        let data = self
            .bytes
            .get(at..self.strings_end)
            .ok_or("BTF string bounds")?;
        let n = data
            .iter()
            .position(|&b| b == 0)
            .ok_or("unterminated BTF string")?;
        Ok(std::str::from_utf8(&data[..n])?)
    }
    fn typ(&self, id: u32) -> Result<Type> {
        self.types
            .get(id as usize)
            .copied()
            .ok_or_else(|| "BTF type id".into())
    }
    pub fn id(&self, name: &str) -> Result<u32> {
        self.names
            .get(name)
            .copied()
            .ok_or_else(|| format!("BTF type unavailable: {name}").into())
    }
    pub fn resolve(&self, mut id: u32) -> Result<u32> {
        for _ in 0..32 {
            let t = self.typ(id)?;
            if !matches!(t.kind(), 8 | 9 | 10 | 11 | 18) {
                return Ok(id);
            }
            id = t.size;
        }
        Err("BTF alias cycle".into())
    }
    pub fn size_id(&self, id: u32) -> Result<usize> {
        self.size_inner(id, 0)
    }
    fn size_inner(&self, id: u32, depth: usize) -> Result<usize> {
        if depth > 32 {
            return Err("BTF size depth".into());
        }
        let t = self.typ(self.resolve(id)?)?;
        match t.kind() {
            2 => Ok(8),
            1 | 4 | 5 | 6 | 16 | 19 => Ok(t.size as usize),
            3 => self
                .size_inner(u32_at(&self.bytes, t.data)?, depth + 1)?
                .checked_mul(u32_at(&self.bytes, t.data + 8)? as usize)
                .ok_or_else(|| "BTF array overflow".into()),
            _ => Err("BTF size unavailable".into()),
        }
    }
    pub fn size(&self, name: &str) -> Result<usize> {
        self.size_id(self.id(name)?)
    }
    pub fn array(&self, id: u32) -> Result<(u32, usize)> {
        let t = self.typ(self.resolve(id)?)?;
        if t.kind() != 3 {
            return Err("BTF field is not array".into());
        }
        Ok((
            u32_at(&self.bytes, t.data)?,
            u32_at(&self.bytes, t.data + 8)? as usize,
        ))
    }
    fn member(&self, id: u32, name: &str, depth: usize) -> Result<Field> {
        if depth > 32 {
            return Err("BTF member depth".into());
        }
        let t = self.typ(self.resolve(id)?)?;
        if !matches!(t.kind(), 4 | 5) {
            return Err("BTF member parent is not aggregate".into());
        }
        let mut anonymous = Vec::new();
        for i in 0..t.count() {
            let at = t.data + i * 12;
            let n = u32_at(&self.bytes, at)?;
            let ty = u32_at(&self.bytes, at + 4)?;
            let mut bits = u32_at(&self.bytes, at + 8)?;
            let width = if t.info >> 31 != 0 {
                let w = (bits >> 24) as u8;
                bits &= 0xffffff;
                w
            } else {
                0
            };
            if n != 0 && self.name(n)? == name {
                let size = if width != 0 {
                    (bits as usize % 8 + width as usize).div_ceil(8)
                } else {
                    self.size_id(ty)?
                };
                if width > 64 || (bits % 8 + width as u32) > 64 {
                    return Err("BTF bitfield unsupported".into());
                }
                return Ok(Field {
                    offset: (bits / 8) as u64,
                    size,
                    type_id: ty,
                    bit: (bits % 8) as u8,
                    bits: width,
                });
            }
            if n == 0 {
                anonymous.push((ty, bits / 8));
            }
        }
        let mut found = None;
        for (ty, offset) in anonymous {
            if let Ok(mut field) = self.member(ty, name, depth + 1) {
                field.offset += offset as u64;
                if found.is_some() {
                    return Err("ambiguous anonymous BTF field".into());
                }
                found = Some(field);
            }
        }
        found.ok_or_else(|| format!("BTF member unavailable: {name}").into())
    }
    pub fn field_id(&self, mut id: u32, path: &str) -> Result<Field> {
        let mut total = 0;
        let mut result = None;
        for part in path.split('.') {
            let mut f = self.member(id, part, 0)?;
            total += f.offset;
            id = f.type_id;
            f.offset = total;
            result = Some(f);
        }
        result.ok_or_else(|| "empty BTF field path".into())
    }
    pub fn field(&self, typ: &str, path: &str) -> Result<Field> {
        self.field_id(self.id(typ)?, path)
    }
    pub fn enum_value(&self, name: &str, item: &str) -> Result<u32> {
        for t in &self.types {
            if t.kind() != 6 || self.name(t.name)? != name {
                continue;
            }
            for i in 0..t.count() {
                let at = t.data + i * 8;
                if self.name(u32_at(&self.bytes, at)?)? == item {
                    return u32_at(&self.bytes, at + 4);
                }
            }
        }
        Err(format!("BTF enum unavailable: {name}.{item}").into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn resolves_nested_anonymous_aliases_and_arrays() {
        let strings = b"\0u32\0inside\0named\0outer\0alias\0items\0";
        let mut records = Vec::new();
        let mut record = |words: &[u32]| {
            for v in words {
                records.extend(v.to_le_bytes());
            }
        };
        record(&[1, 1 << 24, 4, 32]); // 1: u32
        record(&[0, (4 << 24) | 1, 4, 5, 1, 0]); // 2: anonymous struct { inside }
        record(&[24, 8 << 24, 2]); // 3: typedef alias
        record(&[0, 3 << 24, 0, 1, 1, 3]); // 4: u32[3]
        record(&[18, (4 << 24) | 3, 24, 0, 3, 32, 12, 2, 64, 30, 4, 96]);
        let mut bytes = vec![0x9f, 0xeb, 1, 0];
        for v in [
            24,
            0,
            records.len() as u32,
            records.len() as u32,
            strings.len() as u32,
        ] {
            bytes.extend(v.to_le_bytes());
        }
        bytes.extend(records);
        bytes.extend(strings);
        let btf = Btf::parse(bytes).unwrap();
        assert_eq!(btf.field("outer", "inside").unwrap().offset, 4);
        assert_eq!(btf.field("outer", "named.inside").unwrap().offset, 8);
        let items = btf.field("outer", "items").unwrap();
        assert_eq!((items.offset, items.size), (12, 12));
        assert_eq!(btf.array(items.type_id).unwrap(), (1, 3));
        assert!(btf.field("outer", "missing").is_err());
    }
    #[test]
    fn rejects_truncated_and_overflowing_layouts() {
        assert!(Btf::parse(vec![]).is_err());
        let mut b = vec![0; 24];
        b[..4].copy_from_slice(&[0x9f, 0xeb, 1, 0]);
        b[4..8].copy_from_slice(&24u32.to_le_bytes());
        b[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(Btf::parse(b).is_err());
    }
    #[test]
    fn bitfields_preserve_underlying_value_and_shift() {
        let f = Field {
            offset: 1,
            size: 2,
            type_id: 1,
            bit: 3,
            bits: 9,
        };
        assert_eq!(f.value(&[0xf8, 0x0f]).unwrap(), 511);
        assert!(f.value(&[0]).is_err());
    }
}
