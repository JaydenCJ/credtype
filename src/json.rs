//! A tiny, dependency-free JSON reader — just enough to inspect a decoded JWT
//! header/payload and pull out a handful of top-level fields (`alg`, `typ`,
//! `iss`, `exp`, …). It is intentionally minimal: credtype never *emits* JSON
//! through this module (see [`crate::report`]), it only reads untrusted input.

/// A parsed JSON value. Numbers are kept as their source text so that large
/// integers (e.g. `exp`) survive without float rounding.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Num(String),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    /// Look up a key on an object, returning `None` for non-objects.
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(pairs) => pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// Borrow the string payload, if this is a string.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    /// True for JSON objects (used to validate a JWT segment shape).
    pub fn is_object(&self) -> bool {
        matches!(self, Json::Obj(_))
    }
}

/// Parse a complete JSON document. Returns `None` on any syntax error or on
/// trailing garbage after the top-level value.
pub fn parse(input: &[u8]) -> Option<Json> {
    let mut p = Parser {
        data: input,
        pos: 0,
    };
    p.skip_ws();
    let v = p.value()?;
    p.skip_ws();
    if p.pos == p.data.len() {
        Some(v)
    } else {
        None
    }
}

struct Parser<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos += 1;
        Some(b)
    }

    fn skip_ws(&mut self) {
        while let Some(b) = self.peek() {
            if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn expect(&mut self, b: u8) -> Option<()> {
        if self.peek() == Some(b) {
            self.pos += 1;
            Some(())
        } else {
            None
        }
    }

    fn value(&mut self) -> Option<Json> {
        self.skip_ws();
        match self.peek()? {
            b'{' => self.object(),
            b'[' => self.array(),
            b'"' => Some(Json::Str(self.string()?)),
            b't' | b'f' => self.boolean(),
            b'n' => self.null(),
            b'-' | b'0'..=b'9' => self.number(),
            _ => None,
        }
    }

    fn object(&mut self) -> Option<Json> {
        self.expect(b'{')?;
        let mut pairs = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Some(Json::Obj(pairs));
        }
        loop {
            self.skip_ws();
            let key = self.string()?;
            self.skip_ws();
            self.expect(b':')?;
            let val = self.value()?;
            pairs.push((key, val));
            self.skip_ws();
            match self.bump()? {
                b',' => continue,
                b'}' => break,
                _ => return None,
            }
        }
        Some(Json::Obj(pairs))
    }

    fn array(&mut self) -> Option<Json> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Some(Json::Arr(items));
        }
        loop {
            let val = self.value()?;
            items.push(val);
            self.skip_ws();
            match self.bump()? {
                b',' => continue,
                b']' => break,
                _ => return None,
            }
        }
        Some(Json::Arr(items))
    }

    fn string(&mut self) -> Option<String> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            match self.bump()? {
                b'"' => break,
                b'\\' => {
                    let esc = self.bump()?;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'n' => out.push('\n'),
                        b't' => out.push('\t'),
                        b'r' => out.push('\r'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000C}'),
                        b'u' => {
                            let cp = self.hex4()?;
                            // Basic BMP handling; surrogate pairs are rare in
                            // JWT headers and fall back to the replacement char.
                            out.push(char::from_u32(cp).unwrap_or('\u{FFFD}'));
                        }
                        _ => return None,
                    }
                }
                b => {
                    // Accept raw UTF-8 continuation bytes verbatim.
                    out.push(b as char);
                }
            }
        }
        Some(out)
    }

    fn hex4(&mut self) -> Option<u32> {
        let mut v = 0u32;
        for _ in 0..4 {
            let b = self.bump()?;
            let d = (b as char).to_digit(16)?;
            v = v * 16 + d;
        }
        Some(v)
    }

    fn boolean(&mut self) -> Option<Json> {
        if self.data[self.pos..].starts_with(b"true") {
            self.pos += 4;
            Some(Json::Bool(true))
        } else if self.data[self.pos..].starts_with(b"false") {
            self.pos += 5;
            Some(Json::Bool(false))
        } else {
            None
        }
    }

    fn null(&mut self) -> Option<Json> {
        if self.data[self.pos..].starts_with(b"null") {
            self.pos += 4;
            Some(Json::Null)
        } else {
            None
        }
    }

    fn number(&mut self) -> Option<Json> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        while let Some(b) = self.peek() {
            if b.is_ascii_digit() || b == b'.' || b == b'e' || b == b'E' || b == b'+' || b == b'-' {
                self.pos += 1;
            } else {
                break;
            }
        }
        if self.pos == start {
            return None;
        }
        let text = std::str::from_utf8(&self.data[start..self.pos]).ok()?;
        Some(Json::Num(text.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_flat_object() {
        let j = parse(br#"{"alg":"HS256","typ":"JWT"}"#).unwrap();
        assert_eq!(j.get("alg").and_then(Json::as_str), Some("HS256"));
        assert_eq!(j.get("typ").and_then(Json::as_str), Some("JWT"));
        assert!(j.is_object());
    }

    #[test]
    fn parses_numbers_as_text() {
        let j = parse(br#"{"exp":1700000000}"#).unwrap();
        assert_eq!(j.get("exp"), Some(&Json::Num("1700000000".to_string())));
    }

    #[test]
    fn parses_nested_and_arrays() {
        let j = parse(br#"{"a":[1,2,{"b":true}],"c":null}"#).unwrap();
        assert!(matches!(j.get("a"), Some(Json::Arr(_))));
        assert_eq!(j.get("c"), Some(&Json::Null));
    }

    #[test]
    fn handles_escapes() {
        let j = parse(br#"{"k":"a\"b\n"}"#).unwrap();
        assert_eq!(j.get("k").and_then(Json::as_str), Some("a\"b\n"));
    }

    #[test]
    fn rejects_trailing_garbage_and_unterminated() {
        assert!(parse(br#"{}x"#).is_none());
        assert!(parse(br#"{"a":"#).is_none());
    }

    #[test]
    fn empty_object_and_array() {
        assert!(parse(b"{}").unwrap().is_object());
        assert!(matches!(parse(b"[]"), Some(Json::Arr(v)) if v.is_empty()));
    }
}
