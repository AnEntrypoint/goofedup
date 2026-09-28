use serde_json::Value;

pub fn parse(text: &str) -> Option<Value> {
    let without_comments = strip_comments(text.trim_start_matches('\u{feff}'))?;
    let without_trailing_commas = strip_trailing_commas(&without_comments)?;
    serde_json::from_str(&without_trailing_commas).ok()
}

fn strip_comments(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    let mut in_string = false;
    while i < bytes.len() {
        let b = bytes[i];
        if in_string {
            out.push(b);
            if b == b'\\' && i + 1 < bytes.len() {
                out.push(bytes[i + 1]);
                i += 2;
                continue;
            }
            if b == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        match (b, bytes.get(i + 1)) {
            (b'"', _) => {
                in_string = true;
                out.push(b);
                i += 1;
            }
            (b'/', Some(b'/')) => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            (b'/', Some(b'*')) => {
                i = skip_block_comment(bytes, i);
                out.push(b' ');
            }
            _ => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

fn strip_trailing_commas(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    let mut in_string = false;
    while i < bytes.len() {
        let b = bytes[i];
        if in_string {
            out.push(b);
            if b == b'\\' && i + 1 < bytes.len() {
                out.push(bytes[i + 1]);
                i += 2;
                continue;
            }
            if b == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        if b == b'"' {
            in_string = true;
        }
        if b == b',' {
            let mut j = i + 1;
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            if matches!(bytes.get(j), Some(b'}') | Some(b']')) {
                i += 1;
                continue;
            }
        }
        out.push(b);
        i += 1;
    }
    String::from_utf8(out).ok()
}

fn skip_block_comment(bytes: &[u8], start: usize) -> usize {
    let mut i = start + 2;
    while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
        i += 1;
    }
    (i + 2).min(bytes.len())
}

fn skip_trivia(bytes: &[u8], mut i: usize) -> usize {
    loop {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        match (bytes.get(i), bytes.get(i + 1)) {
            (Some(b'/'), Some(b'/')) => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            (Some(b'/'), Some(b'*')) => i = skip_block_comment(bytes, i),
            _ => return i,
        }
    }
}

fn skip_string(bytes: &[u8], start: usize) -> Option<usize> {
    let mut i = start + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'"' => return Some(i + 1),
            _ => i += 1,
        }
    }
    None
}

fn skip_value(bytes: &[u8], start: usize) -> Option<usize> {
    match bytes.get(start)? {
        b'"' => skip_string(bytes, start),
        b'{' | b'[' => {
            let mut depth = 0usize;
            let mut i = start;
            while i < bytes.len() {
                match bytes[i] {
                    b'"' => {
                        i = skip_string(bytes, i)?;
                        continue;
                    }
                    b'/' if matches!(bytes.get(i + 1), Some(b'/') | Some(b'*')) => {
                        i = skip_trivia(bytes, i);
                        continue;
                    }
                    b'{' | b'[' => depth += 1,
                    b'}' | b']' => {
                        depth -= 1;
                        if depth == 0 {
                            return Some(i + 1);
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
            None
        }
        _ => {
            let mut i = start;
            while i < bytes.len()
                && !matches!(bytes[i], b',' | b'}' | b']' | b'/')
                && !bytes[i].is_ascii_whitespace()
            {
                i += 1;
            }
            Some(i)
        }
    }
}

struct Member {
    key: String,
    start: usize,
    end: usize,
    comma: Option<usize>,
}

fn top_level_members(text: &str) -> Option<Vec<Member>> {
    let bytes = text.as_bytes();
    let mut i = skip_trivia(bytes, 0);
    if bytes.get(i) != Some(&b'{') {
        return None;
    }
    i += 1;
    let mut members = Vec::new();
    loop {
        i = skip_trivia(bytes, i);
        match bytes.get(i)? {
            b'}' => return Some(members),
            b'"' => {}
            _ => return None,
        }
        let key_start = i;
        let key_end = skip_string(bytes, key_start)?;
        let key: String = serde_json::from_str(&text[key_start..key_end]).ok()?;
        i = skip_trivia(bytes, key_end);
        if bytes.get(i) != Some(&b':') {
            return None;
        }
        i = skip_trivia(bytes, i + 1);
        let value_end = skip_value(bytes, i)?;
        let after = skip_trivia(bytes, value_end);
        let comma = (bytes.get(after) == Some(&b',')).then_some(after);
        members.push(Member {
            key,
            start: key_start,
            end: comma.map_or(value_end, |c| c + 1),
            comma,
        });
        i = comma.map_or(after, |c| c + 1);
    }
}

fn line_start(bytes: &[u8], from: usize) -> Option<usize> {
    let mut i = from;
    while i > 0 && matches!(bytes[i - 1], b' ' | b'\t') {
        i -= 1;
    }
    (i == 0 || bytes[i - 1] == b'\n').then_some(i)
}

fn line_end(bytes: &[u8], from: usize) -> Option<usize> {
    let mut i = from;
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t') {
        i += 1;
    }
    match bytes.get(i) {
        Some(b'\r') if bytes.get(i + 1) == Some(&b'\n') => Some(i + 2),
        Some(b'\n') => Some(i + 1),
        None => Some(i),
        _ => None,
    }
}

pub fn remove_top_level_keys(text: &str, keys: &[&str]) -> Option<String> {
    let members = top_level_members(text)?;
    let bytes = text.as_bytes();
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    for (index, member) in members.iter().enumerate() {
        if !keys.contains(&member.key.as_str()) {
            continue;
        }
        let whole_line = line_start(bytes, member.start).zip(line_end(bytes, member.end));
        ranges.push(whole_line.unwrap_or((member.start, member.end)));
        if member.comma.is_none() {
            let dangling = members[..index]
                .iter()
                .rev()
                .find(|m| !keys.contains(&m.key.as_str()))
                .and_then(|m| m.comma);
            if let Some(c) = dangling {
                ranges.push((c, c + 1));
            }
        }
    }
    if ranges.is_empty() {
        return None;
    }
    ranges.sort();
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    for (start, end) in ranges {
        if start < cursor {
            continue;
        }
        out.push_str(&text[cursor..start]);
        cursor = end;
    }
    out.push_str(&text[cursor..]);
    Some(out)
}
