pub fn escape_rsplitn(s: &str, n: usize, delimiter: char) -> impl Iterator<Item = &str> {
    struct EscapedSplitRev<'a> {
        remaining: &'a str,
        delimiter: char,
        max_splits: usize,
        splits_done: usize,
    }

    impl<'a> Iterator for EscapedSplitRev<'a> {
        type Item = &'a str;

        fn next(&mut self) -> Option<Self::Item> {
            // Stop if we've reached max splits or no remaining string
            if self.splits_done >= self.max_splits || self.remaining.is_empty() {
                return None;
            }

            // If this is the last split, return the entire remaining string
            if self.splits_done == self.max_splits - 1 {
                let result = self.remaining;
                self.remaining = "";
                self.splits_done += 1;
                return Some(result);
            }

            // Find the last unescaped occurrence of the delimiter
            let mut last_split_index = None;
            let chars = self.remaining.char_indices().rev();

            for (idx, current) in chars {
                // Check if the delimiter is unescaped
                let is_unescaped = idx == 0 || self.remaining.as_bytes()[idx - 1] != b'\\';

                if current == self.delimiter && is_unescaped {
                    last_split_index = Some(idx);
                    break;
                }
            }

            // Perform the split
            let result = if let Some(split_idx) = last_split_index {
                let part = &self.remaining[split_idx + self.delimiter.len_utf8()..];
                self.remaining = &self.remaining[..split_idx];
                part
            } else {
                // No unescaped delimiter found
                let part = self.remaining;
                self.remaining = "";
                part
            };

            self.splits_done += 1;
            Some(result)
        }
    }

    // Adjust max splits if n is 0
    let max_splits = if n == 0 { usize::MAX } else { n };

    EscapedSplitRev {
        remaining: s,
        delimiter,
        max_splits,
        splits_done: 0,
    }
}

pub fn count_unescaped_chars(s: &str, target: char) -> usize {
    let mut count = 0;
    let mut chars = s.chars();

    while let Some(current) = chars.next() {
        if current == '\\' {
            // Skip the next character if it's preceded by a backslash
            chars.next();
        } else if current == target {
            count += 1;
        }
    }

    count
}

pub fn escape_split(s: &str, delimiter: char) -> impl Iterator<Item = &str> {
    struct EscapedSplit<'a> {
        remaining: &'a str,
        delimiter: char,
        first_split: bool,
    }

    impl<'a> Iterator for EscapedSplit<'a> {
        type Item = &'a str;

        fn next(&mut self) -> Option<Self::Item> {
            // If no remaining string, return None
            if self.remaining.is_empty() {
                return None;
            }

            // For the first split, we want to search from the beginning
            if self.first_split {
                self.first_split = false;
            }

            // Find the first unescaped occurrence of the delimiter
            let chars = self.remaining.char_indices();

            for (idx, current) in chars {
                // Check if the delimiter is unescaped
                let is_unescaped = idx == 0 || self.remaining.as_bytes()[idx - 1] != b'\\';

                if current == self.delimiter && is_unescaped {
                    // Split at this point
                    let part = &self.remaining[..idx];
                    self.remaining = &self.remaining[idx + self.delimiter.len_utf8()..];
                    return Some(part);
                }
            }

            // If no delimiter found, return the entire remaining string
            let part = self.remaining;
            self.remaining = "";
            Some(part)
        }
    }

    EscapedSplit {
        remaining: s,
        delimiter,
        first_split: true,
    }
}

pub trait HasOddNonEmptyCount {
    fn is_uneven(&self) -> bool;
}

impl<T: for<'a> AsRef<str>> HasOddNonEmptyCount for Vec<T> {
    fn is_uneven(&self) -> bool {
        self.iter()
            .filter(|s| !s.as_ref().trim().is_empty())
            .count()
            % 2
            != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_custom_rsplitn() {
        // Basic splitting
        let s = "a:b:c";
        assert_eq!(
            escape_rsplitn(s, 2, ':').collect::<Vec<_>>(),
            vec!["c", "a:b"]
        );

        // Escaped delimiter
        let s = r"a\:b:c";
        assert_eq!(
            escape_rsplitn(s, 2, ':').collect::<Vec<_>>(),
            vec!["c", r"a\:b"]
        );

        // Multiple escaped delimiters
        let s = r"a\:b\:c:d";
        assert_eq!(
            escape_rsplitn(s, 2, ':').collect::<Vec<_>>(),
            vec!["d", r"a\:b\:c"]
        );

        // No delimiter
        let s = "abc";
        assert_eq!(escape_rsplitn(s, 2, ':').collect::<Vec<_>>(), vec!["abc"]);

        // Delimiter at the end
        let s = r"a:b\:";
        assert_eq!(
            escape_rsplitn(s, 2, ':').collect::<Vec<_>>(),
            vec![r"b\:", "a"]
        );

        // Complex case with multiple escapes
        let s = r"a\:b:c\:d:e";
        assert_eq!(
            escape_rsplitn(s, 3, ':').collect::<Vec<_>>(),
            vec!["e", r"c\:d", r"a\:b"]
        );
    }

    #[test]
    fn test_count_unescaped_chars() {
        assert_eq!(count_unescaped_chars(r#"hello\"world\""#, '"'), 0);
        assert_eq!(count_unescaped_chars(r#"hello\"world"#, '"'), 0);
        assert_eq!(count_unescaped_chars(r#"hello\"world\"test"#, '"'), 0);
        assert_eq!(count_unescaped_chars(r#"hello\"world\""test"#, '"'), 1);
        assert_eq!(count_unescaped_chars(r#"hello\"world\\\"test"#, '"'), 0);
        assert_eq!(count_unescaped_chars(r#"hello\\\"world\\\"test"#, '"'), 0);
        assert_eq!(count_unescaped_chars("hello world", 'l'), 3);
        assert_eq!(count_unescaped_chars(r"hello\l world", 'l'), 3);
    }

    #[test]
    fn test_escape_split() {
        // Basic splitting
        let s = "a:b:c";
        assert_eq!(
            escape_split(s, ':').collect::<Vec<_>>(),
            vec!["a", "b", "c"]
        );

        // Escaped delimiter
        let s = r"a\:b:c";
        assert_eq!(escape_split(s, ':').collect::<Vec<_>>(), vec![r"a\:b", "c"]);

        // Multiple escaped delimiters
        let s = r"a\:b\:c:d";
        assert_eq!(
            escape_split(s, ':').collect::<Vec<_>>(),
            vec![r"a\:b\:c", "d"]
        );

        // No delimiter
        let s = "abc";
        assert_eq!(escape_split(s, ':').collect::<Vec<_>>(), vec!["abc"]);

        // Delimiter at the end
        let s = r"a:b\:";
        assert_eq!(escape_split(s, ':').collect::<Vec<_>>(), vec!["a", r"b\:"]);

        // Complex case with multiple escapes
        let s = r"a\:b:c\:d:e";
        assert_eq!(
            escape_split(s, ':').collect::<Vec<_>>(),
            vec![r"a\:b", r"c\:d", "e"]
        );

        // Consecutive delimiters with escaping
        let s = r"a:b\::c";
        assert_eq!(
            escape_split(s, ':').collect::<Vec<_>>(),
            vec!["a", r"b\:", "c"]
        );
    }
}
