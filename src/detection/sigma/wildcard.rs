/// Case-insensitive glob match where `*` matches any run of characters and
/// `?` exactly one. `\*`, `\?` and `\\` match the literal character.
///
/// Uses the classic greedy algorithm with a single backtrack point, so it
/// runs in O(pattern * text) time even on hostile input.
pub fn matches(pattern: &str, text: &str) -> bool {
    let pattern = compile(pattern);
    let text: Vec<char> = text.chars().flat_map(char::to_lowercase).collect();

    let (mut p, mut t) = (0, 0);
    // Last `*` seen and the text position it is currently absorbing up to.
    let mut backtrack: Option<(usize, usize)> = None;

    while t < text.len() {
        match pattern.get(p) {
            Some(Token::Star) => {
                backtrack = Some((p, t));
                p += 1;
            }
            Some(Token::Any) => {
                p += 1;
                t += 1;
            }
            Some(Token::Literal(c)) if *c == text[t] => {
                p += 1;
                t += 1;
            }
            _ => match backtrack {
                // Let the last `*` swallow one more character and retry.
                Some((star, absorbed)) => {
                    backtrack = Some((star, absorbed + 1));
                    p = star + 1;
                    t = absorbed + 1;
                }
                None => return false,
            },
        }
    }

    pattern[p..].iter().all(|token| *token == Token::Star)
}

#[derive(Debug, PartialEq, Eq)]
enum Token {
    Star,
    Any,
    Literal(char),
}

fn compile(pattern: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut chars = pattern.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '*' => tokens.push(Token::Star),
            '?' => tokens.push(Token::Any),
            '\\' if matches!(chars.peek(), Some('*' | '?' | '\\')) => {
                tokens.push(Token::Literal(chars.next().unwrap()));
            }
            _ => tokens.extend(c.to_lowercase().map(Token::Literal)),
        }
    }
    tokens
}

#[cfg(test)]
mod tests {
    use super::matches;

    #[test]
    fn literal_patterns_match_case_insensitively() {
        assert!(matches("root", "ROOT"));
        assert!(!matches("root", "roots"));
        assert!(!matches("root", "roo"));
    }

    #[test]
    fn star_matches_any_run_including_empty() {
        assert!(matches("*", ""));
        assert!(matches("sel*", "selection"));
        assert!(matches("sel*", "sel"));
        assert!(matches("*tion", "selection"));
        assert!(matches("a*b*c", "aXXbYYc"));
        assert!(!matches("a*b*c", "aXXbYY"));
    }

    #[test]
    fn question_mark_matches_exactly_one_character() {
        assert!(matches("r??t", "root"));
        assert!(!matches("r??t", "rot"));
    }

    #[test]
    fn escaped_wildcards_are_literal() {
        assert!(matches(r"a\*b", "a*b"));
        assert!(!matches(r"a\*b", "aXb"));
        assert!(matches(r"a\?b", "a?b"));
        assert!(matches(r"a\\b", r"a\b"));
    }

    #[test]
    fn hostile_input_finishes_quickly() {
        let text = "a".repeat(10_000);
        assert!(!matches("*a*a*a*a*a*a*a*a*b", &text));
    }
}
