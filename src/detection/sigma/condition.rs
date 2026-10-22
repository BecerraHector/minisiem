//! Sigma `condition` expressions.
//!
//! Grammar (lowest to highest precedence):
//!
//! ```text
//! or_expr    := and_expr ("or" and_expr)*
//! and_expr   := not_expr ("and" not_expr)*
//! not_expr   := "not" not_expr | primary
//! primary    := "(" or_expr ")" | quantifier | IDENT
//! quantifier := ("1" | "all") "of" ("them" | PATTERN)
//! ```

use std::fmt;

use super::wildcard;

/// Which search identifiers a quantifier (`1 of`, `all of`) ranges over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selector {
    Them,
    Pattern(String),
}

impl Selector {
    pub fn select<'a>(&self, identifiers: &[&'a str]) -> Vec<&'a str> {
        identifiers
            .iter()
            .copied()
            .filter(|id| match self {
                Selector::Them => true,
                Selector::Pattern(pattern) => wildcard::matches(pattern, id),
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Condition {
    Search(String),
    Not(Box<Condition>),
    And(Box<Condition>, Box<Condition>),
    Or(Box<Condition>, Box<Condition>),
    OneOf(Selector),
    AllOf(Selector),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConditionError {
    Empty,
    UnexpectedEnd,
    UnexpectedToken { token: String, position: usize },
    InvalidCharacter { character: char, position: usize },
    AggregationNotSupported,
    WildcardOutsideQuantifier(String),
}

impl fmt::Display for ConditionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "condition is empty"),
            Self::UnexpectedEnd => write!(f, "condition ends unexpectedly"),
            Self::UnexpectedToken { token, position } => {
                write!(f, "unexpected '{token}' at position {position}")
            }
            Self::InvalidCharacter { character, position } => {
                write!(f, "invalid character '{character}' at position {position}")
            }
            Self::AggregationNotSupported => {
                write!(
                    f,
                    "aggregation expressions ('|') are not supported; use correlation rules"
                )
            }
            Self::WildcardOutsideQuantifier(pattern) => {
                write!(f, "wildcard '{pattern}' is only allowed after '1 of' or 'all of'")
            }
        }
    }
}

impl std::error::Error for ConditionError {}

impl Condition {
    pub fn parse(input: &str) -> Result<Self, ConditionError> {
        let tokens = tokenize(input)?;
        if tokens.is_empty() {
            return Err(ConditionError::Empty);
        }

        let mut parser = Parser { tokens, pos: 0 };
        let condition = parser.or_expr()?;
        match parser.peek() {
            None => Ok(condition),
            Some(_) => Err(parser.unexpected()),
        }
    }

    /// Evaluates the condition. `identifiers` lists every search identifier
    /// defined by the rule; `is_match` tells whether one of them matched.
    pub fn evaluate(&self, identifiers: &[&str], is_match: &dyn Fn(&str) -> bool) -> bool {
        match self {
            Condition::Search(id) => is_match(id),
            Condition::Not(inner) => !inner.evaluate(identifiers, is_match),
            Condition::And(a, b) => a.evaluate(identifiers, is_match) && b.evaluate(identifiers, is_match),
            Condition::Or(a, b) => a.evaluate(identifiers, is_match) || b.evaluate(identifiers, is_match),
            Condition::OneOf(selector) => selector.select(identifiers).into_iter().any(is_match),
            Condition::AllOf(selector) => {
                let selected = selector.select(identifiers);
                !selected.is_empty() && selected.into_iter().all(is_match)
            }
        }
    }

    /// Every identifier or pattern the condition references, for validation.
    pub fn references(&self) -> Vec<Reference<'_>> {
        let mut found = Vec::new();
        self.collect_references(&mut found);
        found
    }

    fn collect_references<'a>(&'a self, found: &mut Vec<Reference<'a>>) {
        match self {
            Condition::Search(id) => found.push(Reference::Identifier(id)),
            Condition::Not(inner) => inner.collect_references(found),
            Condition::And(a, b) | Condition::Or(a, b) => {
                a.collect_references(found);
                b.collect_references(found);
            }
            Condition::OneOf(Selector::Pattern(p)) | Condition::AllOf(Selector::Pattern(p)) => {
                found.push(Reference::Pattern(p));
            }
            Condition::OneOf(Selector::Them) | Condition::AllOf(Selector::Them) => {}
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Word(String),
    LParen,
    RParen,
}

impl Token {
    fn text(&self) -> &str {
        match self {
            Token::Word(word) => word,
            Token::LParen => "(",
            Token::RParen => ")",
        }
    }

    fn is_keyword(&self, keyword: &str) -> bool {
        matches!(self, Token::Word(word) if word == keyword)
    }
}

const KEYWORDS: [&str; 6] = ["and", "or", "not", "of", "them", "all"];

fn tokenize(input: &str) -> Result<Vec<(Token, usize)>, ConditionError> {
    let mut tokens = Vec::new();
    let mut chars = input.char_indices().peekable();

    while let Some(&(position, c)) = chars.peek() {
        match c {
            c if c.is_whitespace() => {
                chars.next();
            }
            '(' | ')' => {
                chars.next();
                let token = if c == '(' { Token::LParen } else { Token::RParen };
                tokens.push((token, position));
            }
            '|' => return Err(ConditionError::AggregationNotSupported),
            c if is_word_char(c) => {
                let mut word = String::new();
                while let Some(&(_, c)) = chars.peek().filter(|(_, c)| is_word_char(*c)) {
                    word.push(c);
                    chars.next();
                }
                tokens.push((Token::Word(word), position));
            }
            character => return Err(ConditionError::InvalidCharacter { character, position }),
        }
    }
    Ok(tokens)
}

fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '_' | '-' | '.' | '*')
}

struct Parser {
    tokens: Vec<(Token, usize)>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos).map(|(token, _)| token)
    }

    fn next(&mut self) -> Result<Token, ConditionError> {
        let (token, _) = self.tokens.get(self.pos).ok_or(ConditionError::UnexpectedEnd)?;
        self.pos += 1;
        Ok(token.clone())
    }

    /// Error for the token at the current position (which must exist).
    fn unexpected(&self) -> ConditionError {
        match self.tokens.get(self.pos) {
            Some((token, position)) => ConditionError::UnexpectedToken {
                token: token.text().to_string(),
                position: *position,
            },
            None => ConditionError::UnexpectedEnd,
        }
    }

    fn or_expr(&mut self) -> Result<Condition, ConditionError> {
        let mut left = self.and_expr()?;
        while self.peek().is_some_and(|t| t.is_keyword("or")) {
            self.pos += 1;
            left = Condition::Or(Box::new(left), Box::new(self.and_expr()?));
        }
        Ok(left)
    }

    fn and_expr(&mut self) -> Result<Condition, ConditionError> {
        let mut left = self.not_expr()?;
        while self.peek().is_some_and(|t| t.is_keyword("and")) {
            self.pos += 1;
            left = Condition::And(Box::new(left), Box::new(self.not_expr()?));
        }
        Ok(left)
    }

    fn not_expr(&mut self) -> Result<Condition, ConditionError> {
        if self.peek().is_some_and(|t| t.is_keyword("not")) {
            self.pos += 1;
            return Ok(Condition::Not(Box::new(self.not_expr()?)));
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<Condition, ConditionError> {
        let error = self.unexpected();
        match self.next()? {
            Token::LParen => {
                let inner = self.or_expr()?;
                match self.peek() {
                    Some(Token::RParen) => {
                        self.pos += 1;
                        Ok(inner)
                    }
                    _ => Err(self.unexpected()),
                }
            }
            Token::Word(word) if word == "1" || word == "all" => {
                let selector = self.quantified()?;
                Ok(if word == "1" {
                    Condition::OneOf(selector)
                } else {
                    Condition::AllOf(selector)
                })
            }
            Token::Word(word) if KEYWORDS.contains(&word.as_str()) => Err(error),
            Token::Word(word) if word.chars().all(|c| c.is_ascii_digit()) => Err(error),
            Token::Word(word) if word.contains('*') => Err(ConditionError::WildcardOutsideQuantifier(word)),
            Token::Word(word) => Ok(Condition::Search(word)),
            Token::RParen => Err(error),
        }
    }

    /// Parses `of them` / `of <pattern>` after a `1` or `all`.
    fn quantified(&mut self) -> Result<Selector, ConditionError> {
        let error = self.unexpected();
        if !self.next()?.is_keyword("of") {
            return Err(error);
        }

        let error = self.unexpected();
        match self.next()? {
            Token::Word(word) if word == "them" => Ok(Selector::Them),
            Token::Word(word) if !KEYWORDS.contains(&word.as_str()) => Ok(Selector::Pattern(word)),
            _ => Err(error),
        }
    }
}

/// Something a condition refers to, used to validate it against the rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reference<'a> {
    Identifier(&'a str),
    Pattern(&'a str),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn search(id: &str) -> Condition {
        Condition::Search(id.into())
    }

    fn not(c: Condition) -> Condition {
        Condition::Not(Box::new(c))
    }

    fn and(a: Condition, b: Condition) -> Condition {
        Condition::And(Box::new(a), Box::new(b))
    }

    fn or(a: Condition, b: Condition) -> Condition {
        Condition::Or(Box::new(a), Box::new(b))
    }

    fn parse(input: &str) -> Condition {
        Condition::parse(input).unwrap_or_else(|e| panic!("{input:?} should parse: {e}"))
    }

    #[test]
    fn parses_single_identifier() {
        assert_eq!(parse("selection"), search("selection"));
        assert_eq!(parse("  sel_1-x  "), search("sel_1-x"));
    }

    #[test]
    fn not_binds_tighter_than_and_which_binds_tighter_than_or() {
        assert_eq!(
            parse("a or b and not c"),
            or(search("a"), and(search("b"), not(search("c"))))
        );
        assert_eq!(parse("not a and b"), and(not(search("a")), search("b")));
    }

    #[test]
    fn same_operator_associates_left() {
        assert_eq!(parse("a and b and c"), and(and(search("a"), search("b")), search("c")));
    }

    #[test]
    fn parentheses_override_precedence() {
        assert_eq!(parse("(a or b) and c"), and(or(search("a"), search("b")), search("c")));
        assert_eq!(parse("not (a or b)"), not(or(search("a"), search("b"))));
    }

    #[test]
    fn parses_quantifiers() {
        assert_eq!(
            parse("1 of selection*"),
            Condition::OneOf(Selector::Pattern("selection*".into()))
        );
        assert_eq!(parse("all of them"), Condition::AllOf(Selector::Them));
        assert_eq!(
            parse("1 of them and not filter"),
            and(Condition::OneOf(Selector::Them), not(search("filter")))
        );
    }

    #[test]
    fn rejects_invalid_conditions() {
        let cases = [
            ("", ConditionError::Empty),
            ("   ", ConditionError::Empty),
            ("a and", ConditionError::UnexpectedEnd),
            ("(a", ConditionError::UnexpectedEnd),
            ("1 of", ConditionError::UnexpectedEnd),
            (
                "a b",
                ConditionError::UnexpectedToken {
                    token: "b".into(),
                    position: 2,
                },
            ),
            (
                "a)",
                ConditionError::UnexpectedToken {
                    token: ")".into(),
                    position: 1,
                },
            ),
            (
                "and a",
                ConditionError::UnexpectedToken {
                    token: "and".into(),
                    position: 0,
                },
            ),
            (
                "2 of them",
                ConditionError::UnexpectedToken {
                    token: "2".into(),
                    position: 0,
                },
            ),
            (
                "a & b",
                ConditionError::InvalidCharacter {
                    character: '&',
                    position: 2,
                },
            ),
            ("sel | count() > 5", ConditionError::AggregationNotSupported),
            ("sel*", ConditionError::WildcardOutsideQuantifier("sel*".into())),
        ];

        for (input, expected) in cases {
            assert_eq!(Condition::parse(input), Err(expected), "input: {input:?}");
        }
    }

    #[test]
    fn evaluates_boolean_operators() {
        let ids = ["a", "b", "c"];
        let matched = |id: &str| id == "a" || id == "c";

        assert!(parse("a").evaluate(&ids, &matched));
        assert!(!parse("b").evaluate(&ids, &matched));
        assert!(parse("a and c").evaluate(&ids, &matched));
        assert!(!parse("a and b").evaluate(&ids, &matched));
        assert!(parse("b or c").evaluate(&ids, &matched));
        assert!(parse("a and not b").evaluate(&ids, &matched));
    }

    #[test]
    fn evaluates_quantifiers() {
        let ids = ["selection_root", "selection_admin", "filter"];
        let matched = |id: &str| id == "selection_root";

        assert!(parse("1 of selection*").evaluate(&ids, &matched));
        assert!(!parse("all of selection*").evaluate(&ids, &matched));
        assert!(parse("1 of them").evaluate(&ids, &matched));
        assert!(!parse("all of them").evaluate(&ids, &matched));
        assert!(parse("all of selection_r*").evaluate(&ids, &matched));
    }

    #[test]
    fn lists_references_for_validation() {
        let condition = parse("a and not (1 of sel* or all of them)");

        assert_eq!(
            condition.references(),
            vec![Reference::Identifier("a"), Reference::Pattern("sel*")]
        );
    }
}
