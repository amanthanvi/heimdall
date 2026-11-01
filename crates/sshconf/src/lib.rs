//! OpenSSH and Git configuration text (m02-plan U1, U2; ADR-0007 §2–§4).
//!
//! This is the **pure** configuration-text crate. It reads configuration only through
//! the [`include::ConfigSource`] trait, which has no way to run a command, and it never
//! opens a socket, a pipe or a private key. `Match exec`, `ProxyCommand`,
//! `KnownHostsCommand` and `LocalCommand` are recorded, never executed: an evaluation
//! that depends on them is `Undetermined` (ADR-0007 F4, F13).
//!
//! * U1 owns [`lex`], [`parse`], [`directive`], [`include`] and [`limits`];
//! * U2 owns [`eval`], [`relevant`], [`render`], [`edit`], [`consent`] and
//!   [`gitedit`].
//!
//! **Skeleton status (m02-plan U0, wave 0).** Every type and signature here is fixed by
//! the integrator. A body that its unit has not written yet is
//! `todo!("M02-Uxx …")`. None of them is reachable in this build: no request, CLI
//! command, restart recovery or store method calls into this crate until U3, U4 and U5
//! land (m02-plan "Skeleton rule"). Small mechanical bodies (the keyword spelling
//! table, the limits) are complete.

pub mod consent;
pub mod directive;
pub mod edit;
pub mod eval;
pub mod gitedit;
pub mod include;
pub mod lex;
pub mod limits;
pub mod parse;
pub mod relevant;
pub mod render;

#[cfg(test)]
mod tests {
    use super::directive::KnownKeyword;
    use super::limits::Limits;

    #[test]
    fn limits_are_the_m02_plan_bounds() {
        let l = Limits::default();
        assert_eq!(l.file_bytes, 1 << 20);
        assert_eq!(l.total_bytes, 8 << 20);
        assert_eq!(l.files, 256);
        assert_eq!(l.depth, 16);
        assert_eq!(l.glob_results, 256);
        assert_eq!(l.line_bytes, 4096);
    }

    #[test]
    fn every_known_keyword_spelling_round_trips_case_insensitively() {
        for k in KnownKeyword::ALL {
            assert_eq!(KnownKeyword::parse(k.as_str()), Some(*k));
            assert_eq!(
                KnownKeyword::parse(&k.as_str().to_ascii_lowercase()),
                Some(*k)
            );
            assert_eq!(
                KnownKeyword::parse(&k.as_str().to_ascii_uppercase()),
                Some(*k)
            );
        }
        assert_eq!(KnownKeyword::parse("NoSuchKeyword"), None);
        assert_eq!(KnownKeyword::parse(""), None);
    }

    #[test]
    fn keyword_table_has_no_duplicate_spelling() {
        let mut seen = std::collections::BTreeSet::new();
        for k in KnownKeyword::ALL {
            assert!(
                seen.insert(k.as_str().to_ascii_lowercase()),
                "{}",
                k.as_str()
            );
        }
    }
}
