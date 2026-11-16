//! The two independent settings of a resource.

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};

/// Who can see a resource exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Visibility {
    /// Only trusted peers; anyone else is told "not found".
    #[default]
    Private,
    /// Anyone with the link and every peer.
    Public,
}

/// Whether membership is needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Access {
    /// No membership needed.
    #[default]
    Open,
    /// A valid, unrevoked membership is needed. `gated` is the name on the wire.
    Gated,
}

impl Visibility {
    /// Parses `private` or `public`.
    pub fn parse(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "private" => Ok(Visibility::Private),
            "public" => Ok(Visibility::Public),
            _ => Err(Error::invalid("visibility", format!("{s:?}: private or public"))),
        }
    }
}

impl Access {
    /// Parses `open` or `gated`, and the CLI aliases `members`, `member` and `closed` for
    /// `gated` (aliases are never written on the wire).
    pub fn parse_cli(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "open" => Ok(Access::Open),
            "gated" | "members" | "member" | "closed" => Ok(Access::Gated),
            _ => Err(Error::invalid("access", format!("{s:?}: open or gated"))),
        }
    }

    /// The wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Access::Open => "open",
            Access::Gated => "gated",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_names_and_aliases() {
        assert_eq!(serde_json::to_string(&Access::Gated).unwrap(), "\"gated\"");
        assert!(serde_json::from_str::<Access>("\"members\"").is_err(), "aliases are CLI only");
        for a in ["members", "member", "closed", "GATED"] {
            assert_eq!(Access::parse_cli(a).unwrap(), Access::Gated);
        }
        assert!(Access::parse_cli("nope").is_err());
        assert_eq!((Visibility::default(), Access::default()), (Visibility::Private, Access::Open));
        assert_eq!(Visibility::parse("Public").unwrap(), Visibility::Public);
    }
}
