#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

pub mod axes;
pub mod catalog;
pub mod enforce;
mod error;
pub mod roles;

pub use axes::{Access, Visibility};
pub use catalog::{Catalog, Permission};
pub use enforce::{Decision, Facts, Settings, Transport, decide};
pub use error::{Error, Result};
pub use roles::{Actor, Role, RoleSet, presets};
