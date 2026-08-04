//! Static scanner.
//!
//! Parses source files with tree-sitter and matches declarative rules against the
//! syntax tree. Text matching is deliberately absent: a rule that fires on a string
//! in a comment produces a claim the evidence does not support.

#![doc(html_no_source)]
