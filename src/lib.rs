/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

extern crate regex;
extern crate serde_json;

mod parse;
mod repr;

pub use parse::Error;
use parse::parse_list_impl;
pub use repr::{ResourceType, LoadType, Request, Reaction};
use repr::{Rule, process_rules_for_request_impl};

#[cfg(test)]
mod tests;

pub struct RuleList(Vec<Rule>);

/// Attempt to match the given request against the provided rules. Returns a list
/// of actions to take in response; an empty list means that the request should
/// continue unmodified.
pub fn process_rules_for_request(rules: &RuleList, request: &Request) -> Vec<Reaction> {
    process_rules_for_request_impl(&rules.0, request)
}

/// Parse a string containing a JSON representation of a content blocker list.
/// Returns a vector of parsed rules, or an error representing the nature of
/// the invalid input. Any rules missing required fields will be silently ignored.
pub fn parse_list(body: &str) -> Result<RuleList, Error> {
    parse_list_impl(body).map(|r| RuleList(r))
}
