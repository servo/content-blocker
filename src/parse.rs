/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use regex::Regex;
use repr::{ResourceType, LoadType, DomainExemption, Action, Rule, ResourceTypeList, Exemption};
use repr::Trigger;
use serde_json::{self, Value};

/// Errors returned when parsing a JSON representation of a list of rules.
#[derive(Debug, PartialEq)]
pub enum Error {
    /// A JSON parsing error occurred.
    JSON,
    /// The root JSON object was not a list.
    NotAList,
}

impl ResourceType {
    fn from_str(s: &str) -> Option<ResourceType> {
        Some(match s {
            "document" => ResourceType::Document,
            "image" => ResourceType::Image,
            "style-sheet" => ResourceType::StyleSheet,
            "script" => ResourceType::Script,
            "font" => ResourceType::Font,
            "raw" => ResourceType::Raw,
            "svg-document" => ResourceType::SVGDocument,
            "media" => ResourceType::Media,
            "popup" => ResourceType::Popup,
            _ => return None,
        })
    }
}

impl LoadType {
    fn from_str(s: &str) -> Option<LoadType> {
        match s {
            "first-party" => Some(LoadType::FirstParty),
            "third-party" => Some(LoadType::ThirdParty),
            _ => None,
        }
    }
}

impl DomainExemption {
    fn from_str(s: &str) -> DomainExemption {
        if s.starts_with("*") {
            DomainExemption::SubdomainMatch(s[1..].to_owned())
        } else {
            DomainExemption::DomainMatch(s.to_owned())
        }
    }
}

impl Action {
    fn from_json(v: &Value) -> Option<Action> {
        let v = match v.as_object() {
            Some(v) => v,
            None => return None,
        };

        v.get("type").and_then(|t| t.as_string()).and_then(|t| {
            Some(match t {
                "block" => Action::Block,
                "block-cookies" => Action::BlockCookies,
                "ignore-previous-rules" => Action::IgnorePreviousRules,
                "css-display-none" => {
                    let selector = match v.get("selector").and_then(|s| s.as_string()) {
                        Some(s) => s,
                        None => return None,
                    };
                    Action::CssDisplayNone(selector.to_owned())
                }
                _ => return None,
            })
        })
    }
}

/// Parse a string containing a JSON representation of a content blocker list.
/// Returns a vector of parsed rules, or an error representing the nature of
/// the invalid input. Any rules missing required fields will be silently ignored.
pub fn parse_list_impl(body: &str) -> Result<Vec<Rule>, Error> {
    let json_body: Value = try!(serde_json::from_str(body).map_err(|_| Error::JSON));
    let list = try!(json_body.as_array().ok_or(Error::NotAList));
    let mut rules = vec![];
    for rule in list {
        let obj = match rule.as_object() {
            Some(obj) => obj,
            None => continue,
        };

        let trigger_source = match obj.get("trigger").and_then(|t| t.as_object()) {
            Some(trigger) => trigger,
            None => continue,
        };

        let url_filter_is_case_sensitive = trigger_source.get("url-filter-is-case-sensitive")
                                                         .and_then(|u| u.as_boolean())
                                                         .unwrap_or(false);

        let url_filter = match trigger_source.get("url-filter").and_then(|u| u.as_string()) {
            Some(filter) => {
                let flag = if url_filter_is_case_sensitive {
                    "(?i)"
                } else {
                    ""
                };
                match Regex::new(&format!("{}{}", flag, filter)) {
                    Ok(filter) => filter,
                    Err(_) => continue,
                }
            }
            None => continue,
        };

        let resource_type = match trigger_source.get("resource-type").and_then(|r| r.as_array()) {
            Some(list) => {
                ResourceTypeList::List(
                    list.iter()
                        .filter_map(|r| r.as_string()
                                         .and_then(|s| ResourceType::from_str(s)))
                        .collect())
            }
            None => ResourceTypeList::All,
        };

        let load_type =
            trigger_source.get("load-type")
                          .and_then(|l| l.as_array())
                          .and_then(|list|
                                    list.iter()
                                        .filter_map(|l| l.as_string()
                                                         .and_then(|s| LoadType::from_str(s)))
                                        .next());

        let if_domain =
            trigger_source.get("if-domain")
                          .and_then(|i| i.as_array())
                          .map(|i| i.iter()
                                    .filter_map(|d| d.as_string())
                                    .map(|s| DomainExemption::from_str(s))
                                    .collect());

        let unless_domain =
            trigger_source.get("unless-domain")
                          .and_then(|u| u.as_array())
                          .map(|u| u.iter()
                                    .filter_map(|d| d.as_string())
                                    .map(|s| DomainExemption::from_str(s))
                                    .collect());

        if if_domain.is_some() && unless_domain.is_some() {
            continue;
        }

        let exemption = if let Some(list) = if_domain {
            Some(Exemption::If(list))
        } else if let Some(list) = unless_domain {
            Some(Exemption::Unless(list))
        } else {
            None
        };

        let action = match obj.get("action").and_then(Action::from_json) {
            Some(action) => action,
            None => continue,
        };

        rules.push(Rule {
            trigger: Trigger {
                url_filter: url_filter,
                resource_type: resource_type,
                load_type: load_type,
                exemption: exemption,
            },
            action: action,
        });
    }

    Ok(rules)
}
