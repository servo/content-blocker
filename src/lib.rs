/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

extern crate regex;
extern crate serde_json;
use regex::Regex;
use serde_json::Value;

/// Errors returned when parsing a JSON representation of a list of rules.
#[derive(Debug, PartialEq)]
pub enum Error {
    JSON,
    NotAList,
}

/// A potential list of resource types being requested.
#[derive(Clone, Debug, PartialEq)]
pub enum ResourceTypeList {
    /// All possible types.
    All,
    /// An explicit list of resource types.
    List(Vec<ResourceType>)
}

/// The type of resource being requested.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ResourceType {
    /// A top-level document.
    Document,
    /// An image subresource.
    Image,
    /// A CSS stylesheet subresource.
    StyleSheet,
    /// A JavaScript subresource.
    Script,
    /// A web font.
    Font,
    /// An uncategorized request (eg. XMLHttpRequest).
    Raw,
    /// An SVG document.
    SVGDocument,
    /// A media resource.
    Media,
    /// A popup resource.
    Popup,
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

/// The type of load that is being initiated.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum LoadType {
    /// Same-origin with respect to the originating page.
    FirstParty,
    /// Cross-origin with respect to the originating page.
    ThirdParty,
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

#[derive(Clone, Debug, PartialEq)]
pub enum DomainExemption {
    SubdomainMatch(String),
    DomainMatch(String),
}

impl DomainExemption {
    fn from_str(s: &str) -> DomainExemption {
        if s.starts_with("*") {
            DomainExemption::SubdomainMatch(s[1..].to_owned())
        } else {
            DomainExemption::DomainMatch(s.to_owned())
        }
    }

    fn matches(&self, request: &Request) -> bool {
        let domain = match *self {
            DomainExemption::SubdomainMatch(ref domain) |
            DomainExemption::DomainMatch(ref domain) => domain
        };

        if request.url.find(&format!("://{}", domain)).is_some() {
            return true;
        }
        if let DomainExemption::SubdomainMatch(_) = *self {
            if request.url.find(&format!(".{}", domain)).is_some() {
                return true;
            }
        }

        false
    }
}

/// Conditions which restrict the set of matches for a particular trigger.
#[derive(Clone, Debug, PartialEq)]
pub enum Exemption {
    /// Only trigger if the domain matches one of the included strings.
    If(Vec<DomainExemption>),
    /// Trigger unless the domain matches one of the included strings.
    Unless(Vec<DomainExemption>),
}

/// A set of filters that determine if a given rule's action is performed.
#[derive(Clone, Debug, PartialEq)]
pub struct Trigger {
    /// A simple regex that is matched against the characters in the destination resource's URL.
    url_filter: Regex,
    /// The classes of resources for which this trigger matches.
    resource_type: ResourceTypeList,
    /// The category of loads for which this trigger matches.
    load_type: Option<LoadType>,
    /// Domains which modify the behaviour of this trigger, either specifically including or
    /// excluding from the matches based on string comparison.
    exemption: Option<Exemption>,
}

impl Trigger {
    fn matches(&self, request: &Request) -> bool {
        if let ResourceTypeList::List(ref types) = self.resource_type {
            if types.iter().find(|t| **t == request.resource_type).is_none() {
                return false;
            }
        }

        if let Some(ref load_type) = self.load_type {
            if request.load_type != *load_type {
                return false;
            }
        }

        if self.url_filter.is_match(request.url) {
            match self.exemption {
                Some(Exemption::If(ref exemptions)) => {
                    for condition in exemptions {
                        if condition.matches(request) {
                            return true;
                        }
                    }
                    return false;
                }
                Some(Exemption::Unless(ref exemptions)) => {
                    for condition in exemptions {
                        if condition.matches(request) {
                            return false;
                        }
                    }
                    return true;
                }
                None => return true,
            }
        }

        false
    }
}

impl Default for Trigger {
    fn default() -> Trigger {
        Trigger {
            url_filter: Regex::new("").unwrap(),
            resource_type: ResourceTypeList::All,
            load_type: None,
            exemption: None,
        }
    }
}

/// An action to take when a rule is triggered.
#[derive(Clone, Debug, PartialEq)]
pub enum Action {
    /// Prevent the network request from starting.
    Block,
    /// Remove any HTTP cookies from the network request before starting it.
    BlockCookies,
    /// Hide elements of the requesting page based on the given CSS selector.
    CssDisplayNone(String),
    /// Any previously triggered rules do not have their actions performed.
    IgnorePreviousRules,
}

impl Action {
    fn process(&self, reactions: &mut Vec<Reaction>) {
        match *self {
            Action::Block =>
                reactions.push(Reaction::Block),
            Action::BlockCookies =>
                reactions.push(Reaction::BlockCookies),
            Action::CssDisplayNone(ref selector) =>
                reactions.push(Reaction::HideMatchingElements(selector.clone())),
            Action::IgnorePreviousRules =>
                reactions.clear(),
        }
    }

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

#[derive(Clone, Debug, PartialEq)]
/// A single rule, consisting of a condition to trigger this rule, and an action to take.
pub struct Rule {
    trigger: Trigger,
    action: Action,
}

/// A request that could be filtered.
pub struct Request<'a> {
    /// The requested URL.
    pub url: &'a str,
    /// The resource type for which this request was initiated.
    pub resource_type: ResourceType,
    /// The relationship of this request to the originating document.
    pub load_type: LoadType,
}

impl<'a> Default for Request<'a> {
    fn default() -> Request<'static> {
        Request {
            url: "",
            resource_type: ResourceType::Document,
            load_type: LoadType::FirstParty,
        }
    }
}

/// The action to take for the provided request.
#[derive(Debug, PartialEq)]
pub enum Reaction {
    /// Block the request from starting.
    Block,
    /// Strip the HTTP cookies from the request.
    BlockCookies,
    /// Hide the elements matching the given CSS selector in the originating document.
    HideMatchingElements(String)
}

/// Attempt to match the given request against the provided rules. Returns a list
/// of actions to take in response; an empty list means that the request should
/// continue unmodified.
pub fn process_rules_for_request(rules: &[Rule], request: &Request) -> Vec<Reaction> {
    let mut reactions = vec![];
    for rule in rules {
        if rule.trigger.matches(request) {
            rule.action.process(&mut reactions);
        }
    }
    reactions
}

/// Parse a string containing a JSON representation of a content blocker list.
/// Returns a vector of parsed rules, or an error representing the nature of
/// the invalid input. Any rules missing required fields will be silently ignored.
pub fn parse_list(body: &str) -> Result<Vec<Rule>, Error> {
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

#[cfg(test)]
mod tests;
