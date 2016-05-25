/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use regex::Regex;
use std::cmp::Ordering;
use url::Url;

/// A request that could be filtered.
pub struct Request<'a> {
    /// The requested URL.
    pub url: &'a Url,
    /// The resource type for which this request was initiated.
    pub resource_type: ResourceType,
    /// The relationship of this request to the originating document.
    pub load_type: LoadType,
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

/// A potential list of resource types being requested.
#[derive(Clone, Debug, PartialEq)]
pub enum ResourceTypeList {
    /// All possible types.
    All,
    /// An explicit list of resource types.
    List(Vec<ResourceType>)
}

/// The type of load that is being initiated.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum LoadType {
    /// Same-origin with respect to the originating page.
    FirstParty,
    /// Cross-origin with respect to the originating page.
    ThirdParty,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DomainMatcher {
    pub exact: Box<[String]>,
    pub subdomain: Box<[String]>,
}

impl DomainMatcher {
    fn matches(&self, url: &Url) -> bool {
        let domain = match url.domain() {
            Some(domain) => domain,
            None => return false,
        };
        for candidate in &*self.exact {
            if domain == candidate {
                return true;
            }
        }
        for suffix in &*self.subdomain {
            match domain.len().cmp(&suffix.len()) {
                Ordering::Equal if domain == suffix => return true,
                Ordering::Greater => {
                    if domain.as_bytes()[domain.len() - suffix.len() - 1] == b'.' {
                        if domain.ends_with(suffix) {
                            return true;
                        }
                    }
                }
                _ => {}
            }
        }
        false
    }
}

/// Conditions which restrict the set of matches for a particular trigger.
#[derive(Clone, Debug, PartialEq)]
pub enum DomainConstraint {
    /// Only trigger if the domain matches one of the included strings.
    If(DomainMatcher),
    /// Trigger unless the domain matches one of the included strings.
    Unless(DomainMatcher),
}

/// A set of filters that determine if a given rule's action is performed.
#[derive(Clone, Debug, PartialEq)]
pub struct Trigger {
    /// A simple regex that is matched against the characters in the destination resource's URL.
    pub url_filter: Regex,
    /// The classes of resources for which this trigger matches.
    pub resource_type: ResourceTypeList,
    /// The category of loads for which this trigger matches.
    pub load_type: Option<LoadType>,
    /// Domains which modify the behaviour of this trigger, either specifically including or
    /// excluding from the matches based on string comparison.
    pub domain_constraint: Option<DomainConstraint>,
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

        if self.url_filter.is_match(request.url.as_str()) {
            match self.domain_constraint {
                Some(DomainConstraint::If(ref matcher)) => {
                    return matcher.matches(&request.url);
                }
                Some(DomainConstraint::Unless(ref matcher)) => {
                    return !matcher.matches(&request.url);
                }
                None => return true,
            }
        }

        false
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
}

#[derive(Clone, Debug, PartialEq)]
/// A single rule, consisting of a condition to trigger this rule, and an action to take.
pub struct Rule {
    pub trigger: Trigger,
    pub action: Action,
}


/// Attempt to match the given request against the provided rules. Returns a list
/// of actions to take in response; an empty list means that the request should
/// continue unmodified.
pub fn process_rules_for_request_impl(rules: &[Rule], request: &Request) -> Vec<Reaction> {
    let mut reactions = vec![];
    for rule in rules {
        if rule.trigger.matches(request) {
            rule.action.process(&mut reactions);
        }
    }
    reactions
}
