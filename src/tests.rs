/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use {Rule, Action, Trigger, Error, LoadType, ResourceType, ResourceTypeList, Exemption, Reaction};
use {Request, parse_list, process_rules_for_request};

#[test]
fn invalid_json_format() {
    assert_eq!(parse_list("whee.fun"), Err(Error::JSON));
    assert_eq!(parse_list("["), Err(Error::JSON));
    assert_eq!(parse_list("{ \"action\": {}, \"trigger\": {} }"), Err(Error::NotAList));
}

#[test]
fn empty_list() {
    assert_eq!(parse_list("[]"), Ok(vec![]));
}

#[test]
fn missing_required_values() {
    assert_eq!(parse_list("[{ \"action\": {} }]"), Ok(vec![]));
    assert_eq!(parse_list("[{ \"action\": 5 }]"), Ok(vec![]));
    assert_eq!(parse_list("[{ \"trigger\": 5 }]"), Ok(vec![]));
    assert_eq!(parse_list("[{ \"trigger\": {} }]"), Ok(vec![]));
    assert_eq!(parse_list("[{ \"trigger\": { \"url-filter\": 5} }]"), Ok(vec![]));
    assert_eq!(parse_list("[{ \"trigger\": { \"url-filter\": \"\"} }]"), Ok(vec![]));
    assert_eq!(parse_list("[{ \"trigger\": { \"url-filter\": \"\"}, \"action\": 5 }]"), Ok(vec![]));
    assert_eq!(parse_list("[{ \"trigger\": { \"url-filter\": \"\"}, \"action\": { \"type\": \"invalid\" } }]"), Ok(vec![]));
    assert_eq!(parse_list("[{ \"trigger\": { \"url-filter\": \"\"}, \"action\": { \"type\": 5 } }]"), Ok(vec![]));
    assert_eq!(parse_list("[{ \"trigger\": { \"url-filter\": \"\"}, \"action\": { \"type\": \"css-display-none\" } }]"), Ok(vec![]));
    assert_eq!(parse_list("[{ \"trigger\": { \"url-filter\": \"\"}, \"action\": { \"type\": \"css-display-none\", \"selector\": 5 } }]"), Ok(vec![]));
}

#[test]
fn missing_defaults() {
    let rule = Rule {
        trigger: Trigger {
            url_filter: "hi".to_owned(),
            .. Trigger::default()
        },
        action: Action::Block,
    };
    assert_eq!(parse_list("[{ \"trigger\": { \"url-filter\": \"hi\"}, \"action\": { \"type\": \"block\" } }]"), Ok(vec![rule]));
}

#[test]
fn url_filter_is_case_sensitive() {
    let rule = Rule {
        trigger: Trigger {
            url_filter: "hi".to_owned(),
            url_filter_is_case_sensitive: true,
            .. Trigger::default()
        },
        action: Action::Block,
    };
    assert_eq!(parse_list("[{ \"trigger\": { \"url-filter\": \"hi\", \"url-filter-is-case-sensitive\": true\
                           }, \"action\": { \"type\": \"block\" } }]"), Ok(vec![rule]));
}

#[test]
fn load_type() {
    for &(type_, ref name) in &[(LoadType::FirstParty, "first-party"),
                                (LoadType::ThirdParty, "third-party")] {
        let rule = Rule {
            trigger: Trigger {
                url_filter: "hi".to_owned(),
                load_type: Some(type_),
                .. Trigger::default()
            },
            action: Action::Block,
        };
        assert_eq!(parse_list(&format!("[{{ \"trigger\": {{ \"url-filter\": \"hi\", \
                                        \"load-type\": [\"{}\"]\
                                        }}, \"action\": {{ \"type\": \"block\" }} }}]", name)),
                   Ok(vec![rule]));
    }
}

#[test]
fn resource_type() {
    for &(type_, ref name) in &[(ResourceType::Document, "document"),
                                (ResourceType::Image, "image"),
                                (ResourceType::StyleSheet, "style-sheet"),
                                (ResourceType::Script, "script"),
                                (ResourceType::Font, "font"),
                                (ResourceType::Raw, "raw"),
                                (ResourceType::SVGDocument, "svg-document"),
                                (ResourceType::Media, "media"),
                                (ResourceType::Popup, "popup")] {
        let rule = Rule {
            trigger: Trigger {
                url_filter: "hi".to_owned(),
                resource_type: ResourceTypeList::List(vec![type_, ResourceType::Document]),
                .. Trigger::default()
            },
            action: Action::Block,
        };
        assert_eq!(parse_list(&format!("[{{ \"trigger\": {{ \"url-filter\": \"hi\", \
                                        \"resource-type\": [\"{}\", \"document\"]\
                                        }}, \"action\": {{ \"type\": \"block\" }} }}]", name)),
                   Ok(vec![rule]));
    }
}

#[test]
fn if_domain() {
    let rule = Rule {
        trigger: Trigger {
            url_filter: "hi".to_owned(),
            exemption: Exemption::If(vec!["domain".to_owned(), "domain2".to_owned()]),
            .. Trigger::default()
        },
        action: Action::Block,
    };
    assert_eq!(parse_list("[{ \"trigger\": { \"url-filter\": \"hi\", \
                           \"if-domain\": [\"domain\", \"domain2\"]\
                           }, \"action\": { \"type\": \"block\" } }]"), Ok(vec![rule]));
}

#[test]
fn unless_domain() {
    let rule = Rule {
        trigger: Trigger {
            url_filter: "hi".to_owned(),
            exemption: Exemption::Unless(vec!["domain".to_owned(), "domain2".to_owned()]),
            .. Trigger::default()
        },
        action: Action::Block,
    };
    assert_eq!(parse_list("[{ \"trigger\": { \"url-filter\": \"hi\",\
                           \"unless-domain\": [\"domain\", \"domain2\"]\
                           }, \"action\": { \"type\": \"block\" } }]"), Ok(vec![rule]));
}

#[test]
fn if_unless_domain() {
    assert_eq!(parse_list("[{ \"trigger\": { \"url-filter\": \"hi\", \
                           \"if-domain\": [\"domain\"], \"unless-domain\": [\"domain\"]\
                           }, \"action\": { \"type\": \"block\" } }]"), Ok(vec![]));
}

#[test]
fn action() {
    for &(ref action, ref name) in &[(Action::Block, "block"),
                                     (Action::BlockCookies, "block-cookies"),
                                     (Action::IgnorePreviousRules, "ignore-previous-rules")] {
        let rule = Rule {
            trigger: Trigger {
                url_filter: "hi".to_owned(),
                .. Trigger::default()
            },
            action: action.clone(),
        };
        assert_eq!(parse_list(&format!("[{{ \"trigger\": {{ \"url-filter\": \"hi\"\
                                        }}, \"action\": {{ \"type\": \"{}\" }} }}]", name)),
                   Ok(vec![rule]));
    }

    let rule = Rule {
        trigger: Trigger {
            url_filter: "hi".to_owned(),
            .. Trigger::default()
        },
        action: Action::CssDisplayNone("selector".to_owned()),
    };
    assert_eq!(parse_list("[{ \"trigger\": { \"url-filter\": \"hi\"\
                           }, \"action\": { \"type\": \"css-display-none\",\
                           \"selector\": \"selector\" } }]"),
               Ok(vec![rule]));
}
