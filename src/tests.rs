/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use regex::Regex;
use {Rule, Action, Trigger, Error, LoadType, ResourceType, ResourceTypeList, Exemption, Reaction};
use {DomainExemption, Request, parse_list, process_rules_for_request};

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
        trigger: Trigger::default(),
        action: Action::Block,
    };
    assert_eq!(parse_list("[{ \"trigger\": { \"url-filter\": \"\"}, \"action\": { \"type\": \"block\" } }]"), Ok(vec![rule]));
}

#[test]
fn url_filter_is_case_sensitive() {
    let rule = Rule {
        trigger: Trigger {
            url_filter: Regex::new("(?i)hi").unwrap(),
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
                load_type: Some(type_),
                .. Trigger::default()
            },
            action: Action::Block,
        };
        println!("checking {:?}", type_);
        assert_eq!(parse_list(&format!("[{{ \"trigger\": {{ \"url-filter\": \"\", \
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
                resource_type: ResourceTypeList::List(vec![type_, ResourceType::Document]),
                .. Trigger::default()
            },
            action: Action::Block,
        };
        println!("checking {:?}", type_);
        assert_eq!(parse_list(&format!("[{{ \"trigger\": {{ \"url-filter\": \"\", \
                                        \"resource-type\": [\"{}\", \"document\"]\
                                        }}, \"action\": {{ \"type\": \"block\" }} }}]", name)),
                   Ok(vec![rule]));
    }
}

#[test]
fn if_domain() {
    let rule = Rule {
        trigger: Trigger {
            exemption: Some(Exemption::If(vec![DomainExemption::DomainMatch("domain".to_owned()),
                                               DomainExemption::SubdomainMatch("domain2".to_owned())])),
            .. Trigger::default()
        },
        action: Action::Block,
    };
    assert_eq!(parse_list("[{ \"trigger\": { \"url-filter\": \"\", \
                           \"if-domain\": [\"domain\", \"*domain2\"]\
                           }, \"action\": { \"type\": \"block\" } }]"), Ok(vec![rule]));
}

#[test]
fn unless_domain() {
    let rule = Rule {
        trigger: Trigger {
            exemption: Some(Exemption::Unless(vec![DomainExemption::DomainMatch("domain".to_owned()),
                                                   DomainExemption::SubdomainMatch("domain2".to_owned())])),
            .. Trigger::default()
        },
        action: Action::Block,
    };
    assert_eq!(parse_list("[{ \"trigger\": { \"url-filter\": \"\",\
                           \"unless-domain\": [\"domain\", \"*domain2\"]\
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
            trigger: Trigger::default(),
            action: action.clone(),
        };
        println!("checking {:?}", action);
        assert_eq!(parse_list(&format!("[{{ \"trigger\": {{ \"url-filter\": \"\"\
                                        }}, \"action\": {{ \"type\": \"{}\" }} }}]", name)),
                   Ok(vec![rule]));
    }

    let rule = Rule {
        trigger: Trigger::default(),
        action: Action::CssDisplayNone("selector".to_owned()),
    };
    assert_eq!(parse_list("[{ \"trigger\": { \"url-filter\": \"\"\
                           }, \"action\": { \"type\": \"css-display-none\",\
                           \"selector\": \"selector\" } }]"),
               Ok(vec![rule]));
}

#[test]
fn url_filter_matches() {
    let rule = Rule {
        trigger: Trigger {
            url_filter: Regex::new("http[s]?://domain.org").unwrap(),
            .. Trigger::default()
        },
        action: Action::Block,
    };

    for &(url, expected) in &[("http://domain.org/test/page1.html", &[Reaction::Block][..]),
                              ("https://domain.org/test/page1.html", &[Reaction::Block][..]),
                              ("http://www.domain.org/test/page1.html", &[][..])] {
        let request = Request {
            url: url,
            .. Request::default()
        };
        println!("checking {:?}", url);
        let reactions = process_rules_for_request(&[rule.clone()], &request);
        assert_eq!(reactions, expected);
    }
}

#[test]
fn caseless_url_filter_matches() {
    let rule = Rule {
        trigger: Trigger {
            url_filter: Regex::new("(?i)http[s]?://domain.org").unwrap(),
            .. Trigger::default()
        },
        action: Action::Block,
    };

    for &(url, expected) in &[("http://DOMAIN.ORG/test/page1.html", &[Reaction::Block][..]),
                              ("https://domain.ORG/test/page1.html", &[Reaction::Block][..]),
                              ("http://www.domain.org/test/page1.html", &[][..])] {
        let request = Request {
            url: url,
            .. Request::default()
        };
        println!("checking {:?}", url);
        let reactions = process_rules_for_request(&[rule.clone()], &request);
        assert_eq!(reactions, expected);
    }
}

#[test]
fn resource_type_matches() {
    let rule = Rule {
        trigger: Trigger {
            url_filter: Regex::new("http://domain.org").unwrap(),
            resource_type: ResourceTypeList::List(vec![ResourceType::Media, ResourceType::Raw]),
            .. Trigger::default()
        },
        action: Action::Block,
    };

    for &(type_, expected) in &[(ResourceType::Document, &[][..]),
                                (ResourceType::Media, &[Reaction::Block][..]),
                                (ResourceType::Raw, &[Reaction::Block][..])] {
        let request = Request {
            url: "http://domain.org/test/page1.html",
            resource_type: type_,
            .. Request::default()
        };
        println!("checking {:?}", type_);
        let reactions = process_rules_for_request(&[rule.clone()], &request);
        assert_eq!(reactions, expected);
    }
}

#[test]
fn load_type_matches() {
    let rule = Rule {
        trigger: Trigger {
            url_filter: Regex::new("http://domain.org").unwrap(),
            load_type: Some(LoadType::FirstParty),
            .. Trigger::default()
        },
        action: Action::Block,
    };

    for &(type_, expected) in &[(LoadType::FirstParty, &[Reaction::Block][..]),
                                (LoadType::ThirdParty, &[][..])] {
        let request = Request {
            url: "http://domain.org/test/page1.html",
            load_type: type_,
            .. Request::default()
        };
        println!("checking {:?}", type_);
        let reactions = process_rules_for_request(&[rule.clone()], &request);
        assert_eq!(reactions, expected);
    }
}

#[test]
fn if_domain_matches() {
    let rule = Rule {
        trigger: Trigger {
            url_filter: Regex::new("ad.html").unwrap(),
            exemption: Some(Exemption::If(vec![DomainExemption::DomainMatch("bad.org".to_owned()),
                                               DomainExemption::SubdomainMatch("verybad.org".to_owned())])),
            .. Trigger::default()
        },
        action: Action::Block,
    };

    for &(url, expected) in &[("http://good.org/ad.html", &[][..]),
                              ("http://bad.org/ad.html", &[Reaction::Block][..]),
                              ("http://ok.bad.org/ad.html", &[][..]),
                              ("http://verybad.org/ad.html", &[Reaction::Block][..]),
                              ("http://notok.verybad.org/ad.html", &[Reaction::Block][..])] {
        let request = Request {
            url: url,
            .. Request::default()
        };
        println!("checking {:?}", url);
        let reactions = process_rules_for_request(&[rule.clone()], &request);
        assert_eq!(reactions, expected);
    }
}

#[test]
fn unless_domain_matches() {
    let rule = Rule {
        trigger: Trigger {
            url_filter: Regex::new("ad.html").unwrap(),
            exemption: Some(Exemption::Unless(vec![DomainExemption::DomainMatch("bad.org".to_owned()),
                                                   DomainExemption::SubdomainMatch("verybad.org".to_owned())])),
            .. Trigger::default()
        },
        action: Action::Block,
    };

    for &(url, expected) in &[("http://good.org/ad.html", &[Reaction::Block][..]),
                              ("http://notgood.good.org/ad.html", &[Reaction::Block][..]),
                              ("http://bad.org/ad.html", &[][..]),
                              ("http://ok.bad.org/ad.html", &[Reaction::Block][..]),
                              ("http://verybad.org/ad.html", &[][..]),
                              ("http://notok.verybad.org/ad.html", &[][..])] {
        let request = Request {
            url: url,
            .. Request::default()
        };
        println!("checking {:?}", url);
        let reactions = process_rules_for_request(&[rule.clone()], &request);
        assert_eq!(reactions, expected);
    }
}

#[test]
fn multiple_rules_match() {
    let rules = vec![
        Rule {
            trigger: Trigger {
                url_filter: Regex::new("http://domain.org").unwrap(),
                .. Trigger::default()
            },
            action: Action::Block,
        },
        Rule {
            trigger: Trigger {
                url_filter: Regex::new("http://domain.org/nocookies.sjs").unwrap(),
                .. Trigger::default()
            },
            action: Action::IgnorePreviousRules,
        },
        Rule {
            trigger: Trigger {
                url_filter: Regex::new("http://domain.org/nocookies.sjs").unwrap(),
                .. Trigger::default()
            },
            action: Action::BlockCookies,
        },
        Rule {
            trigger: Trigger {
                url_filter: Regex::new("http://domain.org/hideme.jpg").unwrap(),
                .. Trigger::default()
            },
            action: Action::CssDisplayNone("#adblock".to_owned()),
        },
        Rule {
            trigger: Trigger {
                url_filter: Regex::new("http://domain.org/ok.html").unwrap(),
                .. Trigger::default()
            },
            action: Action::IgnorePreviousRules,
        },
        Rule {
            trigger: Trigger {
                url_filter: Regex::new("http://domain.org/ok.html\\?except_this=1").unwrap(),
                .. Trigger::default()
            },
            action: Action::BlockCookies,
        },
    ];

    for &(url, expected) in &[("http://domain.org/test/page1.html", &[Reaction::Block][..]),
                              ("http://domain.org/nocookies.sjs", &[Reaction::BlockCookies][..]),
                              ("http://domain.org/hideme.jpg", &[Reaction::Block,
                                                                 Reaction::HideMatchingElements("#adblock".to_owned())][..]),
                              ("http://domain.org/ok.html", &[][..]),
                              ("http://domain.org/ok.html?except_this=1", &[Reaction::BlockCookies][..])] {
        let request = Request {
            url: url,
            .. Request::default()
        };
        println!("checking {:?}", url);
        let reactions = process_rules_for_request(&rules, &request);
        assert_eq!(reactions, expected);
    }
}
