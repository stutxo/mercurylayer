use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use anyhow::{ensure, Context, Result};

use super::report::Route;
use super::route_lexer::{balanced, lex, Token};

const MERCURY_MOUNTS: &[&str] = &[
    "endpoints::deposit::post_deposit",
    "endpoints::deposit::get_token",
    "endpoints::bip448_sign::bip448_sign_first",
    "endpoints::bip448_sign::bip448_sign_second",
    "endpoints::bip448_sign::bip448_signature_count",
    "endpoints::lightning_latch::get_paymenthash",
    "endpoints::lightning_latch::post_paymenthash",
    "endpoints::lightning_latch::transfer_preimage",
    "endpoints::transfer_sender::transfer_sender",
    "endpoints::transfer_sender::transfer_update_msg",
    "endpoints::transfer_receiver::get_msg_addr",
    "endpoints::transfer_receiver::statechain_info",
    "endpoints::transfer_receiver::transfer_unlock",
    "endpoints::transfer_receiver::transfer_receiver",
    "endpoints::withdraw::withdraw_complete",
    "utils::info_config",
    "all_options",
];
const TOKEN_MOUNTS: &[&str] = &[
    "endpoints::token::token_verify",
    "endpoints::token::token_gen",
    "all_options",
];
const EXPECTED_MERCURY_TOKEN: &[(&str, &str, &str, &str)] = &[
    (
        "mercury",
        "bip448_sign_first",
        "POST",
        "/bip448-statechain/sign/first",
    ),
    (
        "mercury",
        "bip448_sign_second",
        "POST",
        "/bip448-statechain/sign/second",
    ),
    (
        "mercury",
        "bip448_signature_count",
        "GET",
        "/bip448-statechain/signature-count/<statechain_id>",
    ),
    ("mercury", "get_token", "GET", "/deposit/get_token"),
    ("mercury", "post_deposit", "POST", "/deposit/init/pod"),
    ("mercury", "info_config", "GET", "/info/config"),
    (
        "mercury",
        "statechain_info",
        "GET",
        "/info/statechain/<statechain_id>",
    ),
    (
        "mercury",
        "get_msg_addr",
        "GET",
        "/transfer/get_msg_addr/<new_auth_key>",
    ),
    (
        "mercury",
        "post_paymenthash",
        "POST",
        "/transfer/paymenthash",
    ),
    (
        "mercury",
        "get_paymenthash",
        "GET",
        "/transfer/paymenthash/<batch_id>",
    ),
    ("mercury", "transfer_receiver", "POST", "/transfer/receiver"),
    ("mercury", "transfer_sender", "POST", "/transfer/sender"),
    (
        "mercury",
        "transfer_preimage",
        "POST",
        "/transfer/transfer_preimage",
    ),
    ("mercury", "transfer_unlock", "POST", "/transfer/unlock"),
    (
        "mercury",
        "transfer_update_msg",
        "POST",
        "/transfer/update_msg",
    ),
    ("mercury", "withdraw_complete", "POST", "/withdraw/complete"),
    ("token", "token_gen", "GET", "/token/token_gen"),
    (
        "token",
        "token_verify",
        "GET",
        "/token/token_verify/<token_id>",
    ),
];
const EXPECTED_LOCKBOX: &[(&str, &str)] = &[
    ("GET", "/"),
    ("POST", "/get_public_key"),
    ("POST", "/bip448/get_public_nonce"),
    ("POST", "/bip448/get_partial_signature"),
    ("GET", "/signature_count/<string>"),
    ("POST", "/keyupdate"),
    ("DELETE", "/delete_statechain/<string>"),
];

#[derive(Clone, Debug, PartialEq, Eq)]
struct Declaration {
    mount: String,
    route: Route,
}

pub(super) fn verify(repo_root: &Path) -> Result<(Vec<Route>, Vec<Route>)> {
    let mercury_main = read(repo_root, "server/src/main.rs")?;
    let mercury_sources = [
        (
            "endpoints::deposit",
            read(repo_root, "server/src/endpoints/deposit.rs")?,
        ),
        (
            "endpoints::bip448_sign",
            read(repo_root, "server/src/endpoints/bip448_sign.rs")?,
        ),
        (
            "endpoints::lightning_latch",
            read(repo_root, "server/src/endpoints/lightning_latch.rs")?,
        ),
        (
            "endpoints::transfer_sender",
            read(repo_root, "server/src/endpoints/transfer_sender.rs")?,
        ),
        (
            "endpoints::transfer_receiver",
            read(repo_root, "server/src/endpoints/transfer_receiver.rs")?,
        ),
        (
            "endpoints::withdraw",
            read(repo_root, "server/src/endpoints/withdraw.rs")?,
        ),
        ("utils", read(repo_root, "server/src/endpoints/utils.rs")?),
    ];
    let expected_mercury = expected_routes("mercury");
    let mut routes = verify_rocket(
        "mercury",
        &mercury_main,
        &mercury_sources,
        MERCURY_MOUNTS,
        &expected_mercury,
    )?;

    let token_main = read(repo_root, "token-server-v2/src/main.rs")?;
    let token_sources = [(
        "endpoints::token",
        read(repo_root, "token-server-v2/src/endpoints/token.rs")?,
    )];
    let expected_token = expected_routes("token");
    routes.extend(verify_rocket(
        "token",
        &token_main,
        &token_sources,
        TOKEN_MOUNTS,
        &expected_token,
    )?);
    routes.sort_by(route_order);
    let expected_all = EXPECTED_MERCURY_TOKEN
        .iter()
        .map(|&(service, handler, method, path)| Route {
            service: service.into(),
            handler: handler.into(),
            method: method.into(),
            path: path.into(),
        })
        .collect::<Vec<_>>();
    ensure!(
        routes == expected_all,
        "Mercury/token route inventory drifted"
    );

    let lockbox = parse_crow(&read(repo_root, "lockbox/src/server.cpp")?)?;
    let expected_lockbox = EXPECTED_LOCKBOX
        .iter()
        .enumerate()
        .map(|(index, &(method, path))| Route {
            service: "lockbox".into(),
            handler: format!("crow_route_{index}"),
            method: method.into(),
            path: path.into(),
        })
        .collect::<Vec<_>>();
    ensure!(
        lockbox == expected_lockbox,
        "lockbox route inventory drifted"
    );
    Ok((routes, lockbox))
}

fn read(root: &Path, relative: &str) -> Result<String> {
    fs::read_to_string(root.join(relative)).with_context(|| format!("read route source {relative}"))
}

fn expected_routes(service: &str) -> Vec<Route> {
    EXPECTED_MERCURY_TOKEN
        .iter()
        .filter(|entry| entry.0 == service)
        .map(|&(service, handler, method, path)| Route {
            service: service.into(),
            handler: handler.into(),
            method: method.into(),
            path: path.into(),
        })
        .collect()
}

fn verify_rocket(
    service: &str,
    main: &str,
    modules: &[(&str, String)],
    expected_mounts: &[&str],
    expected_routes: &[Route],
) -> Result<Vec<Route>> {
    let mounts = rust_mounts(main)?;
    ensure!(
        mounts
            .iter()
            .map(String::as_str)
            .eq(expected_mounts.iter().copied()),
        "{service} Rocket mount inventory/order drifted"
    );
    let mut declarations = rust_declarations(service, "", main)?;
    for (prefix, source) in modules {
        declarations.extend(rust_declarations(service, prefix, source)?);
    }
    let declaration_mounts = declarations
        .iter()
        .map(|value| value.mount.as_str())
        .collect::<BTreeSet<_>>();
    ensure!(
        declaration_mounts.len() == declarations.len()
            && mounts.iter().map(String::as_str).collect::<BTreeSet<_>>() == declaration_mounts,
        "{service} mounted handlers and lexical route declarations differ"
    );
    let options = declarations
        .iter()
        .filter(|value| value.route.method == "OPTIONS")
        .collect::<Vec<_>>();
    ensure!(
        options.len() == 1
            && options[0].mount == "all_options"
            && options[0].route.handler == "all_options"
            && options[0].route.path == "/<_..>",
        "{service} must have one exact mounted OPTIONS catchall excluded from acceptance count"
    );
    let mut routes = declarations
        .into_iter()
        .filter(|value| value.route.method != "OPTIONS")
        .map(|value| value.route)
        .collect::<Vec<_>>();
    routes.sort_by(route_order);
    ensure!(
        routes == expected_routes,
        "{service} route handler/method/path/cardinality drifted"
    );
    Ok(routes)
}

fn route_order(left: &Route, right: &Route) -> std::cmp::Ordering {
    (&left.service, &left.path, &left.method, &left.handler).cmp(&(
        &right.service,
        &right.path,
        &right.method,
        &right.handler,
    ))
}

fn rust_mounts(source: &str) -> Result<Vec<String>> {
    let tokens = lex(source)?;
    let starts = (0..tokens.len().saturating_sub(2))
        .filter(|&index| {
            matches!(&tokens[index], Token::Ident(value) if value == "routes")
                && tokens[index + 1] == Token::Symbol('!')
                && tokens[index + 2] == Token::Symbol('[')
        })
        .collect::<Vec<_>>();
    ensure!(
        starts.len() == 1,
        "route source must contain one lexical routes! macro"
    );
    let open = starts[0] + 2;
    let close = balanced(&tokens, open, '[', ']')?;
    let mut mounts = Vec::new();
    let mut start = open + 1;
    for end in
        (open + 1..=close).filter(|&index| index == close || tokens[index] == Token::Symbol(','))
    {
        if end > start {
            mounts.push(rust_path(&tokens[start..end])?);
        }
        start = end + 1;
    }
    Ok(mounts)
}

fn rust_path(tokens: &[Token]) -> Result<String> {
    ensure!(!tokens.is_empty(), "empty Rocket mount expression");
    let mut output = String::new();
    for (index, token) in tokens.iter().enumerate() {
        match token {
            Token::Ident(value) if index % 3 == 0 => output.push_str(value),
            Token::Symbol(':') if index % 3 != 0 => output.push(':'),
            _ => anyhow::bail!("unsupported Rocket mount expression"),
        }
    }
    ensure!(
        tokens.len() % 3 == 1 && !output.ends_with(':'),
        "malformed Rocket handler path"
    );
    Ok(output)
}

fn rust_declarations(service: &str, prefix: &str, source: &str) -> Result<Vec<Declaration>> {
    let tokens = lex(source)?;
    let mut declarations = Vec::new();
    let methods = ["get", "post", "put", "delete", "patch", "head", "options"];
    let mut index = 0;
    while index + 3 < tokens.len() {
        let Some(method) = (tokens[index] == Token::Symbol('#')
            && tokens[index + 1] == Token::Symbol('['))
        .then(|| match &tokens[index + 2] {
            Token::Ident(value) if methods.contains(&value.as_str()) => Some(value.clone()),
            _ => None,
        })
        .flatten() else {
            index += 1;
            continue;
        };
        ensure!(
            tokens[index + 3] == Token::Symbol('('),
            "Rocket route attribute lacks arguments"
        );
        let close_args = balanced(&tokens, index + 3, '(', ')')?;
        ensure!(
            tokens.get(close_args + 1) == Some(&Token::Symbol(']')),
            "Rocket route attribute is unterminated"
        );
        let path = tokens[index + 4..close_args]
            .iter()
            .find_map(|token| match token {
                Token::String(value) => Some(value.clone()),
                _ => None,
            })
            .context("Rocket route path is not literal")?;
        let function = (close_args + 2..tokens.len())
            .find(|&offset| matches!(&tokens[offset], Token::Ident(value) if value == "fn"))
            .context("Rocket route lacks following function")?;
        ensure!(
            !tokens[close_args + 2..function].contains(&Token::Symbol('#')),
            "another attribute precedes Rocket handler"
        );
        let handler = match tokens.get(function + 1) {
            Some(Token::Ident(value)) => value.clone(),
            _ => anyhow::bail!("Rocket handler name is absent"),
        };
        let mount = if prefix.is_empty() {
            handler.clone()
        } else {
            format!("{prefix}::{handler}")
        };
        declarations.push(Declaration {
            mount,
            route: Route {
                service: service.into(),
                handler,
                method: method.to_ascii_uppercase(),
                path,
            },
        });
        index = function + 2;
    }
    Ok(declarations)
}

fn parse_crow(source: &str) -> Result<Vec<Route>> {
    let tokens = lex(source)?;
    let mut routes = Vec::new();
    let mut index = 0;
    while index + 1 < tokens.len() {
        if !matches!(&tokens[index], Token::Ident(value) if value == "CROW_ROUTE") {
            index += 1;
            continue;
        }
        ensure!(
            tokens[index + 1] == Token::Symbol('('),
            "Crow route lacks invocation"
        );
        let close = balanced(&tokens, index + 1, '(', ')')?;
        ensure!(
            matches!(tokens.get(index+2), Some(Token::Ident(value)) if value == "app")
                && tokens.get(index + 3) == Some(&Token::Symbol(',')),
            "Crow route app/path grammar drifted"
        );
        let path = match tokens.get(index + 4) {
            Some(Token::String(value)) => value.clone(),
            _ => anyhow::bail!("Crow route path is not literal"),
        };
        ensure!(
            index + 5 == close,
            "Crow route invocation has extra arguments"
        );
        let method = if tokens.get(close + 1) == Some(&Token::Symbol('.'))
            && matches!(tokens.get(close+2), Some(Token::Ident(value)) if value == "methods")
        {
            ensure!(
                tokens.get(close + 3) == Some(&Token::Symbol('(')),
                "Crow methods call is malformed"
            );
            let methods_close = balanced(&tokens, close + 3, '(', ')')?;
            let value = match tokens.get(close + 4) {
                Some(Token::String(value)) => value.clone(),
                _ => anyhow::bail!("Crow method is not literal"),
            };
            ensure!(
                matches!(tokens.get(close+5), Some(Token::Ident(suffix)) if suffix == "_method")
                    && close + 6 == methods_close,
                "Crow method literal suffix drifted"
            );
            value
        } else {
            "GET".into()
        };
        ensure!(
            matches!(method.as_str(), "GET" | "POST" | "DELETE"),
            "unsupported Crow method"
        );
        routes.push(Route {
            service: "lockbox".into(),
            handler: format!("crow_route_{}", routes.len()),
            method,
            path,
        });
        index = close + 1;
    }
    Ok(routes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_protected_sources_have_exact_lexical_inventory() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
        let (mercury_token, lockbox) = verify(&root).unwrap();
        assert_eq!((mercury_token.len(), lockbox.len()), (18, 7));
    }

    #[test]
    fn comments_and_strings_cannot_supply_or_hide_routes_and_all_drift_fails() {
        let main = "routes![endpoints::x::a,all_options] #[options(\"/<_..>\")] fn all_options(){}";
        let exact = "// #[post(\"/fake\")] fn fake(){}\n const X:&str=\"#[get(/fake)]\"; #[get(\"/a\")] pub async fn a(){}";
        let expected = vec![Route {
            service: "test".into(),
            handler: "a".into(),
            method: "GET".into(),
            path: "/a".into(),
        }];
        verify_rocket(
            "test",
            main,
            &[("endpoints::x", exact.into())],
            &["endpoints::x::a", "all_options"],
            &expected,
        )
        .unwrap();
        for (changed_main, changed_source) in [
            (main.replace("endpoints::x::a,", ""), exact.to_owned()),
            (
                main.to_owned(),
                exact.replace("#[get(\"/a\")]", "// #[get(\"/a\")]"),
            ),
            (
                main.to_owned(),
                exact.replace("#[get(\"/a\")]", "#[post(\"/a\")]"),
            ),
            (main.to_owned(), exact.replace("\"/a\"", "\"/b\"")),
            (
                main.to_owned(),
                format!("{exact} #[get(\"/extra\")] fn extra(){{}}"),
            ),
        ] {
            assert!(verify_rocket(
                "test",
                &changed_main,
                &[("endpoints::x", changed_source)],
                &["endpoints::x::a", "all_options"],
                &expected
            )
            .is_err());
        }
    }

    #[test]
    fn crow_comments_strings_and_method_path_drift_are_lexical() {
        let exact = "// CROW_ROUTE(app,\"/fake\")\n const char*x=\"CROW_ROUTE(app,/fake)\"; CROW_ROUTE(app,\"/\")([]{}); CROW_ROUTE(app,\"/x\").methods(\"POST\"_method)([]{});";
        assert_eq!(parse_crow(exact).unwrap().len(), 2);
        assert!(parse_crow(&exact.replace("\"POST\"_method", "\"PATCH\"_method")).is_err());
        assert_ne!(
            parse_crow(&exact.replace("\"/x\"", "\"/y\"")).unwrap()[1].path,
            "/x"
        );
    }
}
