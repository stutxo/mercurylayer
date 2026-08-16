#[tokio::main]
async fn main() {
    let mut args = std::env::args_os().skip(1).collect::<Vec<_>>();
    let code = if args.first().and_then(|value| value.to_str()) == Some("__bip448-verify-helper") {
        args.remove(0);
        rust::workflow::run_hidden_verify_helper(args).await
    } else {
        rust::workflow::run(args).await
    };
    if code != rust::workflow::EXIT_SUCCESS {
        std::process::exit(code);
    }
}
