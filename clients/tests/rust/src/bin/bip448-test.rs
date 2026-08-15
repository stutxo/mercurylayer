#[tokio::main]
async fn main() {
    let code = rust::workflow::run(std::env::args_os().skip(1)).await;
    if code != rust::workflow::EXIT_SUCCESS {
        std::process::exit(code);
    }
}
