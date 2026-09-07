//! Entrypoint: environment-driven configuration, then serve forever.

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let config = unidpp_trust::Config::from_env();
    unidpp_trust::run(config).await
}
