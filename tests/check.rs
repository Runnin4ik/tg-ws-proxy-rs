use clap::Parser;

use tg_ws_proxy_rs::check::run_check_with_outbound;
use tg_ws_proxy_rs::config::Config;

mod common;

use common::{
    await_proxy_request, await_unit_task, mtproto_acceptor, rejecting_http_proxy,
    tunneling_http_proxy,
};

/// Build a `--check` config that routes through `proxy_addr` and disables
/// environment proxy discovery so the test is not affected by the host's
/// `HTTPS_PROXY` / `NO_PROXY` settings.
fn check_config(proxy_addr: &str, extra: &[&str]) -> Config {
    let mut args = vec![
        "tg-ws-proxy",
        "--check",
        "--outbound-proxy",
        proxy_addr,
        "--no-outbound-proxy",
        "--no-proxy",
        "",
        "--cf-connect-timeout",
        "2",
        "--upstream-connect-timeout",
        "2",
    ];
    args.extend_from_slice(extra);

    // Same normalization the binary applies before running a check.
    Config::try_parse_from(args).unwrap().with_defaults()
}

#[tokio::test]
async fn check_reports_success_when_there_is_nothing_configured() {
    let config = Config::try_parse_from(["tg-ws-proxy", "--check"]).unwrap();
    let outbound = config.outbound_connector().unwrap();

    assert!(run_check_with_outbound(&config, &outbound).await);
}

#[tokio::test]
async fn check_cf_domain_honors_disabled_tls() {
    let (proxy_addr, proxy_task) = rejecting_http_proxy().await;
    let config = check_config(
        &format!("http://{proxy_addr}"),
        &["--cf-domain", "example.net", "--cf-disable-tls"],
    );
    let outbound = config.outbound_connector().unwrap();

    assert!(!run_check_with_outbound(&config, &outbound).await);
    let request = await_proxy_request(proxy_task).await;
    assert!(request.starts_with("CONNECT kws2.example.net:80 HTTP/1.1"));
}

#[tokio::test]
async fn check_cf_worker_probes_the_dc2_tunnel_through_the_outbound_proxy() {
    let (proxy_addr, proxy_task) = rejecting_http_proxy().await;
    let config = check_config(
        &format!("http://{proxy_addr}"),
        &["--cf-worker-domain", "https://worker.example.dev/"],
    );
    let outbound = config.outbound_connector().unwrap();

    assert!(!run_check_with_outbound(&config, &outbound).await);
    // The scheme and trailing slash are normalized away before the connect.
    let request = await_proxy_request(proxy_task).await;
    assert!(request.starts_with("CONNECT worker.example.dev:443 HTTP/1.1"));
}

#[tokio::test]
async fn check_upstream_mtproto_uses_outbound_proxy() {
    let (proxy_addr, proxy_task) = rejecting_http_proxy().await;
    let config = check_config(
        &format!("http://{proxy_addr}"),
        &[
            "--mtproto-proxy",
            "upstream.example:443:00112233445566778899aabbccddeeff",
        ],
    );
    let outbound = config.outbound_connector().unwrap();

    assert!(!run_check_with_outbound(&config, &outbound).await);
    let request = await_proxy_request(proxy_task).await;
    assert!(request.starts_with("CONNECT upstream.example:443 HTTP/1.1"));
}

#[tokio::test]
async fn check_upstream_mtproto_successfully_tunnels_through_proxy() {
    let (upstream, upstream_task) = mtproto_acceptor().await;
    let (proxy_addr, proxy_task) = tunneling_http_proxy(upstream).await;
    let config = check_config(
        &format!("http://{proxy_addr}"),
        &[
            "--mtproto-proxy",
            "upstream.example:443:00112233445566778899aabbccddeeff",
        ],
    );
    let outbound = config.outbound_connector().unwrap();

    assert!(run_check_with_outbound(&config, &outbound).await);
    let request = await_proxy_request(proxy_task).await;
    assert!(request.starts_with("CONNECT upstream.example:443 HTTP/1.1"));
    await_unit_task(upstream_task).await;
}

#[tokio::test]
async fn check_fails_fast_on_an_invalid_upstream_secret() {
    // `--mtproto-proxy` validates the hex at parse time, so an odd-length
    // secret must never reach the probe.
    let parsed = Config::try_parse_from([
        "tg-ws-proxy",
        "--check",
        "--mtproto-proxy",
        "upstream.example:443:not-hex",
    ]);

    assert!(parsed.is_err());
}

/// The listener probe fails when the listener accepts the connection and never
/// answers: a handshake that was merely accepted is not a working proxy.
#[tokio::test]
async fn check_listener_fails_when_nothing_answers() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let held = tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
        // Hold the connection open, so the probe has to time out instead of
        // reading a close.
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    });

    let config = Config::try_parse_from([
        "tg-ws-proxy",
        "--check",
        "--check-listener",
        "--no-outbound-proxy",
        "--host",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--secret",
        "00112233445566778899aabbccddeeff",
        "--handshake-timeout",
        "1",
    ])
    .unwrap()
    .with_defaults();
    let outbound = config.outbound_connector().unwrap();

    assert!(!run_check_with_outbound(&config, &outbound).await);
    held.abort();
}

/// A listener configured for FakeTLS camouflage is skipped rather than failed:
/// the plain probe cannot speak to it, and a failure would blame a config that
/// works for its clients.
#[tokio::test]
async fn check_listener_skips_a_faketls_listener() {
    let config = Config::try_parse_from([
        "tg-ws-proxy",
        "--check",
        "--check-listener",
        "--listen-faketls-domain",
        "www.example.com",
        "--secret",
        "ee00112233445566778899aabbccddeeff7777772e6578616d706c652e636f6d",
    ])
    .unwrap()
    .with_defaults();
    let outbound = config.outbound_connector().unwrap();

    assert!(run_check_with_outbound(&config, &outbound).await);
}
