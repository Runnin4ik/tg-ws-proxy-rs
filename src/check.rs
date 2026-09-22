//! Connectivity checker for Cloudflare proxy domains and upstream MTProto
//! proxies.
//!
//! Run with `--check` to verify that every configured CF domain and every
//! upstream MTProto proxy can reach Telegram before the proxy starts serving
//! clients.  The check exits with status 0 when all probes pass, or status 1
//! when any probe fails.
//!
//! ## What is tested
//!
//! **CF domain** — A WebSocket connection is attempted through
//! `kws2.{domain}:443`.  A successful HTTP 101 upgrade (status `Connected`)
//! means Cloudflare is correctly routing the WebSocket traffic to Telegram's
//! DC 2 server and the domain is usable by the proxy.
//!
//! **CF Worker** — The Worker's WebSocket tunnel to DC 2 is opened *and* a
//! 64-byte MTProto init is pushed through it.  The upgrade on its own says
//! nothing: the Worker returns `101` before its TCP `connect()` to Telegram is
//! known to have worked, so only the init — and the silence that should follow
//! it — proves the far end is really a DC.
//!
//! **MTProto proxy (plain / 0xdd)** — A TCP connection is made and the
//! 64-byte MTProto obfuscation handshake is sent.  A successful send verifies
//! the proxy is reachable at the network level.
//!
//! **MTProto proxy (FakeTLS / 0xee)** — As above, but a proper TLS ClientHello
//! with HMAC authentication is sent first.  The probe waits for the server's
//! fake TLS handshake response; a successful drain confirms both reachability
//! and correct protocol support.
//!
//! **Own listener** (`--check-listener`) — The probe talks to the listener this
//! config serves on the way a client would: a 64-byte obfuscated handshake,
//! then a real `req_pq_multi`, and the reply has to decrypt to Telegram's
//! `resPQ`.  A handshake the listener merely accepts is not the verdict here,
//! for the same reason the Worker probe sends an init: the listener accepts
//! those 64 bytes before it has anywhere to forward them, so only the DC's
//! answer says the chain — inbound handshake, chosen tier, DC — works.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cipher::StreamCipher;
use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::{Config, MtProtoProxy, default_dc_ip};
use crate::crypto::{self, ProtoTag, generate_client_handshake};
use crate::faketls;
use crate::outbound::OutboundConnector;
use crate::ws_client::{
    connect_cf_worker_ws_for_dc_with_outbound_mode, connect_cf_ws_for_dc_with_outbound_mode,
    ws_recv, ws_send,
};

// ─── Probe result ─────────────────────────────────────────────────────────────

enum ProbeStatus {
    Ok(Duration),
    Fail(String),
}

impl ProbeStatus {
    fn marker(&self) -> &'static str {
        match self {
            Self::Ok(_) => "OK ",
            Self::Fail(_) => "FAIL",
        }
    }

    fn detail(&self) -> String {
        match self {
            Self::Ok(d) => format!("{}ms", d.as_millis()),
            Self::Fail(reason) => reason.clone(),
        }
    }

    fn is_ok(&self) -> bool {
        matches!(self, Self::Ok(_))
    }
}

// ─── Listener probe request ───────────────────────────────────────────────────

/// Telegram's `resPQ` constructor: the answer to `req_pq_multi`, and the only
/// proof that the far end of a tunnel is a data centre rather than a middlebox
/// that accepted the handshake.
const RES_PQ_CTOR: u32 = 0x0516_2463;

/// Byte offset of the constructor in a plain MTProto frame: 4 bytes of frame
/// length, 8 of `auth_key_id`, 8 of message id, 4 of body length.
const FRAME_CTOR_OFFSET: usize = 24;

/// Header of a plain MTProto frame — enough bytes to read the constructor.
const FRAME_HEADER_LEN: usize = FRAME_CTOR_OFFSET + 4;

/// Telegram proxy secrets carry 16 bytes of key.
const SECRET_KEY_LEN: usize = 16;

/// Address to reach our own listener on: the bind address, unless it is a
/// wildcard — which is not a destination.
fn listener_probe_host(config: &Config) -> String {
    match config.bind_host().as_str() {
        "0.0.0.0" | "::" => "127.0.0.1".to_string(),
        host => host.to_string(),
    }
}

/// A `req_pq_multi` request in the padded-intermediate transport.
///
/// This is what a client sends once the obfuscation handshake is done: 8 zero
/// bytes where an established session would carry `auth_key_id`, then the
/// message id, the body length and the body — length-prefixed and padded to a
/// multiple of 4, the shape the splitter reads off the wire.
fn build_req_pq_multi() -> Vec<u8> {
    const REQ_PQ_MULTI_CTOR: u32 = 0xbe7e_8ef1;

    // `unixtime << 32`, as the protocol defines it.  Telegram only needs the id
    // to move forward within a session, and this request is a single one.
    let msg_id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        << 32;

    let mut nonce = [0u8; 16];
    rand::rng().fill_bytes(&mut nonce);

    let mut body = Vec::with_capacity(4 + nonce.len());
    body.extend_from_slice(&REQ_PQ_MULTI_CTOR.to_le_bytes());
    body.extend_from_slice(&nonce);

    let mut packet = Vec::with_capacity(8 + 8 + 4 + body.len());
    packet.extend_from_slice(&[0u8; 8]);
    packet.extend_from_slice(&msg_id.to_le_bytes());
    packet.extend_from_slice(&(body.len() as u32).to_le_bytes());
    packet.extend_from_slice(&body);

    let padding = (4 - packet.len() % 4) % 4;
    let mut frame = Vec::with_capacity(4 + packet.len() + padding);
    frame.extend_from_slice(&((packet.len() + padding) as u32).to_le_bytes());
    frame.extend_from_slice(&packet);
    frame.resize(frame.len() + padding, 0);
    frame
}

/// True when the decrypted reply is Telegram's `resPQ`.
fn reply_is_res_pq(plain: &[u8]) -> bool {
    let Some(header) = plain.get(..FRAME_HEADER_LEN) else {
        return false;
    };

    let mut auth_key_id = [0u8; 8];
    auth_key_id.copy_from_slice(&header[4..12]);
    let mut ctor = [0u8; 4];
    ctor.copy_from_slice(&header[FRAME_CTOR_OFFSET..FRAME_HEADER_LEN]);

    u64::from_le_bytes(auth_key_id) == 0 && u32::from_le_bytes(ctor) == RES_PQ_CTOR
}

// ─── Individual probes ────────────────────────────────────────────────────────

/// Probe a CF domain by attempting a WebSocket connection to DC 2 through it.
///
/// DC 2 is used as a representative data-centre — if the domain is correctly
/// configured in Cloudflare (`kws2.{domain}` A record, orange-cloud, Flexible
/// SSL), this probe will succeed and other DCs should work too.
async fn probe_cf_domain(
    domain: &str,
    skip_tls: bool,
    timeout: Duration,
    outbound: &OutboundConnector,
    disable_tls: bool,
) -> ProbeStatus {
    let start = Instant::now();
    let (ws, _record, _all_redirects) = connect_cf_ws_for_dc_with_outbound_mode(
        2,
        &[domain.to_string()],
        false,
        skip_tls,
        timeout,
        outbound,
        disable_tls,
    )
    .await;
    if ws.is_some() {
        ProbeStatus::Ok(start.elapsed())
    } else {
        ProbeStatus::Fail(
            "WebSocket connection failed — check DNS records and Cloudflare settings".to_string(),
        )
    }
}

/// How long the Worker probe waits for its tunnel to be torn down before
/// calling it healthy.
///
/// Telegram answers the 64-byte init with silence — it only speaks once the
/// client sends a request — so silence *is* the success signal here and the
/// probe can only wait it out.  Long enough to cover a Worker round trip plus
/// the DC handshake, short enough that `--check` stays interactive.
const WORKER_TUNNEL_SETTLE: Duration = Duration::from_secs(3);

/// Probe a Cloudflare Worker by opening its WebSocket tunnel to DC 2 and
/// pushing a real MTProto init through it.
///
/// The WebSocket upgrade alone proves nothing about the tunnel: Cloudflare
/// answers `101` from the Worker script itself, before — and regardless of
/// whether — its `connect()` to the Telegram DC ever succeeds.  A Worker that
/// cannot reach Telegram therefore passed this check while every real client
/// through it died instantly (#93).  Sending the init and watching for a
/// close is what tells the two apart.
async fn probe_cf_worker(
    domain: &str,
    skip_tls: bool,
    timeout: Duration,
    outbound: &OutboundConnector,
    disable_tls: bool,
) -> ProbeStatus {
    let Some(dst) = default_dc_ip(2) else {
        return ProbeStatus::Fail("DC 2 default IP is missing".to_string());
    };

    let start = Instant::now();
    let ws = connect_cf_worker_ws_for_dc_with_outbound_mode(
        domain,
        dst,
        2,
        false,
        skip_tls,
        timeout,
        outbound,
        disable_tls,
    )
    .await;
    let Some(mut ws) = ws else {
        return ProbeStatus::Fail(
            "Worker WebSocket tunnel failed — check Worker code and domain".to_string(),
        );
    };

    let relay_init = crypto::generate_relay_init(ProtoTag::Intermediate, 2);
    if let Err(e) = ws_send(&mut ws, relay_init.to_vec()).await {
        return ProbeStatus::Fail(format!("Worker tunnel closed on send: {}", e));
    }

    // Everything the user cares about timing has happened by now; the settle
    // wait below is a fixed cost of the probe, not latency of the tunnel, and
    // reporting it would make every healthy Worker look three seconds slow.
    let elapsed = start.elapsed();

    // Anything arriving here is the tunnel dying: either a close frame, or a
    // stray payload from something on `dst:443` that is not a Telegram DC.
    match tokio::time::timeout(WORKER_TUNNEL_SETTLE, ws_recv(&mut ws)).await {
        Err(_) => ProbeStatus::Ok(elapsed),
        Ok(None) => ProbeStatus::Fail(format!(
            "Worker tunnel to {} closed immediately — the Worker cannot reach Telegram \
             (check its live logs in the Cloudflare dashboard)",
            dst
        )),
        Ok(Some(data)) => ProbeStatus::Fail(format!(
            "Worker tunnel to {} answered the MTProto init with {} unexpected bytes — \
             the far end is not a Telegram DC",
            dst,
            data.len()
        )),
    }
}

/// Probe an MTProto proxy (plain or FakeTLS) by connecting and sending the
/// MTProto obfuscation handshake.
///
/// For FakeTLS proxies the probe also drains the server's fake TLS handshake,
/// verifying end-to-end protocol negotiation.  For plain proxies a successful
/// TCP connect + handshake send is sufficient to confirm reachability.
async fn probe_mtproto_proxy(
    proxy: &MtProtoProxy,
    timeout: Duration,
    outbound: &OutboundConnector,
) -> ProbeStatus {
    let key_bytes = proxy.secret_key();
    let faketls_hostname = proxy.faketls_hostname();

    let start = Instant::now();

    // ── TCP connect ───────────────────────────────────────────────────────
    let stream = match outbound.connect(&proxy.host, proxy.port, timeout).await {
        Ok(s) => s,
        Err(e) => return ProbeStatus::Fail(format!("TCP connect failed: {}", e)),
    };
    let _ = stream.set_nodelay(true);

    // Use DC index 2 (non-media) as a representative test target.
    let (handshake, _enc, _dec) =
        generate_client_handshake(key_bytes, 2, ProtoTag::PaddedIntermediate);
    let (mut reader, mut writer) = stream.into_split();

    if let Some(hostname) = faketls_hostname {
        // ── FakeTLS path ──────────────────────────────────────────────────
        let mut client_hello = faketls::build_faketls_client_hello(hostname);
        faketls::sign_faketls_client_hello(&mut client_hello, key_bytes);

        if let Err(e) = writer.write_all(&client_hello).await {
            return ProbeStatus::Fail(format!("send FakeTLS ClientHello: {}", e));
        }

        // Drain the server's fake TLS handshake (ServerHello → CCS → AppData).
        let drained =
            tokio::time::timeout(timeout, faketls::drain_faketls_server_hello(&mut reader))
                .await
                .unwrap_or(false);

        if !drained {
            return ProbeStatus::Fail(
                "FakeTLS server handshake failed or timed out — check secret and proxy address"
                    .to_string(),
            );
        }
    } else {
        // ── Plain MTProto path ────────────────────────────────────────────
        if let Err(e) = writer.write_all(&handshake).await {
            return ProbeStatus::Fail(format!("send MTProto handshake: {}", e));
        }
    }

    ProbeStatus::Ok(start.elapsed())
}

/// Probe the listener this config serves on, the way a client would.
///
/// Connects, sends the obfuscation handshake and a real `req_pq_multi`, and
/// requires the reply to decrypt to `resPQ`.  Nothing weaker will do: the
/// listener accepts a handshake before it has anywhere to forward the
/// connection, so a successful send says only that the socket is open — the
/// trap the Worker probe hit in #93.
async fn probe_listener(
    host: &str,
    port: u16,
    secret: &[u8],
    dc_idx: i16,
    timeout: Duration,
    outbound: &OutboundConnector,
) -> ProbeStatus {
    let start = Instant::now();

    let stream = match outbound.connect(host, port, timeout).await {
        Ok(stream) => stream,
        Err(e) => return ProbeStatus::Fail(format!("TCP connect failed: {}", e)),
    };
    let _ = stream.set_nodelay(true);
    let (mut reader, mut writer) = stream.into_split();

    let (handshake, mut enc, mut dec) =
        generate_client_handshake(secret, dc_idx, ProtoTag::PaddedIntermediate);
    if let Err(e) = writer.write_all(&handshake).await {
        return ProbeStatus::Fail(format!("send MTProto handshake: {}", e));
    }

    let mut request = build_req_pq_multi();
    enc.apply_keystream(&mut request);
    if let Err(e) = writer.write_all(&request).await {
        return ProbeStatus::Fail(format!("send req_pq_multi: {}", e));
    }

    // Read until the frame header is complete.  Telegram stays silent until it
    // has the request, and the proxy's pool may still be coming up, so this
    // waits the handshake budget rather than the shorter connect budget.
    let mut plain = Vec::with_capacity(FRAME_HEADER_LEN);
    let mut chunk = [0u8; 256];
    let read = tokio::time::timeout(timeout, async {
        while plain.len() < FRAME_HEADER_LEN {
            match reader.read(&mut chunk).await {
                Ok(0) => break,
                Ok(read) => {
                    dec.apply_keystream(&mut chunk[..read]);
                    plain.extend_from_slice(&chunk[..read]);
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    })
    .await;

    match read {
        Err(_) => ProbeStatus::Fail(format!("no reply within {}s", timeout.as_secs())),
        Ok(Err(e)) => ProbeStatus::Fail(format!("read from listener: {}", e)),
        Ok(Ok(())) if reply_is_res_pq(&plain) => ProbeStatus::Ok(start.elapsed()),
        Ok(Ok(())) => ProbeStatus::Fail(format!(
            "reply is not resPQ ({} bytes received)",
            plain.len()
        )),
    }
}

// ─── Proxy kind label ─────────────────────────────────────────────────────────

fn proxy_kind(proxy: &MtProtoProxy) -> &'static str {
    // Inspect the first byte of the decoded hex secret.
    let first_byte = proxy
        .secret
        .get(..2)
        .and_then(|s| u8::from_str_radix(s, 16).ok());
    match first_byte {
        Some(0xee) => "FakeTLS",
        Some(0xdd) => "padded",
        _ => "plain",
    }
}

// ─── Main entry point ─────────────────────────────────────────────────────────

/// Run the full connectivity check for all configured CF domains and MTProto
/// proxies.
///
/// Prints a human-readable report to stdout.  Returns `true` when every probe
/// passed so that the caller can exit with the appropriate status code.
pub async fn run_check(config: &Config) -> bool {
    let outbound = match config.outbound_connector() {
        Ok(outbound) => outbound,
        Err(e) => {
            eprintln!("Invalid outbound proxy configuration: {e}");
            return false;
        }
    };
    run_check_with_outbound(config, &outbound).await
}

/// Same as [`run_check`], but uses a pre-built outbound connector so callers
/// can share proxy configuration across runtime components.
pub async fn run_check_with_outbound(config: &Config, outbound: &OutboundConnector) -> bool {
    let cf_timeout = Duration::from_secs(config.cf_connect_timeout);
    let upstream_timeout = Duration::from_secs(config.upstream_connect_timeout);
    let skip_tls = config.skip_tls_verify;

    let sep = "=".repeat(60);
    println!("{}", sep);
    println!("  tg-ws-proxy connectivity check");
    println!("{}", sep);

    let cf_worker_domains = config.cf_worker_domains();

    if config.cf_domains.is_empty()
        && cf_worker_domains.is_empty()
        && config.mtproto_proxies.is_empty()
        && !config.check_listener
    {
        println!();
        println!("  Nothing to check.");
        println!(
            "  Configure --cf-domain, --cf-worker-domain, --mtproto-proxy \
             and/or --check-listener and re-run."
        );
        println!("{}", sep);
        return true;
    }

    let mut all_ok = true;

    // ── Cloudflare domain probes ──────────────────────────────────────────
    if !config.cf_domains.is_empty() {
        println!();
        println!("Cloudflare proxy domains (DC2 WebSocket probe):");

        for domain in &config.cf_domains {
            print!("  {:40}  ... ", format!("kws2.{}", domain));
            // Flush so the user sees the label before the potentially slow probe.
            let _ = std::io::Write::flush(&mut std::io::stdout());

            let status = probe_cf_domain(
                domain,
                skip_tls,
                cf_timeout,
                outbound,
                config.cf_disable_tls,
            )
            .await;
            println!("[{}]  {}", status.marker(), status.detail());

            if !status.is_ok() {
                all_ok = false;
            }
        }
    }

    // ── Cloudflare Worker probe ──────────────────────────────────────────
    if !cf_worker_domains.is_empty() {
        println!();
        println!("Cloudflare Worker domains (DC2 TCP tunnel probe):");
        for domain in cf_worker_domains {
            print!("  {:40}  ... ", domain);
            let _ = std::io::Write::flush(&mut std::io::stdout());

            let status = probe_cf_worker(
                domain,
                skip_tls,
                cf_timeout,
                outbound,
                config.cf_disable_tls,
            )
            .await;
            println!("[{}]  {}", status.marker(), status.detail());

            if !status.is_ok() {
                all_ok = false;
            }
        }
    }

    // ── MTProto proxy probes ──────────────────────────────────────────────
    if !config.mtproto_proxies.is_empty() {
        println!();
        println!("Upstream MTProto proxies:");

        for proxy in &config.mtproto_proxies {
            let label = format!("{}:{}  [{}]", proxy.host, proxy.port, proxy_kind(proxy));
            print!("  {:40}  ... ", label);
            let _ = std::io::Write::flush(&mut std::io::stdout());

            let status = probe_mtproto_proxy(proxy, upstream_timeout, outbound).await;
            println!("[{}]  {}", status.marker(), status.detail());

            if !status.is_ok() {
                all_ok = false;
            }
        }
    }

    // ── Own listener probe ────────────────────────────────────────────────
    if config.check_listener {
        println!();
        println!("Own listener (end-to-end MTProto probe):");

        let host = listener_probe_host(config);
        print!("  {:40}  ... ", format!("{}:{}", host, config.port));
        let _ = std::io::Write::flush(&mut std::io::stdout());

        // `normalized_secrets` is already the decoded 16-byte key of each
        // configured secret, with any `dd`/`ee` mode prefix stripped.
        let secret = config
            .normalized_secrets()
            .first()
            .filter(|key| key.len() == SECRET_KEY_LEN);

        // A listener started with `--listen-faketls-domain` reads a TLS record
        // before anything else, so it is skipped rather than failed: the plain
        // probe cannot speak to it, and a failure would blame a config that
        // works for its clients.
        if config.normalized_listen_faketls_domain().is_some() {
            println!("[SKIP]  FakeTLS listener: this probe speaks the plain transport");
        } else if let Some(secret) = secret {
            let status = probe_listener(
                &host,
                config.port,
                secret,
                // DC 2, as in the probes above: a representative data centre.
                2,
                Duration::from_secs(config.handshake_timeout),
                outbound,
            )
            .await;
            println!("[{}]  {}", status.marker(), status.detail());
            if !status.is_ok() {
                all_ok = false;
            }
        } else {
            println!("[FAIL]  no --secret to probe with — pass the one the proxy serves");
            all_ok = false;
        }
    }

    // ── Summary ───────────────────────────────────────────────────────────
    println!();
    println!("{}", sep);
    if all_ok {
        println!("  Result: all checks passed");
    } else {
        println!("  Result: one or more checks FAILED");
    }
    println!("{}", sep);

    all_ok
}

#[cfg(test)]
mod tests;
