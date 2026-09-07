// OTA 本地安装服务器（itms-services 路径）。
//
// 原理：签名完成后，本机 HTTPS 服务器（127.0.0.1）托管
//   /SealCA.mobileconfig（一次性信任的本地根 CA 描述文件）
//   /manifest.plist（itms 安装清单）
//   /app.ipa（签名后的 IPA）
// 通过 itms-services:// 协议让 iOS 系统安装器接管安装——
// 完全绕开 minimuxer/隧道/installd 暂存链路，系统级可靠。
//
// 证书体系：App 首次使用时生成自签根证书（CN=Seal Local Root CA），
// 用户安装并信任一次描述文件后，本机回环 HTTPS 永久可信。

use rcgen::{CertificateParams, DnType, KeyPair, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsAcceptor;

pub struct OtaIdentity {
    pub ca_pem: String,
    pub cert_pem: String,
    pub key_pem: String,
}

/// 生成自签根证书 + 服务器叶子证书（SAN: 127.0.0.1 / localhost）
pub fn generate_identity() -> Result<OtaIdentity, String> {
    let ca_key = KeyPair::generate().map_err(|e| e.to_string())?;
    let mut ca_params =
        CertificateParams::new(Vec::new()).map_err(|e| e.to_string())?;
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Seal Local Root CA");
    let ca_cert = ca_params.self_signed(&ca_key).map_err(|e| e.to_string())?;

    let leaf_key = KeyPair::generate().map_err(|e| e.to_string())?;
    let mut leaf_params = CertificateParams::new(vec![]).map_err(|e| e.to_string())?;
    leaf_params
        .subject_alt_names
        .push(SanType::IpAddress(std::net::IpAddr::from([127, 0, 0, 1])));
    leaf_params.subject_alt_names.push(SanType::DnsName(
        "localhost"
            .to_string()
            .try_into()
            .map_err(|e| format!("{e:?}"))?,
    ));
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "127.0.0.1");
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &ca_cert, &ca_key)
        .map_err(|e| e.to_string())?;

    Ok(OtaIdentity {
        ca_pem: ca_cert.pem(),
        cert_pem: leaf_cert.pem(),
        key_pem: leaf_key.serialize_pem(),
    })
}

/// 静态服务配置（FFI configure 时写入）
struct OtaAssets {
    ca_profile: Vec<u8>,
    manifest_path: String,
    ipa_path: String,
    cert_der: CertificateDer<'static>,
    key_der_bytes: Vec<u8>,
    /// fullchain 证书链（leaf + CA），可选。有则优先使用，无则退化为仅 leaf
    fullchain_der: Option<Vec<CertificateDer<'static>>>,
}

static OTA_ASSETS: std::sync::OnceLock<
    std::sync::Mutex<Option<OtaAssets>>,
> = std::sync::OnceLock::new();

fn assets_slot() -> &'static std::sync::Mutex<Option<OtaAssets>> {
    OTA_ASSETS.get_or_init(|| std::sync::Mutex::new(None))
}

/// 配置服务资源（PEM 证书/密钥、清单、IPA 路径、CA 描述文件路径）
/// cert_pem 支持单证书或 fullchain（leaf + CA 拼接），内部自动识别
pub fn configure(
    ca_pem: &str,
    cert_pem: &str,
    key_pem: &str,
    ca_profile: Vec<u8>,
    manifest_path: String,
    ipa_path: String,
) -> Result<(), String> {
    let pem_body = |pem: &str| -> Result<Vec<u8>, String> {
        let body: String = pem
            .lines()
            .filter(|line| !line.contains("-----"))
            .collect();
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(body.trim())
            .map_err(|e| format!("PEM 解码失败: {e}"))
    };
    // 解析 fullchain：cert_pem 可能包含多个证书（leaf + CA）
    let chain = load_cert_chain(cert_pem)?;
    let cert_der = chain.first().cloned().ok_or("证书链为空".to_string())?;
    // 如果链中只有 1 张证书，fullchain = None（退化为旧行为）
    let fullchain_der = if chain.len() > 1 { Some(chain) } else { None };
    let key_der_bytes = pem_body(key_pem).map_err(|e| format!("私钥解析失败: {e}"))?;
    let mut slot = assets_slot().lock().map_err(|e| e.to_string())?;
    *slot = Some(OtaAssets {
        ca_profile,
        manifest_path,
        ipa_path,
        cert_der,
        key_der_bytes,
        fullchain_der,
    });
    Ok(())
}

/// 从 PEM 字符串解析所有证书 DER（支持 fullchain 多证书）
fn load_cert_chain(pem: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let mut certs = Vec::new();
    for line_block in pem.split("-----BEGIN CERTIFICATE-----") {
        let block = line_block.trim();
        if block.is_empty() {
            continue;
        }
        // 去掉尾部 -----END CERTIFICATE-----\n
        let b64 = block
            .split("-----END CERTIFICATE-----")
            .next()
            .unwrap_or(block)
            .lines()
            .filter(|l| !l.contains("-----"))
            .collect::<String>();
        use base64::Engine;
        match base64::engine::general_purpose::STANDARD.decode(b64.trim()) {
            Ok(der) => certs.push(CertificateDer::from(der)),
            Err(_) => continue,
        }
    }
    if certs.is_empty() {
        return Err("证书链中未找到任何证书".into());
    }
    Ok(certs)
}

/// 启动 HTTPS 服务器（绑定 127.0.0.1 随机端口，后台常驻）。
/// 返回分配的端口。
pub async fn serve() -> Result<u16, String> {
    let assets = {
        let slot = assets_slot().lock().map_err(|e| e.to_string())?;
        match slot.as_ref() {
            Some(a) => OtaAssets {
                ca_profile: a.ca_profile.clone(),
                manifest_path: a.manifest_path.clone(),
                ipa_path: a.ipa_path.clone(),
                cert_der: a.cert_der.clone(),
                key_der_bytes: a.key_der_bytes.clone(),
                fullchain_der: a.fullchain_der.clone(),
            },
            None => return Err("OTA 服务尚未配置".into()),
        }
    };

    // 构建证书链：优先从 Swift 侧传入的 fullchain（leaf + CA），回退到单个 leaf
    let cert_chain = assets.fullchain_der.clone().unwrap_or_else(|| vec![assets.cert_der.clone()]);

    let tls_config = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .map_err(|e| format!("TLS 协议版本配置失败: {e}"))?
    .with_no_client_auth()
    .with_single_cert(
        cert_chain,
        PrivateKeyDer::try_from(assets.key_der_bytes.clone())
            .map_err(|e| format!("私钥加载失败: {e:?}"))?,
    )
    .map_err(|e| format!("TLS 配置失败: {e}"))?;

    let acceptor = Arc::new(TlsAcceptor::from(Arc::new(tls_config)));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("端口绑定失败: {e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| e.to_string())?
        .port();

    let ca_profile = Arc::new(assets.ca_profile);
    let manifest_path = Arc::new(assets.manifest_path.clone());
    let ipa_path = Arc::new(assets.ipa_path);

    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                continue;
            };
            let acceptor = Arc::clone(&acceptor);
            let ca_profile = Arc::clone(&ca_profile);
            let manifest_path = Arc::clone(&manifest_path);
            let ipa_path = Arc::clone(&ipa_path);
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let _ = handle_connection(tls, ca_profile, manifest_path, ipa_path).await;
            });
        }
    });

    Ok(port)
}

async fn handle_connection(
    mut stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    ca_profile: Arc<Vec<u8>>,
    manifest_path: Arc<String>,
    ipa_path: Arc<String>,
) -> std::io::Result<()> {
    // 读取请求头（最多 16KB，找到 \r\n\r\n 即可）
    let mut buf = vec![0u8; 16384];
    let mut total = 0;
    while total < buf.len() {
        let n = stream.read(&mut buf[total..]).await?;
        if n == 0 {
            return Ok(());
        }
        total += n;
        if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let head = String::from_utf8_lossy(&buf[..total]).to_string();
    let request_path = head
        .split_whitespace()
        .nth(1)
        .unwrap_or("")
        .split('?')
        .next()
        .unwrap_or("")
        .to_string();

    let (status, content_type, body): (&str, &str, Vec<u8>) = match request_path.as_str() {
        "/manifest.plist" => ("200 OK", "application/xml", tokio::fs::read(manifest_path.as_str()).await.unwrap_or_default()),
        "/app.ipa" => {
            let data = tokio::fs::read(ipa_path.as_str()).await?;
            ("200 OK", "application/octet-stream", data)
        }
        "/SealCA.mobileconfig" => {
            ("200 OK", "application/x-apple-aspen-config", ca_profile.as_ref().clone())
        }
        "/ping" => ("200 OK", "text/plain", b"ok".to_vec()),
        _ => ("404 Not Found", "text/plain", b"not found".to_vec()),
    };

    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.write_all(&body).await?;
    stream.flush().await?;
    Ok(())
}
