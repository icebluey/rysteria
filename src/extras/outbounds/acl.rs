use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use geoip2::{Country as GeoIp2Country, Reader as GeoIp2Reader};
use prost::Message;
use regex::Regex;
use tokio::net::lookup_host;

use crate::extras::outbounds::utils::{
    BoxUdpConn, DirectOutbound, HostResolver, PluggableOutbound, TcpConnResult,
};

const BUILTIN_DIRECT: &str = "direct";
const BUILTIN_REJECT: &str = "reject";
const BUILTIN_DEFAULT: &str = "default";

#[derive(Clone)]
pub struct OutboundEntry {
    pub name: String,
    pub outbound: Arc<dyn PluggableOutbound>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Protocol {
    Both,
    Tcp,
    Udp,
}

#[derive(Clone)]
enum MatchExpr {
    All,
    DomainExact(String),
    DomainSuffix(String),
    DomainWildcard(String),
    Ip(IpAddr),
    Cidr(Cidr),
    GeoIpCountry(String),
    GeoSiteGroup { name: String, attrs: Vec<String> },
}

#[derive(Clone)]
struct Rule {
    line_no: usize,
    outbound_name: String,
    matcher: MatchExpr,
    protocol: Protocol,
    start_port: u16,
    end_port: u16,
    hijack_ip: Option<IpAddr>,
}

pub struct ACLEngine {
    rules: Vec<Rule>,
    outbounds: HashMap<String, Arc<dyn PluggableOutbound>>,
    default: Arc<dyn PluggableOutbound>,
    resolver: Option<Arc<dyn HostResolver>>,
    geoip_db: Option<GeoIpDatabase>,
    geosite_map: HashMap<String, GeoSiteMatcher>,
}

struct GeoIpDatabase {
    bytes: Arc<[u8]>,
}

impl GeoIpDatabase {
    fn match_country(&self, ip: IpAddr, expected_country: &str) -> bool {
        let reader = match GeoIp2Reader::<GeoIp2Country>::from_bytes(self.bytes.as_ref()) {
            Ok(reader) => reader,
            Err(_) => return false,
        };
        match reader.lookup(ip) {
            Ok(country) => country_code_from_lookup(&country)
                .is_some_and(|v: &str| v.eq_ignore_ascii_case(expected_country)),
            Err(_) => false,
        }
    }
}

#[derive(Clone)]
struct GeoSiteMatcher {
    domains: Vec<GeoSiteDomain>,
}

#[derive(Clone)]
struct GeoSiteDomain {
    kind: GeoSiteDomainKind,
    attrs: HashSet<String>,
}

#[derive(Clone)]
enum GeoSiteDomainKind {
    Plain(String),
    Regex(Regex),
    Root(String),
    Full(String),
}

#[derive(Clone)]
struct Cidr {
    network: IpAddr,
    prefix: u8,
}

impl Cidr {
    fn parse(raw: &str) -> io::Result<Self> {
        let (ip_part, prefix_part) = raw.split_once('/').ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("invalid CIDR: {raw}"))
        })?;
        let ip = ip_part.parse::<IpAddr>().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid CIDR IP: {raw}"),
            )
        })?;
        let prefix = prefix_part.parse::<u8>().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid CIDR prefix: {raw}"),
            )
        })?;
        match ip {
            IpAddr::V4(_) if prefix > 32 => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid CIDR prefix: {raw}"),
                ));
            }
            IpAddr::V6(_) if prefix > 128 => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid CIDR prefix: {raw}"),
                ));
            }
            _ => {}
        }
        Ok(Self {
            network: ip,
            prefix,
        })
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(n), IpAddr::V4(v)) => {
                if self.prefix == 0 {
                    return true;
                }
                let mask = u32::MAX << (32 - self.prefix);
                (u32::from(n) & mask) == (u32::from(v) & mask)
            }
            (IpAddr::V6(n), IpAddr::V6(v)) => {
                if self.prefix == 0 {
                    return true;
                }
                let mask = u128::MAX << (128 - self.prefix);
                (u128::from(n) & mask) == (u128::from(v) & mask)
            }
            _ => false,
        }
    }
}

pub fn new_acl_engine_from_string(
    rules: &str,
    outbounds: Vec<OutboundEntry>,
) -> io::Result<Arc<dyn PluggableOutbound>> {
    new_acl_engine_from_string_with_resolver_and_geo(rules, outbounds, None, None, None)
}

pub fn new_acl_engine_from_string_with_resolver(
    rules: &str,
    outbounds: Vec<OutboundEntry>,
    resolver: Option<Arc<dyn HostResolver>>,
) -> io::Result<Arc<dyn PluggableOutbound>> {
    new_acl_engine_from_string_with_resolver_and_geo(rules, outbounds, resolver, None, None)
}

pub fn new_acl_engine_from_string_with_resolver_and_geo(
    rules: &str,
    outbounds: Vec<OutboundEntry>,
    resolver: Option<Arc<dyn HostResolver>>,
    geoip_path: Option<&str>,
    geosite_path: Option<&str>,
) -> io::Result<Arc<dyn PluggableOutbound>> {
    let mut map: HashMap<String, Arc<dyn PluggableOutbound>> = HashMap::new();
    let mut first_user: Option<Arc<dyn PluggableOutbound>> = None;
    for ob in outbounds {
        let key = ob.name.to_ascii_lowercase();
        if first_user.is_none() {
            first_user = Some(Arc::clone(&ob.outbound));
        }
        map.insert(key, ob.outbound);
    }

    if !map.contains_key(BUILTIN_DIRECT) {
        map.insert(
            BUILTIN_DIRECT.to_string(),
            Arc::new(DirectOutbound::default().with_resolver(resolver.clone())),
        );
    }
    map.entry(BUILTIN_REJECT.to_string())
        .or_insert_with(|| Arc::new(RejectOutbound));
    if !map.contains_key(BUILTIN_DEFAULT) {
        let default = first_user
            .unwrap_or_else(|| Arc::new(DirectOutbound::default().with_resolver(resolver.clone())));
        map.insert(BUILTIN_DEFAULT.to_string(), default);
    }

    let default = Arc::clone(map.get(BUILTIN_DEFAULT).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "default outbound must exist")
    })?);

    let parsed_rules = parse_rules(rules)?;

    let need_geoip = parsed_rules
        .iter()
        .any(|rule| matches!(rule.matcher, MatchExpr::GeoIpCountry(_)));
    let need_geosite = parsed_rules
        .iter()
        .any(|rule| matches!(rule.matcher, MatchExpr::GeoSiteGroup { .. }));

    let geoip_db = if need_geoip {
        let path = geoip_path
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "acl contains geoip:* matcher but acl.geoip is empty",
                )
            })?;
        Some(load_geoip_db(path)?)
    } else {
        None
    };

    let geosite_map = if need_geosite {
        let path = geosite_path
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "acl contains geosite:* matcher but acl.geosite is empty",
                )
            })?;
        load_geosite_map(path)?
    } else {
        HashMap::new()
    };

    for rule in &parsed_rules {
        if !map.contains_key(&rule.outbound_name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "error at line {}: outbound {} not found",
                    rule.line_no, rule.outbound_name
                ),
            ));
        }
        match &rule.matcher {
            MatchExpr::GeoIpCountry(_) => {}
            MatchExpr::GeoSiteGroup { name, .. } => {
                if !geosite_map.contains_key(name) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "error at line {}: GeoSite name {name} not found",
                            rule.line_no
                        ),
                    ));
                }
            }
            _ => {}
        }
    }

    Ok(Arc::new(ACLEngine {
        rules: parsed_rules,
        outbounds: map,
        default,
        resolver,
        geoip_db,
        geosite_map,
    }))
}

fn parse_rules(raw: &str) -> io::Result<Vec<Rule>> {
    let mut rules = Vec::new();
    for (idx, source_line) in raw.lines().enumerate() {
        let line_no = idx + 1;
        let line = source_line
            .split_once('#')
            .map(|(left, _)| left)
            .unwrap_or(source_line)
            .trim();
        if line.is_empty() {
            continue;
        }

        let open = line.find('(').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid syntax at line {line_no}: {line}"),
            )
        })?;
        let close = line.rfind(')').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid syntax at line {line_no}: {line}"),
            )
        })?;
        if close != line.len() - 1 || close <= open + 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid syntax at line {line_no}: {line}"),
            ));
        }

        let outbound_name = line[..open].trim().to_ascii_lowercase();
        if outbound_name.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid syntax at line {line_no}: {line}"),
            ));
        }

        let inner = line[open + 1..close].trim();
        let fields: Vec<&str> = inner.split(',').map(str::trim).collect();
        if fields.is_empty() || fields.len() > 3 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid syntax at line {line_no}: {line}"),
            ));
        }
        let address = fields[0];
        let proto_port = fields.get(1).copied().unwrap_or_default();
        let hijack = fields.get(2).copied().unwrap_or_default();

        let matcher = parse_match_expr(address, line_no)?;
        let (protocol, start_port, end_port) = parse_proto_port(proto_port, line_no)?;
        let hijack_ip = if hijack.is_empty() {
            None
        } else {
            Some(hijack.parse::<IpAddr>().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "error at line {line_no}: invalid hijack address (must be IP): {hijack}"
                    ),
                )
            })?)
        };

        rules.push(Rule {
            line_no,
            outbound_name,
            matcher,
            protocol,
            start_port,
            end_port,
            hijack_ip,
        });
    }
    Ok(rules)
}

fn parse_match_expr(raw: &str, line_no: usize) -> io::Result<MatchExpr> {
    let value = raw.to_ascii_lowercase();
    if value.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("error at line {line_no}: empty ACL matcher"),
        ));
    }
    if value == "*" || value == "all" {
        return Ok(MatchExpr::All);
    }
    if let Some(country) = value.strip_prefix("geoip:") {
        let country = country.trim();
        if country.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("error at line {line_no}: empty GeoIP country code"),
            ));
        }
        return Ok(MatchExpr::GeoIpCountry(country.to_string()));
    }
    if let Some(group) = value.strip_prefix("geosite:") {
        let (name, attrs) = parse_geosite_name(group);
        if name.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("error at line {line_no}: empty GeoSite name"),
            ));
        }
        return Ok(MatchExpr::GeoSiteGroup { name, attrs });
    }
    if let Some(suffix) = value.strip_prefix("suffix:") {
        let suffix = suffix.trim().trim_start_matches('.').to_string();
        if suffix.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("error at line {line_no}: empty domain suffix"),
            ));
        }
        return Ok(MatchExpr::DomainSuffix(suffix));
    }
    if value.contains('/') {
        return Ok(MatchExpr::Cidr(Cidr::parse(&value)?));
    }
    if let Ok(ip) = value.parse::<IpAddr>() {
        return Ok(MatchExpr::Ip(ip));
    }
    if value.contains('*') {
        return Ok(MatchExpr::DomainWildcard(value));
    }
    Ok(MatchExpr::DomainExact(value))
}

fn parse_geosite_name(raw: &str) -> (String, Vec<String>) {
    let mut parts = raw.split('@');
    let name = parts.next().unwrap_or("").trim().to_ascii_lowercase();
    let attrs = parts
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(|v| v.to_ascii_lowercase())
        .collect::<Vec<_>>();
    (name, attrs)
}

fn parse_proto_port(raw: &str, line_no: usize) -> io::Result<(Protocol, u16, u16)> {
    let pp = raw.trim().to_ascii_lowercase();
    if pp.is_empty() || pp == "*" || pp == "*/*" {
        return Ok((Protocol::Both, 0, 0));
    }
    if !pp.contains('/') {
        return match pp.as_str() {
            "tcp" => Ok((Protocol::Tcp, 0, 0)),
            "udp" => Ok((Protocol::Udp, 0, 0)),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("error at line {line_no}: invalid protocol/port: {raw}"),
            )),
        };
    }

    let (proto_raw, port_raw) = pp.split_once('/').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("error at line {line_no}: invalid protocol/port: {raw}"),
        )
    })?;
    let protocol = match proto_raw {
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        "*" => Protocol::Both,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("error at line {line_no}: invalid protocol/port: {raw}"),
            ));
        }
    };
    if port_raw == "*" {
        return Ok((protocol, 0, 0));
    }
    if let Some((start, end)) = port_raw.split_once('-') {
        let start_port = start.parse::<u16>().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("error at line {line_no}: invalid protocol/port: {raw}"),
            )
        })?;
        let end_port = end.parse::<u16>().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("error at line {line_no}: invalid protocol/port: {raw}"),
            )
        })?;
        if start_port > end_port {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("error at line {line_no}: invalid protocol/port: {raw}"),
            ));
        }
        return Ok((protocol, start_port, end_port));
    }
    let port = port_raw.parse::<u16>().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("error at line {line_no}: invalid protocol/port: {raw}"),
        )
    })?;
    Ok((protocol, port, port))
}

fn wildcard_match(pattern: &str, host: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let mut remainder = host;
    let mut first = true;
    for part in pattern.split('*') {
        if part.is_empty() {
            continue;
        }
        if first && !pattern.starts_with('*') {
            if !remainder.starts_with(part) {
                return false;
            }
            remainder = &remainder[part.len()..];
            first = false;
            continue;
        }
        if let Some(pos) = remainder.find(part) {
            remainder = &remainder[pos + part.len()..];
        } else {
            return false;
        }
        first = false;
    }
    if pattern.ends_with('*') {
        true
    } else {
        remainder.is_empty()
    }
}

fn parse_req_addr(req_addr: &str) -> (String, u16, Option<IpAddr>) {
    if let Ok(sa) = req_addr.parse::<SocketAddr>() {
        let ip = sa.ip();
        return (ip.to_string(), sa.port(), Some(ip));
    }
    if let Some((host, port)) = req_addr.rsplit_once(':') {
        if let Ok(port) = port.parse::<u16>() {
            let host = host
                .trim_matches('[')
                .trim_matches(']')
                .to_ascii_lowercase();
            let parsed_ip = host.parse::<IpAddr>().ok();
            return (host, port, parsed_ip);
        }
    }
    let host = req_addr.to_ascii_lowercase();
    let parsed_ip = host.parse::<IpAddr>().ok();
    (host, 0, parsed_ip)
}

async fn resolve_host_ips(
    resolver: Option<&Arc<dyn HostResolver>>,
    host: &str,
    port: u16,
) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    let mut seen = HashSet::new();
    if let Ok(ip) = host.parse::<IpAddr>() {
        return vec![ip];
    }
    if let Some(resolver) = resolver {
        if let Ok(resolved) = resolver.resolve(host).await {
            if let Some(ip) = resolved.ipv4.map(IpAddr::V4)
                && seen.insert(ip)
            {
                ips.push(ip);
            }
            if let Some(ip) = resolved.ipv6.map(IpAddr::V6)
                && seen.insert(ip)
            {
                ips.push(ip);
            }
            if !ips.is_empty() {
                return ips;
            }
        }
    }
    if let Ok(iter) = lookup_host((host, port)).await {
        for addr in iter {
            let ip = addr.ip();
            if seen.insert(ip) {
                ips.push(ip);
            }
        }
    }
    ips
}

fn country_code_from_lookup<'a>(result: &'a GeoIp2Country<'a>) -> Option<&'a str> {
    result
        .country
        .as_ref()
        .and_then(|v| v.iso_code)
        .or_else(|| result.registered_country.as_ref().and_then(|v| v.iso_code))
}

fn geoip_match(
    db: &GeoIpDatabase,
    expected_country: &str,
    host_ip: Option<IpAddr>,
    resolved: &[IpAddr],
) -> bool {
    let check_ip = |ip: IpAddr| -> bool { db.match_country(ip, expected_country) };

    if let Some(ip) = host_ip
        && check_ip(ip)
    {
        return true;
    }
    resolved.iter().copied().any(check_ip)
}

fn geosite_match(matcher: &GeoSiteMatcher, host: &str, required_attrs: &[String]) -> bool {
    for domain in &matcher.domains {
        if !required_attrs.is_empty()
            && required_attrs
                .iter()
                .any(|attr| !domain.attrs.contains(attr))
        {
            continue;
        }
        let matched = match &domain.kind {
            GeoSiteDomainKind::Plain(v) => host.contains(v),
            GeoSiteDomainKind::Regex(v) => v.is_match(host),
            GeoSiteDomainKind::Root(v) => host == v || host.ends_with(&format!(".{v}")),
            GeoSiteDomainKind::Full(v) => host == v,
        };
        if matched {
            return true;
        }
    }
    false
}

impl ACLEngine {
    fn match_proto_and_port(rule: &Rule, proto: Protocol, port: u16) -> bool {
        if rule.protocol != Protocol::Both && rule.protocol != proto {
            return false;
        }
        if rule.start_port != 0 && (port < rule.start_port || port > rule.end_port) {
            return false;
        }
        true
    }

    fn match_host(rule: &Rule, host: &str, host_ip: Option<IpAddr>, resolved: &[IpAddr]) -> bool {
        match &rule.matcher {
            MatchExpr::All => true,
            MatchExpr::DomainExact(exact) => host == exact,
            MatchExpr::DomainSuffix(suffix) => {
                host == suffix || host.ends_with(&format!(".{suffix}"))
            }
            MatchExpr::DomainWildcard(pattern) => wildcard_match(pattern, host),
            MatchExpr::Ip(ip) => {
                if let Some(hip) = host_ip {
                    if hip == *ip {
                        return true;
                    }
                }
                resolved.iter().any(|resolved_ip| resolved_ip == ip)
            }
            MatchExpr::Cidr(cidr) => {
                if let Some(hip) = host_ip {
                    if cidr.contains(hip) {
                        return true;
                    }
                }
                resolved
                    .iter()
                    .any(|resolved_ip| cidr.contains(*resolved_ip))
            }
            MatchExpr::GeoIpCountry(_) | MatchExpr::GeoSiteGroup { .. } => false,
        }
    }

    async fn select_outbound(
        &self,
        req_addr: &str,
        proto: Protocol,
    ) -> (Arc<dyn PluggableOutbound>, String) {
        let (host, port, host_ip) = parse_req_addr(req_addr);
        let resolved_ips = if host_ip.is_some() {
            Vec::new()
        } else {
            resolve_host_ips(self.resolver.as_ref(), &host, port).await
        };

        for rule in &self.rules {
            if !Self::match_proto_and_port(rule, proto, port) {
                continue;
            }
            let host_matched = match &rule.matcher {
                MatchExpr::GeoIpCountry(country) => self
                    .geoip_db
                    .as_ref()
                    .map(|db| geoip_match(db, country, host_ip, &resolved_ips))
                    .unwrap_or(false),
                MatchExpr::GeoSiteGroup { name, attrs } => self
                    .geosite_map
                    .get(name)
                    .map(|m| geosite_match(m, &host, attrs))
                    .unwrap_or(false),
                _ => Self::match_host(rule, &host, host_ip, &resolved_ips),
            };
            if !host_matched {
                continue;
            }

            let outbound = match self.outbounds.get(&rule.outbound_name) {
                Some(ob) => Arc::clone(ob),
                None => continue,
            };
            let rewritten_addr = if let Some(ip) = rule.hijack_ip {
                match ip {
                    IpAddr::V4(v4) => SocketAddr::new(IpAddr::V4(v4), port).to_string(),
                    IpAddr::V6(v6) => SocketAddr::new(IpAddr::V6(v6), port).to_string(),
                }
            } else {
                req_addr.to_string()
            };
            return (outbound, rewritten_addr);
        }

        (Arc::clone(&self.default), req_addr.to_string())
    }
}

#[async_trait]
impl PluggableOutbound for ACLEngine {
    async fn tcp(&self, req_addr: &str) -> io::Result<TcpConnResult> {
        let (ob, rewritten) = self.select_outbound(req_addr, Protocol::Tcp).await;
        ob.tcp(&rewritten).await
    }

    async fn udp(&self, req_addr: &str) -> io::Result<BoxUdpConn> {
        let (ob, rewritten) = self.select_outbound(req_addr, Protocol::Udp).await;
        ob.udp(&rewritten).await
    }
}

struct RejectOutbound;

#[async_trait]
impl PluggableOutbound for RejectOutbound {
    async fn tcp(&self, _req_addr: &str) -> io::Result<TcpConnResult> {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "rejected"))
    }

    async fn udp(&self, _req_addr: &str) -> io::Result<BoxUdpConn> {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "rejected"))
    }
}

fn load_geoip_db(path: &str) -> io::Result<GeoIpDatabase> {
    let bytes: Arc<[u8]> = Arc::from(fs::read(path)?.into_boxed_slice());
    GeoIp2Reader::<GeoIp2Country>::from_bytes(bytes.as_ref()).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to parse geoip mmdb file: {err:?}"),
        )
    })?;
    Ok(GeoIpDatabase { bytes })
}

fn load_geosite_map(path: &str) -> io::Result<HashMap<String, GeoSiteMatcher>> {
    let buf = fs::read(path)?;
    let list = GeoSiteListProto::decode(buf.as_slice()).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to parse geosite file: {err}"),
        )
    })?;
    let mut map = HashMap::<String, GeoSiteMatcher>::new();
    for entry in list.entry {
        let name = entry.country_code.to_ascii_lowercase();
        let dst = map.entry(name).or_insert_with(|| GeoSiteMatcher {
            domains: Vec::new(),
        });
        for domain in entry.domain {
            let attrs = domain
                .attribute
                .into_iter()
                .map(|attr| attr.key.to_ascii_lowercase())
                .collect::<HashSet<_>>();
            let kind = match GeoSiteDomainTypeProto::try_from(domain.r#type).ok() {
                Some(GeoSiteDomainTypeProto::Plain) => {
                    GeoSiteDomainKind::Plain(domain.value.to_ascii_lowercase())
                }
                Some(GeoSiteDomainTypeProto::Regex) => {
                    let re = Regex::new(&domain.value).map_err(|err| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("invalid geosite regex: {err}"),
                        )
                    })?;
                    GeoSiteDomainKind::Regex(re)
                }
                Some(GeoSiteDomainTypeProto::Domain) => {
                    GeoSiteDomainKind::Root(domain.value.to_ascii_lowercase())
                }
                Some(GeoSiteDomainTypeProto::Full) => {
                    GeoSiteDomainKind::Full(domain.value.to_ascii_lowercase())
                }
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unsupported geosite domain type",
                    ));
                }
            };
            dst.domains.push(GeoSiteDomain { kind, attrs });
        }
    }
    Ok(map)
}

#[derive(Clone, PartialEq, Message)]
struct GeoSiteListProto {
    #[prost(message, repeated, tag = "1")]
    entry: Vec<GeoSiteProto>,
}

#[derive(Clone, PartialEq, Message)]
struct GeoSiteProto {
    #[prost(string, tag = "1")]
    country_code: String,
    #[prost(message, repeated, tag = "2")]
    domain: Vec<GeoSiteDomainProto>,
}

#[derive(Clone, PartialEq, Message)]
struct GeoSiteDomainProto {
    #[prost(enumeration = "GeoSiteDomainTypeProto", tag = "1")]
    r#type: i32,
    #[prost(string, tag = "2")]
    value: String,
    #[prost(message, repeated, tag = "3")]
    attribute: Vec<GeoSiteDomainAttributeProto>,
}

#[derive(Clone, PartialEq, Message)]
struct GeoSiteDomainAttributeProto {
    #[prost(string, tag = "1")]
    key: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
enum GeoSiteDomainTypeProto {
    Plain = 0,
    Regex = 1,
    Domain = 2,
    Full = 3,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn parse_proto_port_accepts_variants() {
        let (p, s, e) = parse_proto_port("*", 1).unwrap();
        assert!(matches!(p, Protocol::Both));
        assert_eq!(s, 0);
        assert_eq!(e, 0);

        let (p, s, e) = parse_proto_port("tcp/443", 1).unwrap();
        assert!(matches!(p, Protocol::Tcp));
        assert_eq!(s, 443);
        assert_eq!(e, 443);

        let (p, s, e) = parse_proto_port("udp/1000-2000", 1).unwrap();
        assert!(matches!(p, Protocol::Udp));
        assert_eq!(s, 1000);
        assert_eq!(e, 2000);
    }

    #[test]
    fn wildcard_match_supports_prefix_suffix() {
        assert!(wildcard_match("*.example.com", "api.example.com"));
        assert!(wildcard_match("foo*", "foobar"));
        assert!(wildcard_match("*bar", "foobar"));
        assert!(!wildcard_match("*.example.com", "example.net"));
    }

    #[test]
    fn compile_fails_when_outbound_missing() {
        let outbounds = vec![OutboundEntry {
            name: "default".to_string(),
            outbound: Arc::new(DirectOutbound::default()),
        }];
        let err = new_acl_engine_from_string("missing(all)", outbounds)
            .err()
            .expect("missing outbound should fail");
        assert!(err.to_string().contains("outbound missing not found"));
    }

    #[test]
    fn parse_hijack_address() {
        let rules = parse_rules("default(all,udp/53,1.1.1.1)").unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].start_port, 53);
        assert_eq!(rules[0].end_port, 53);
        assert_eq!(
            rules[0].hijack_ip,
            Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))
        );
    }
}
