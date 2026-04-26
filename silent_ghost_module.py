#!/usr/bin/env python3
# SILENT♕GHOST – وحدة المسح للإستخبارات (نسخة مصححة بالكامل)
import socket, ssl, urllib.parse, urllib.request, json, re, time
import concurrent.futures, sys, ipaddress, itertools

# ---------- CONFIG ----------
COMMON_PORTS = [
    21,22,23,25,53,80,110,111,135,139,143,443,445,
    587,636,873,993,995,1080,1433,1521,1723,2082,2083,
    2181,2375,2483,2484,3306,3389,4000,4567,5000,5432,
    5900,5984,6379,7001,8000,8080,8443,8888,9000,9090,
    9200,9300,10000,11211,27017,27018,28015,50000,50070
]
SCAN_TIMEOUT = 1.5
MAX_WORKERS = 150
REVERSE_IP_DISPLAY_LIMIT = 30

# ---------- HELPERS ----------
def parse_target(user_input):
    if '://' not in user_input:
        user_input = 'http://' + user_input
    parsed = urllib.parse.urlparse(user_input)
    host = parsed.hostname
    if not host:
        parts = user_input.replace('http://','').replace('https://','').split(':')
        host = parts[0]
        port = int(parts[1].split('/')[0]) if len(parts)>1 else 80
    else:
        port = parsed.port or (443 if parsed.scheme=='https' else 80)
    scheme = parsed.scheme if parsed.scheme in ('http','https') else 'http'
    return host, port, scheme

def resolve_host(host):
    try:
        ipaddress.ip_address(host)
        return host, True
    except ValueError:
        pass
    try:
        ip = socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]
        return ip, False
    except socket.gaierror:
        return None, False

def check_port(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(SCAN_TIMEOUT)
    result = sock.connect_ex((host, port))
    sock.close()
    if result == 0: return (port, 'open')
    elif result == 115: return (port, 'filtered')
    else: return (port, 'closed')

def scan_ports(host, ports):
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(ports))) as executor:
        future_to_port = {executor.submit(check_port, host, p): p for p in ports}
        for future in concurrent.futures.as_completed(future_to_port):
            port, state = future.result()
            results[port] = state
    return results

SERVICE_SIGNATURES = {
    21:'FTP', 22:'SSH', 23:'Telnet', 25:'SMTP', 53:'DNS',
    80:'HTTP', 110:'POP3', 143:'IMAP', 443:'HTTPS', 445:'SMB',
    587:'SMTP', 636:'LDAPS', 873:'Rsync', 993:'IMAPS', 995:'POP3S',
    1080:'SOCKS', 1433:'MSSQL', 1521:'Oracle', 1723:'PPTP',
    2082:'cPanel', 2083:'cPanel SSL', 2181:'ZooKeeper', 2375:'Docker',
    2483:'Oracle', 2484:'Oracle SSL', 3306:'MySQL', 3389:'RDP',
    4000:'IRC', 4567:'VNC', 5000:'UPnP', 5432:'PostgreSQL',
    5900:'VNC', 5984:'CouchDB', 6379:'Redis', 7001:'WebLogic',
    8000:'HTTP-alt', 8080:'HTTP-proxy', 8443:'HTTPS-alt',
    8888:'HTTP-alt', 9000:'Web', 9090:'Web', 9200:'Elasticsearch',
    9300:'Elasticsearch', 10000:'Webmin', 11211:'Memcached',
    27017:'MongoDB', 27018:'MongoDB', 28015:'RethinkDB',
    50000:'SAP', 50070:'Hadoop'
}

def detect_service(host, port, timeout=2.0):
    ssl_ports = [443, 636, 993, 995, 8443, 2083, 2484]
    if port in ssl_ports:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cn = None
                    for field in cert.get('subject', []):
                        if field[0][0] == 'commonName':
                            cn = field[0][1]
                            break
                    return f"TLS ({cn})" if cn else "TLS (no CN)"
        except Exception as e:
            return f"TLS error: {e}"
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        banner = b''
        try:
            while len(banner) < 2048:
                data = sock.recv(1024)
                if not data: break
                banner += data
        except socket.timeout:
            pass
        sock.close()
        banner_str = banner.decode('utf-8', errors='ignore').strip()
        service = SERVICE_SIGNATURES.get(port, 'unknown')
        if banner_str:
            bl = banner_str.lower()
            if 'ssh' in bl: service = 'SSH'
            elif 'ftp' in bl: service = 'FTP'
            elif 'mysql' in bl: service = 'MySQL'
            elif 'http' in bl: service = 'HTTP'
            elif 'smtp' in bl: service = 'SMTP'
            elif 'pop3' in bl: service = 'POP3'
            elif 'imap' in bl: service = 'IMAP'
            elif 'redis' in bl: service = 'Redis'
            elif 'mongodb' in bl: service = 'MongoDB'
            elif 'vnc' in bl: service = 'VNC'
        banner_excerpt = banner_str[:60].replace('\n',' ').replace('\r',' ')
        desc = banner_excerpt if banner_excerpt else 'no banner'
        return f"{service} | {desc}"
    except Exception as e:
        return f"error: {e}"

def reverse_ip_hackertarget(ip):
    domains = []
    url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
    try:
        req = urllib.request.Request(url, headers={'User-Agent':'SILENT-GHOST/2099'})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = resp.read().decode('utf-8', errors='ignore')
            if not data.startswith('error') and not data.startswith('API count'):
                domains = [line.strip() for line in data.splitlines() if line.strip()]
    except: pass
    return domains

def reverse_ip_yougetsignal(ip):
    domains = []
    url = f"https://domains.yougetsignal.com/domains.php?remoteAddress={ip}"
    try:
        req = urllib.request.Request(url, headers={'User-Agent':'SILENT-GHOST/2099'})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            if data.get('status') == 'Success':
                for entry in data.get('domainArray', []):
                    domains.append(entry[0])
    except: pass
    return domains

def multi_source_reverse_ip(ip):
    sources = {}
    src1 = reverse_ip_hackertarget(ip)
    sources['hackertarget'] = src1
    src2 = reverse_ip_yougetsignal(ip)
    sources['yougetsignal'] = src2
    return sources

def asn_network_sample(asn_string):
    match = re.match(r'AS(\d+)', asn_string)
    if not match:
        return []
    asn_num = match.group(1)
    url = f"https://api.hackertarget.com/aslookup/?q=AS{asn_num}"
    try:
        req = urllib.request.Request(url, headers={'User-Agent':'SILENT-GHOST/2099'})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = resp.read().decode('utf-8', errors='ignore')
            lines = data.strip().splitlines()
            prefixes = []
            for line in lines[1:]:
                if ':' in line:
                    net = line.split(':')[0]
                    prefixes.append(net)
            return prefixes[:15]
    except: pass
    return []

def subdomain_enum(domain):
    subs = set()
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        req = urllib.request.Request(url, headers={'User-Agent':'SILENT-GHOST/2099'})
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode())
            for entry in data:
                name = entry.get('name_value', '')
                for sub in name.split('\n'):
                    sub = sub.strip().lower()
                    if sub and '*' not in sub:
                        subs.add(sub)
    except: pass
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        req = urllib.request.Request(url, headers={'User-Agent':'SILENT-GHOST/2099'})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = resp.read().decode('utf-8', errors='ignore')
            for line in data.strip().splitlines():
                sub, _ = line.split(',', 1)
                sub = sub.strip().lower()
                if sub and '*' not in sub:
                    subs.add(sub)
    except: pass
    return sorted(subs)

def analyse_firewall(port_results, http_headers=None):
    hints = []
    filtered = [p for p,s in port_results.items() if s=='filtered']
    if filtered: hints.append(f"FW active (filtered:{filtered})")
    else: hints.append("No filtered ports")
    if http_headers:
        server = http_headers.get('Server','').lower()
        if 'cloudflare' in server: hints.append("WAF:Cloudflare")
        if 'awselb' in server: hints.append("WAF:AWS")
        if http_headers.get('X-Sucuri-ID'): hints.append("WAF:Sucuri")
        if 'cf_clearance' in http_headers.get('Set-Cookie',''): hints.append("WAF:Cloudflare")
    return " | ".join(hints) if hints else "Inconclusive"

def grab_http_info(host, port, scheme='http'):
    try:
        if scheme=='https':
            context = ssl.create_default_context()
            sock = socket.create_connection((host,port), timeout=3)
            ssock = context.wrap_socket(sock, server_hostname=host)
            stream = ssock.makefile('rwb')
        else:
            sock = socket.create_connection((host,port), timeout=3)
            stream = sock.makefile('rwb')
        req = f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: SILENT-GHOST/2099\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        stream.write(req.encode()); stream.flush()
        resp = stream.read(8192).decode('utf-8', errors='ignore')
        stream.close(); sock.close()
        header_part, _, body = resp.partition('\r\n\r\n')
        headers = {}
        for line in header_part.split('\r\n')[1:]:
            if ':' in line:
                k,v = line.split(':',1); headers[k.strip()] = v.strip()
        title = re.search(r'<title>(.*?)</title>', body, re.IGNORECASE|re.DOTALL)
        title = title.group(1).strip() if title else None
        tech = []
        if headers.get('Server'): tech.append(f"Srv:{headers['Server']}")
        if headers.get('X-Powered-By'): tech.append(f"X-Pw:{headers['X-Powered-By']}")
        return {'headers':headers, 'title':title, 'technologies':tech}
    except Exception as e:
        return {'error':str(e)}

def geo_info(ip):
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,timezone,isp,org,as,query"
        req = urllib.request.Request(url, headers={'User-Agent':'Architect/2099'})
        resp = urllib.request.urlopen(req, timeout=5)
        data = json.loads(resp.read().decode())
        if data.get('status')=='success':
            return {k:data.get(k) for k in ['ip','country','countryCode','regionName','city','timezone','isp','org','as']}
        else: return {'error':data.get('message','unknown')}
    except Exception as e: return {'error':str(e)}

def dns_records(domain):
    record_types = ['A','AAAA','MX','NS','TXT','CNAME','SOA']
    results = {}
    base = 'https://cloudflare-dns.com/dns-query?name={}&type={}'
    for rtype in record_types:
        try:
            req = urllib.request.Request(base.format(urllib.parse.quote(domain), rtype),
                                        headers={'Accept':'application/dns-json','User-Agent':'Architect/2099'})
            resp = urllib.request.urlopen(req, timeout=5)
            data = json.loads(resp.read().decode())
            if data.get('Status')==0:
                answers = data.get('Answer',[])
                if answers: results[rtype] = [a['data'] for a in answers]
        except: continue
    return results

# ---------- التابع الرئيسي المصحح (تم تغيير اسم الدالة من p إلى add_line) ----------
def shadow_scan(target_input: str) -> str:
    output_lines = []
    # استخدام اسم مختلف تماماً عن متغيرات الحلقات
    add_line = lambda text: output_lines.append(text)

    add_line("👑 SILENT♕GHOST SHADOW REPORT")
    add_line("=" * 30)

    host, port, scheme = parse_target(target_input)
    add_line(f"Target: {host}:{port} ({scheme})")

    ip, is_ip = resolve_host(host)
    if not ip:
        return f"ERROR: Cannot resolve {host}"
    add_line(f"Resolved IP: {ip}")

    geo = geo_info(ip)
    asn_str = geo.get('as', 'N/A')
    if 'error' not in geo:
        add_line(f"Country: {geo.get('country')} ({geo.get('countryCode')})  | City: {geo.get('city')}, {geo.get('regionName')}")
        add_line(f"ISP/Org: {geo.get('isp')} / {geo.get('org')}  | ASN: {asn_str}")
    else:
        add_line(f"Geo: Failed ({geo.get('error')})")

    add_line("\n--- Reverse IP Lookup ---")
    rev_sources = multi_source_reverse_ip(ip)
    all_rev = set()
    for doms in rev_sources.values():
        all_rev.update(doms)
    for src, doms in rev_sources.items():
        if doms:
            add_line(f"  {src}: {', '.join(doms[:REVERSE_IP_DISPLAY_LIMIT])}")
            if len(doms) > REVERSE_IP_DISPLAY_LIMIT:
                add_line(f"    ... and {len(doms)-REVERSE_IP_DISPLAY_LIMIT} more")
        else:
            add_line(f"  {src}: no results")
    add_line(f"Total associated domains: {len(all_rev)}")

    add_line("\n--- ASN Cluster ---")
    prefixes = asn_network_sample(asn_str)
    if prefixes:
        add_line(f"ASN: {asn_str} – Network ranges (sample): {', '.join(prefixes)}")
    else:
        add_line(f"ASN: {asn_str} – (ranges unavailable)")
    if all_rev:
        add_line("Domains on this IP (first 15): " + ', '.join(sorted(all_rev)[:15]))

    add_line("\n--- Port Scanning ---")
    port_results = scan_ports(ip, COMMON_PORTS)
    open_ports = {prt:state for prt,state in port_results.items() if state=='open'}
    if open_ports:
        add_line("Open ports: " + ', '.join(str(prt) for prt in sorted(open_ports)))
    else:
        add_line("No open ports found (stealth mode)")
    filtered_ports = [prt for prt,state in port_results.items() if state=='filtered']
    if filtered_ports:
        add_line(f"Filtered ports: {', '.join(str(prt) for prt in filtered_ports)}")

    if open_ports:
        add_line("\n--- Service Detection ---")
        for this_port in sorted(open_ports.keys()):
            svc = detect_service(ip, this_port)
            add_line(f"  Port {this_port}: {svc}")

    http_data = None
    if port in open_ports or 80 in open_ports or 443 in open_ports:
        add_line("\n--- HTTP Information ---")
        http_data = grab_http_info(host, port, scheme)
        if 'error' in http_data:
            add_line(f"HTTP grab error: {http_data['error']}")
        else:
            if http_data.get('title'):
                add_line(f"Title: {http_data['title']}")
            if http_data.get('technologies'):
                add_line(f"Technologies: {', '.join(http_data['technologies'])}")
            for k,v in http_data.get('headers',{}).items():
                add_line(f"  {k}: {v}")

    subdomains = []
    if not is_ip:
        add_line("\n--- Subdomain Enumeration ---")
        subdomains = subdomain_enum(host)
        if subdomains:
            add_line(f"Found {len(subdomains)} subdomains: {', '.join(subdomains[:25])}")
            if len(subdomains) > 25:
                add_line(f"  ... and {len(subdomains)-25} more")
        else:
            add_line("No subdomains found")

    add_line("\n--- Firewall Heuristics ---")
    fw = analyse_firewall(port_results, http_data['headers'] if http_data and 'headers' in http_data else None)
    add_line(fw)

    if not is_ip:
        add_line("\n--- DNS Records ---")
        dns = dns_records(host)
        if dns:
            for rtype, recs in dns.items():
                for rec in recs:
                    add_line(f"  {rtype}: {rec}")
        else:
            add_line("No DNS records retrieved")

    add_line("\n" + "="*30)
    add_line("✅ SILENT♕GHOST scan complete.")
    return "\n".join(output_lines)
