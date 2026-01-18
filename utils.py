import datetime
import json
import base64
import pytz
import yaml
from croniter import croniter
import uuid
import hashlib
import ipaddress
import re
import ulid
import socket
import ssl
import difflib
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def epoch_to_datetime(epoch_str):
    try:
        epoch = float(epoch_str)
        # Check if milliseconds (13 digits) or seconds (10 digits)
        if epoch > 9999999999:
            epoch /= 1000.0
        
        dt_utc = datetime.datetime.fromtimestamp(epoch, tz=pytz.UTC)
        dt_local = datetime.datetime.fromtimestamp(epoch)
        
        return {
            "utc": dt_utc.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "local": dt_local.strftime("%Y-%m-%d %H:%M:%S Local"),
            "iso": dt_utc.isoformat()
        }
    except Exception as e:
        return {"error": str(e)}

from dateutil import parser as date_parser

def datetime_to_epoch(datetime_str):
    try:
        dt = date_parser.parse(datetime_str)
        
        # If no timezone is provided, assume local or UTC? 
        # SREs usually work with UTC, but let's default to local if not specified, 
        # or just use whatever the parser finds.
        
        epoch = int(dt.timestamp())
        return {
            "seconds": str(epoch),
            "milliseconds": str(epoch * 1000)
        }
    except Exception as e:
        return {"error": f"Could not parse date: {str(e)}"}

def format_json(json_str, indent=4):
    try:
        data = json.loads(json_str)
        return json.dumps(data, indent=indent)
    except Exception as e:
        return f"Error: {str(e)}"

def minify_json(json_str):
    try:
        data = json.loads(json_str)
        return json.dumps(data, separators=(',', ':'))
    except Exception as e:
        return f"Error: {str(e)}"

def base64_encode(data_str):
    try:
        encoded_bytes = base64.b64encode(data_str.encode("utf-8"))
        return encoded_bytes.decode("utf-8")
    except Exception as e:
        return f"Error: {str(e)}"

def base64_decode(data_str):
    try:
        decoded_bytes = base64.b64decode(data_str.encode("utf-8"))
        return decoded_bytes.decode("utf-8")
    except Exception as e:
        return f"Error: {str(e)}"

def get_timezone_time(tz_name):
    try:
        tz = pytz.timezone(tz_name)
        now = datetime.datetime.now(tz)
        return now.strftime("%H:%M:%S")
    except Exception:
        return "--:--:--"

def get_available_timezones():
    return pytz.all_timezones

def milliseconds_to_duration(ms_str):
    try:
        ms = float(ms_str)
        seconds = ms / 1000.0
        minutes = seconds / 60.0
        hours = minutes / 60.0
        days = hours / 24.0
        weeks = days / 7.0
        
        return {
            "hours": f"{hours:.2f} hrs",
            "days": f"{days:.2f} days",
            "weeks": f"{weeks:.2f} weeks"
        }
    except Exception as e:
        return {"error": str(e)}

def jwt_decode(token):
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return {"error": "Invalid JWT format (must have 3 parts)"}
        
        # Helper to pad base64 string
        def pad_b64(s):
            return s + '=' * (-len(s) % 4)

        header = json.loads(base64.urlsafe_b64decode(pad_b64(parts[0])).decode('utf-8'))
        payload = json.loads(base64.urlsafe_b64decode(pad_b64(parts[1])).decode('utf-8'))
        
        return {"header": header, "payload": payload}
    except Exception as e:
        return {"error": str(e)}

def cron_next_runs(cron_str, num_runs=5):
    try:
        base_time = datetime.datetime.now()
        iter = croniter(cron_str, base_time)
        runs = []
        for _ in range(num_runs):
            dt = iter.get_next(datetime.datetime)
            runs.append(dt.strftime("%Y-%m-%d %H:%M:%S"))
        return runs
    except Exception as e:
        return [f"Error: {str(e)}"]

def yaml_to_json(yaml_str):
    try:
        data = yaml.safe_load(yaml_str)
        return json.dumps(data, indent=4)
    except Exception as e:
        return f"Error: {str(e)}"

def json_to_yaml(json_str):
    try:
        data = json.loads(json_str)
        return yaml.dump(data, default_flow_style=False)
    except Exception as e:
        return f"Error: {str(e)}"

def generate_ids():
    return {
        "uuid": str(uuid.uuid4()),
        "ulid": str(ulid.new()),
        "hex": uuid.uuid4().hex
    }

def calculate_hashes(text):
    if not text:
        return {"md5": "", "sha1": "", "sha256": ""}
    data = text.encode('utf-8')
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest()
    }

def calculate_cidr_advanced(ip_str, mask_str=None):
    try:
        # Support both CIDR (49.206.128.42/30) and separate Mask
        if mask_str:
            if mask_str.startswith('/'):
                cidr_str = f"{ip_str}{mask_str}"
            else:
                cidr_str = f"{ip_str}/{mask_str}"
        else:
            cidr_str = ip_str

        network = ipaddress.ip_network(cidr_str, strict=False)
        ip = ipaddress.ip_address(ip_str.split('/')[0])
        
        # Basic Info
        num_hosts = network.num_addresses
        prefix = network.prefixlen
        
        # Usable handling (/31, /32)
        if prefix == 32:
            usable_hosts = 1
            first_ip = str(network.network_address)
            last_ip = str(network.network_address)
        elif prefix == 31:
            usable_hosts = 2
            first_ip = str(network.network_address)
            last_ip = str(network.broadcast_address)
        else:
            usable_hosts = max(0, num_hosts - 2)
            first_ip = str(network.network_address + 1)
            last_ip = str(network.broadcast_address - 1)

        # Binary/Hex/Int
        ip_int = int(ip)
        ip_bin = bin(ip_int)[2:].zfill(32)
        ip_bin_formatted = " ".join([ip_bin[i:i+8] for i in range(0, 32, 8)])
        
        mask_int = int(network.netmask)
        mask_bin = bin(mask_int)[2:].zfill(32)
        mask_bin_formatted = ".".join([mask_bin[i:i+8] for i in range(0, 32, 8)])

        # Wildcard
        wildcard_int = int(network.hostmask)
        wildcard_str = str(network.hostmask)

        # IP Class
        first_octet = int(str(ip).split('.')[0])
        if 1 <= first_octet <= 126: ip_class = "A"
        elif 128 <= first_octet <= 191: ip_class = "B"
        elif 192 <= first_octet <= 223: ip_class = "C"
        elif 224 <= first_octet <= 239: ip_class = "D (Multicast)"
        elif 240 <= first_octet <= 255: ip_class = "E (Experimental)"
        else: ip_class = "Loopback/Special"

        # Reverse DNS
        rev_dns = ".".join(reversed(str(ip).split('.'))) + ".in-addr.arpa"

        # IPv6 Transition
        # IPv4-mapped: ::ffff:c0a8:0101 for 192.168.1.1
        ipv4_mapped = f"::ffff:{ip_int:08x}"
        ipv4_mapped = ":".join([ipv4_mapped[i:i+4] for i in range(0, len(ipv4_mapped), 4)])
        # 6to4: 2002:c0a8:0101::/48
        prefix_6to4 = f"2002:{ip_int:08x}::/48"
        prefix_6to4 = prefix_6to4.replace("2002:", "2002:").replace("::", "::") # formatting fix
        
        res = {
            "ip": str(ip),
            "network": str(network.network_address),
            "netmask": str(network.netmask),
            "broadcast": str(network.broadcast_address),
            "wildcard": wildcard_str,
            "hosts_total": num_hosts,
            "hosts_usable": usable_hosts,
            "range": f"{first_ip} - {last_ip}" if usable_hosts > 0 else "N/A",
            "cidr": f"/{prefix}",
            "mask_bin": mask_bin_formatted,
            "ip_class": ip_class,
            "ip_type": "Private" if ip.is_private else "Public",
            "binary_id": ip_bin,
            "integer_id": ip_int,
            "hex_id": f"0x{ip_int:08x}",
            "reverse_dns": rev_dns,
            "ipv4_mapped": ipv4_mapped,
            "prefix_6to4": prefix_6to4,
        }

        # Subnet List (Possible siblings in the same /24, /16, or /8 block)
        siblings = []
        try:
            if prefix >= 24:
                parent_prefix = 24
            elif prefix >= 16:
                parent_prefix = 16
            elif prefix >= 8:
                parent_prefix = 8
            else:
                parent_prefix = prefix # Don't show siblings for extremely large blocks
            
            if parent_prefix != prefix:
                parent_network = ipaddress.ip_network(f"{res['ip']}/{parent_prefix}", strict=False)
                # Limit to first 256 subnets to avoid UI lag
                for i, sub in enumerate(parent_network.subnets(new_prefix=prefix)):
                    if i >= 256: break
                    siblings.append({
                        "net": str(sub.network_address),
                        "range": f"{sub.network_address + (1 if prefix < 31 else 0)} - {sub.broadcast_address - (1 if prefix < 31 else 0)}",
                        "broadcast": str(sub.broadcast_address)
                    })
        except Exception:
            pass # Fallback to empty siblings if parent calculation fails
        
        res["siblings"] = siblings
        return res
    except Exception as e:
        return {"error": str(e)}

def test_regex(pattern, text):
    try:
        matches = []
        for match in re.finditer(pattern, text):
            matches.append({
                "match": match.group(),
                "start": match.start(),
                "end": match.end(),
                "groups": match.groups()
            })
        return {"matches": matches, "count": len(matches)}
    except re.error as e:
        return {"error": str(e)}

def decode_cert(pem_data):
    try:
        cert = x509.load_pem_x509_certificate(pem_data.encode('utf-8'), default_backend())
        return {
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "serial": str(cert.serial_number),
            "not_valid_before": str(cert.not_valid_before_utc),
            "not_valid_after": str(cert.not_valid_after_utc),
            "version": str(cert.version)
        }
    except Exception as e:
        return {"error": str(e)}
import socket

def check_port(host, port, timeout=2):
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except Exception:
        return False

def calculate_wildcard(mask_str):
    try:
        # If it's CIDR, convert to mask first
        if '/' in mask_str:
            mask = str(ipaddress.ip_network(mask_str, strict=False).netmask)
        else:
            mask = mask_str
            
        octets = mask.split('.')
        if len(octets) != 4:
            raise ValueError("Invalid IPv4 mask format")
            
        wildcard_parts = [str(255 - int(o)) for o in octets]
        wildcard = '.'.join(wildcard_parts)
        return {"mask": mask, "wildcard": wildcard}
    except Exception as e:
        return {"error": str(e)}

def calculate_mss(mtu_str, tunnel_type):
    try:
        mtu = int(mtu_str)
        # Standard IP + TCP header = 40 bytes
        # Overhead per tunnel type (conservative estimates)
        overheads = {
            "Standard (No Tunnel)": 0,
            "IPsec Transport": 56,
            "IPsec Tunnel": 80,
            "GRE": 24,
            "VXLAN": 50,
            "Wireguard": 60
        }
        
        overhead = overheads.get(tunnel_type, 0)
        mss = mtu - 40 - overhead
        return {
            "mtu": mtu,
            "overhead": overhead,
            "mss": mss,
            "description": f"Target MSS for {tunnel_type}"
        }
    except Exception as e:
        return {"error": str(e)}

def calculate_ttl(seconds_str):
    try:
        total_seconds = float(seconds_str)
        
        # Calculate expiration
        now = datetime.datetime.now()
        expiry = now + datetime.timedelta(seconds=total_seconds)
        
        # Breakdown
        years = total_seconds // (365 * 24 * 3600)
        remaining = total_seconds % (365 * 24 * 3600)
        
        months = remaining // (30 * 24 * 3600)
        remaining %= (30 * 24 * 3600)
        
        weeks = remaining // (7 * 24 * 3600)
        remaining %= (7 * 24 * 3600)
        
        days = remaining // (24 * 3600)
        remaining %= (24 * 3600)
        
        hours = remaining // 3600
        mins = (remaining % 3600) // 60
        
        duration_parts = []
        if years > 0: duration_parts.append(f"{int(years)}y")
        if months > 0: duration_parts.append(f"{int(months)}mo")
        if weeks > 0: duration_parts.append(f"{int(weeks)}w")
        if days > 0: duration_parts.append(f"{int(days)}d")
        if hours > 0: duration_parts.append(f"{int(hours)}h")
        if mins > 0: duration_parts.append(f"{int(mins)}m")
        
        if not duration_parts:
            duration_parts = [f"{total_seconds}s"]

        return {
            "duration": " ".join(duration_parts),
            "expiry_local": expiry.strftime("%Y-%m-%d %H:%M:%S Local"),
            "expiry_utc": expiry.astimezone(pytz.UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
        }
    except Exception as e:
        return {"error": str(e)}

import urllib.request
import urllib.parse

def lookup_mac_vendor(mac_str):
    try:
        # Sanitize: Keep only hex chars
        clean_mac = re.sub(r'[^0-9A-Fa-f]', '', mac_str).upper()
        if len(clean_mac) < 6:
            return {"error": "Invalid MAC: Too short"}
        
        oui = clean_mac[:6]
        
        # Local fallback for common/test OUIs
        fallbacks = {
            "00000C": "Cisco Systems, Inc.",
            "000142": "Cisco Systems, Inc.",
            "BCD1D3": "Apple, Inc.",
            "005056": "VMware, Inc.",
            "080027": "Oracle Corporation (VirtualBox)",
            "00155D": "Microsoft Corporation (Hyper-V)"
        }
        
        if oui in fallbacks:
            return {"vendor": fallbacks[oui], "oui": oui, "source": "local"}
            
        # Call public API (macvendors.co)
        # We use urllib to avoid adding 'requests' as a dependency
        try:
            url = f"https://api.macvendors.com/{urllib.parse.quote(oui)}"
            req = urllib.request.Request(url, headers={'User-Agent': 'OpsNexus/1.1'})
            with urllib.request.urlopen(req, timeout=3) as response:
                vendor = response.read().decode('utf-8')
                return {"vendor": vendor, "oui": oui, "source": "api"}
        except Exception:
            return {"error": f"Vendor not found for OUI: {oui}", "oui": oui}

    except Exception as e:
        return {"error": str(e)}

def get_ip_ownership(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private:
            return {"status": "private", "message": "Private IP (N/A)"}
        
        # Query ip-api.com (JSON)
        url = f"http://ip-api.com/json/{ip_str}"
        req = urllib.request.Request(url, headers={'User-Agent': 'OpsNexus/1.1'})
        with urllib.request.urlopen(req, timeout=3) as response:
            data = json.loads(response.read().decode('utf-8'))
            if data.get("status") == "success":
                return {
                    "status": "public",
                    "isp": data.get("isp", "Unknown ISP"),
                    "org": data.get("org", "Unknown Org"),
                    "location": f"{data.get('city', '')}, {data.get('country', '')}".strip(", ")
                }
            return {"status": "error", "message": data.get("message", "Lookup failed")}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def audit_ssl_site(hostname, port=443):
    try:
        # 1. Basic Connection & Cert Fetch
        context = ssl.create_default_context()
        # Ensure we don't hang if site is down
        with socket.create_connection((hostname, int(port)), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(cert_bin, default_backend())
                protocol = ssock.version()
        
        # 2. Extract Details
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        now = datetime.datetime.now(datetime.timezone.utc)
        
        days_left = (not_after - now).days
        is_valid = not_before <= now <= not_after
        
        # SANs (Subject Alternative Names)
        try:
            sans_ext = cert.extensions.get_extension_for_oid(x509.OID_SUBJECT_ALTERNATIVE_NAME).value
            san_list = sans_ext.get_values_for_type(x509.DNSName)
        except Exception:
            san_list = []

        # Serial & Fingerprint
        serial = f"{cert.serial_number:X}"
        fingerprint = cert.fingerprint(hashes.SHA256()).hex().upper()

        return {
            "status": "success",
            "hostname": hostname,
            "is_valid": is_valid,
            "days_left": days_left,
            "subject": subject,
            "issuer": issuer,
            "valid_from": not_before.strftime("%Y-%m-%d"),
            "valid_to": not_after.strftime("%Y-%m-%d"),
            "protocol": protocol,
            "sans": ", ".join(san_list[:5]) + ("..." if len(san_list) > 5 else ""),
            "serial": serial,
            "fingerprint": f"SHA256: {fingerprint}"
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

def generate_k8s_manifest(resource_type, params):
    """Generates K8s YAML manifests based on type and params."""
    try:
        name = params.get("name", "example-app")
        namespace = params.get("namespace", "default")
        labels = params.get("labels", {"app": name})
        
        # Helper to format labels
        lbl_str = "\n".join([f"    {k}: {v}" for k, v in labels.items()])

        if resource_type == "Deployment":
            replicas = params.get("replicas", 3)
            image = params.get("image", "nginx:latest")
            port = params.get("port", 80)
            return f"""apiVersion: apps/v1
kind: Deployment
metadata:
  name: {name}
  namespace: {namespace}
  labels:
{lbl_str}
spec:
  replicas: {replicas}
  selector:
    matchLabels:
{lbl_str}
  template:
    metadata:
      labels:
{lbl_str}
    spec:
      containers:
      - name: {name}
        image: {image}
        ports:
        - containerPort: {port}
"""

        elif resource_type == "Service":
            svc_type = params.get("service_type", "ClusterIP")
            port = params.get("port", 80)
            target_port = params.get("target_port", port)
            return f"""apiVersion: v1
kind: Service
metadata:
  name: {name}
  namespace: {namespace}
spec:
  type: {svc_type}
  selector:
{lbl_str}
  ports:
  - protocol: TCP
    port: {port}
    targetPort: {target_port}
"""

        elif resource_type == "ConfigMap":
            data = params.get("data", {"key": "value"})
            data_str = "\n".join([f"  {k}: {v}" for k, v in data.items()])
            return f"""apiVersion: v1
kind: ConfigMap
metadata:
  name: {name}
  namespace: {namespace}
data:
{data_str}
"""

        elif resource_type == "Ingress":
            host = params.get("host", "example.com")
            path = params.get("path", "/")
            svc_name = params.get("service_name", name)
            svc_port = params.get("service_port", 80)
            return f"""apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: {name}
  namespace: {namespace}
  annotations:
    kubernetes.io/ingress.class: nginx
spec:
  rules:
  - host: {host}
    http:
      paths:
      - path: {path}
        pathType: Prefix
        backend:
          service:
            name: {svc_name}
            port:
              number: {svc_port}
"""
        return "Unknown Resource Type"
    except Exception as e:
        return f"Error generating manifest: {str(e)}"

def generate_unified_diff(text_a, text_b):
    """Generates a unified diff between two text blocks."""
    try:
        a_lines = text_a.splitlines()
        b_lines = text_b.splitlines()
        
        diff = list(difflib.unified_diff(a_lines, b_lines, fromfile='Original', tofile='Modified', lineterm=''))
        
        # Format the diff with metadata for the UI
        formatted_diff = []
        for line in diff:
            if line.startswith('---') or line.startswith('+++') or line.startswith('@@'):
                formatted_diff.append({"type": "meta", "text": line})
            elif line.startswith('-'):
                formatted_diff.append({"type": "remove", "text": line})
            elif line.startswith('+'):
                formatted_diff.append({"type": "add", "text": line})
            else:
                formatted_diff.append({"type": "same", "text": line})
                
        return {"status": "success", "diff": formatted_diff}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def generate_split_diff(text_a, text_b):
    """Generates a side-by-side aligned diff with intraline highlighting."""
    try:
        a_lines = text_a.splitlines()
        b_lines = text_b.splitlines()
        
        s = difflib.SequenceMatcher(None, a_lines, b_lines)
        left_res = []
        right_res = []
        
        for tag, i1, i2, j1, j2 in s.get_opcodes():
            if tag == 'equal':
                for i in range(i1, i2):
                    left_res.append({"type": "same", "text": a_lines[i]})
                    right_res.append({"type": "same", "text": b_lines[j1 + (i - i1)]})
            elif tag == 'replace':
                # Attempt intraline highlighting for changed lines
                len_a = i2 - i1
                len_b = j2 - j1
                max_len = max(len_a, len_b)
                for i in range(max_len):
                    line_a = a_lines[i1 + i] if i < len_a else None
                    line_b = b_lines[j1 + i] if i < len_b else None
                    
                    if line_a is not None and line_b is not None:
                        # Character level diff
                        chars = difflib.SequenceMatcher(None, line_a, line_b)
                        left_spans = []
                        right_spans = []
                        for c_tag, ci1, ci2, cj1, cj2 in chars.get_opcodes():
                            if c_tag == 'equal':
                                left_spans.append({"type": "same", "text": line_a[ci1:ci2]})
                                right_spans.append({"type": "same", "text": line_b[cj1:cj2]})
                            elif c_tag == 'replace':
                                left_spans.append({"type": "change", "text": line_a[ci1:ci2]})
                                right_spans.append({"type": "change", "text": line_b[cj1:cj2]})
                            elif c_tag == 'delete':
                                left_spans.append({"type": "change", "text": line_a[ci1:ci2]})
                            elif c_tag == 'insert':
                                right_spans.append({"type": "change", "text": line_b[cj1:cj2]})
                        
                        left_res.append({"type": "change_row", "spans": left_spans})
                        right_res.append({"type": "change_row", "spans": right_spans})
                    elif line_a is not None:
                        left_res.append({"type": "remove", "text": line_a})
                        right_res.append({"type": "empty", "text": ""})
                    elif line_b is not None:
                        left_res.append({"type": "empty", "text": ""})
                        right_res.append({"type": "add", "text": line_b})
            elif tag == 'delete':
                for i in range(i1, i2):
                    left_res.append({"type": "remove", "text": a_lines[i]})
                    right_res.append({"type": "empty", "text": ""})
            elif tag == 'insert':
                for j in range(j1, j2):
                    left_res.append({"type": "empty", "text": ""})
                    right_res.append({"type": "add", "b_idx": j, "text": b_lines[j]})
                    
        return {"status": "success", "left": left_res, "right": right_res}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def format_hcl(hcl_text):
    """Custom HCL formatter that handles indentation and operator alignment."""
    try:
        if not hcl_text.strip(): return ""
        lines = hcl_text.splitlines()
        indent_level = 0
        indent_size = 2
        
        processed_lines = [line.strip() for line in lines]
        final_lines = []
        
        i = 0
        while i < len(processed_lines):
            line = processed_lines[i]
            
            if not line:
                final_lines.append("")
                i += 1
                continue

            # Handle closing brace before indentation check
            if line.startswith("}") or line.startswith("]"):
                indent_level = max(0, indent_level - 1)

            # Check for assignment block for alignment
            if "=" in line and not any(line.startswith(c) for c in ["#", "//", "/*"]) and "{" not in line and "[" not in line:
                block = []
                j = i
                while j < len(processed_lines):
                    curr = processed_lines[j]
                    if not curr: # Allow empty lines in block
                        block.append(None)
                        j += 1
                        continue
                    if "=" in curr and not any(curr.startswith(c) for c in ["#", "//", "/*"]) and "{" not in curr and "}" not in curr and "[" not in curr and "]" not in curr:
                        block.append(curr)
                        j += 1
                    else:
                        break
                
                if len(block) > 1 or (len(block) == 1 and block[0]):
                    max_key_len = 0
                    parts = []
                    for b_line in block:
                        if b_line is None:
                            parts.append(None)
                        else:
                            k, v = b_line.split("=", 1)
                            k, v = k.strip(), v.strip()
                            max_key_len = max(max_key_len, len(k))
                            parts.append((k, v))
                    
                    for p in parts:
                        if p is None:
                            final_lines.append("")
                        else:
                            final_lines.append(" " * (indent_level * indent_size) + f"{p[0].ljust(max_key_len)} = {p[1]}")
                    i = j
                    # If the block ended because of a brace, don't increment i twice
                    continue

            # Default line handling
            final_lines.append(" " * (indent_level * indent_size) + line)
            
            # Increase indent after opening braces
            if line.endswith("{") or line.endswith("["):
                indent_level += 1
            
            i += 1
            
        return "\n".join(final_lines)
    except Exception as e:
        return f"Error formatting HCL: {str(e)}"
