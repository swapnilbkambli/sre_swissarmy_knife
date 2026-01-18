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
from cryptography import x509
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
