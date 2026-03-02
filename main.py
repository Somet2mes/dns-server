# -*- coding: utf-8 -*-
import asyncio
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from threading import Lock

import dns.resolver
import requests
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
executor = ThreadPoolExecutor(max_workers=10)
http = requests.Session()

_ip_location_cache: dict[str, tuple[float, dict]] = {}
_ip_location_cache_lock = Lock()
_IP_LOCATION_OK_TTL_SECONDS = 24 * 60 * 60
_IP_LOCATION_FAIL_TTL_SECONDS = 5 * 60
_IP_LOCATION_CACHE_MAX = 50_000


class BatchRequest(BaseModel):
    domains: list[str]
    include_location: bool = True
    dns_server: str | None = "8.8.8.8"


def resolve_domain(domain: str, dns_server: str) -> list[str]:
    """使用指定DNS服务器解析域名A记录"""
    r = dns.resolver.Resolver()
    r.nameservers = [dns_server]
    r.timeout = 5
    r.lifetime = 5
    try:
        answers = r.resolve(domain, 'A')
        return [a.to_text() for a in answers]
    except Exception as e:
        logging.warning(f"解析 {domain} 失败 (DNS: {dns_server}): {e}")
        return []


def get_ip_location(ip: str) -> dict:
    """查询IP归属地 (多Provider，附带差异信息)"""
    now = time.time()
    with _ip_location_cache_lock:
        cached = _ip_location_cache.get(ip)
        if cached and cached[0] > now:
            return cached[1]

    def remember(loc: dict, ttl_seconds: int) -> dict:
        expire_at = now + ttl_seconds
        with _ip_location_cache_lock:
            if len(_ip_location_cache) > _IP_LOCATION_CACHE_MAX:
                _ip_location_cache.clear()
            _ip_location_cache[ip] = (expire_at, loc)
        return loc

    def lookup_ip_api(target_ip: str) -> dict | None:
        try:
            resp = http.get(
                f"http://ip-api.com/json/{target_ip}",
                params={
                    "fields": "status,message,country,countryCode,regionName,city,isp",
                },
                headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"},
                timeout=10,
            )
            if not resp.ok:
                return None
            data = resp.json()
            if data.get("status") != "success":
                return None
            return {
                "country": data.get("country", "Unknown"),
                "country_code": data.get("countryCode", ""),
                "region": data.get("regionName", ""),
                "city": data.get("city", ""),
                "isp": data.get("isp", ""),
                "source": "ip-api",
            }
        except Exception as e:
            logging.warning(f"[ip-api] 查询IP {target_ip} 归属地失败: {e}")
            return None

    def lookup_ipwhois(target_ip: str) -> dict | None:
        try:
            resp = http.get(
                f"https://ipwho.is/{target_ip}",
                headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"},
                timeout=10,
            )
            if not resp.ok:
                return None
            data = resp.json()
            if data.get("success") is False:
                return None
            connection = data.get("connection") or {}
            isp = connection.get("isp") or connection.get("org") or ""
            return {
                "country": data.get("country", "Unknown"),
                "country_code": data.get("country_code", ""),
                "region": data.get("region", ""),
                "city": data.get("city", ""),
                "isp": isp,
                "source": "ipwhois",
            }
        except Exception as e:
            logging.warning(f"[ipwhois] 查询IP {target_ip} 归属地失败: {e}")
            return None

    def lookup_ip_sb(target_ip: str) -> dict | None:
        try:
            resp = http.get(
                f"https://api.ip.sb/geoip/{target_ip}",
                headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"},
                timeout=10,
            )
            if not resp.ok:
                return None
            data = resp.json()
            country = data.get("country") or "Unknown"
            return {
                "country": country,
                "country_code": data.get("country_code", ""),
                "region": data.get("region", ""),
                "city": data.get("city", ""),
                "isp": data.get("isp", ""),
                "source": "ip.sb",
            }
        except Exception as e:
            logging.warning(f"[ip.sb] 查询IP {target_ip} 归属地失败: {e}")
            return None

    candidates: list[dict] = []
    primary = lookup_ip_api(ip)
    if primary:
        candidates.append(primary)
    secondary = lookup_ipwhois(ip)
    if secondary:
        candidates.append(secondary)
    third = lookup_ip_sb(ip)
    if third:
        candidates.append(third)

    if not candidates:
        return remember({"country": "Unknown", "source": "unknown"}, _IP_LOCATION_FAIL_TTL_SECONDS)

    best = primary or secondary or third
    distinct_countries = {
        c.get("country")
        for c in candidates
        if c.get("country") and c.get("country") != "Unknown"
    }
    discrepancy = len(distinct_countries) > 1

    result = dict(best)
    result["discrepancy"] = discrepancy
    result["sources"] = candidates
    if discrepancy:
        result["country_candidates"] = sorted(distinct_countries)

    return remember(result, _IP_LOCATION_OK_TTL_SECONDS)


@app.get("/health")
async def health():
    return {"status": "ok", "server_info": {"service": "dns-resolver"}}


@app.post("/batch_resolve")
async def batch_resolve(req: BatchRequest):
    loop = asyncio.get_event_loop()
    dns_server = req.dns_server or "8.8.8.8"
    results = {}
    success_count = 0

    async def process_domain(domain):
        nonlocal success_count
        ips = await loop.run_in_executor(executor, resolve_domain, domain, dns_server)
        if not ips:
            results[domain] = {"success": False, "ips": [], "error": "No A records"}
            return

        entry = {"success": True, "ips": ips}
        if req.include_location:
            ip_locations = {}
            locs = await asyncio.gather(
                *[loop.run_in_executor(executor, get_ip_location, ip) for ip in ips]
            )
            for ip, loc in zip(ips, locs):
                ip_locations[ip] = loc
            entry["ip_locations"] = ip_locations

        results[domain] = entry
        success_count += 1

    await asyncio.gather(*[process_domain(d) for d in req.domains])

    return {
        "total_domains": len(req.domains),
        "successful_resolutions": success_count,
        "dns_server_used": dns_server,
        "server_info": {"service": "dns-resolver"},
        "results": results,
    }
