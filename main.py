# -*- coding: utf-8 -*-
import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor

import dns.resolver
import requests
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
executor = ThreadPoolExecutor(max_workers=10)


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
    """查询IP归属地"""
    try:
        resp = requests.get(
            f"https://api.ip.sb/geoip/{ip}",
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=10,
        )
        if resp.ok:
            data = resp.json()
            return {
                "country": data.get("country", "Unknown"),
                "country_code": data.get("country_code", ""),
                "isp": data.get("isp", ""),
            }
    except Exception as e:
        logging.warning(f"查询IP {ip} 归属地失败: {e}")
    return {"country": "Unknown"}


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
