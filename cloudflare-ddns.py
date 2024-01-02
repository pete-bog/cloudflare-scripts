#!/usr/bin/env python3
import argparse
import logging
from copy import deepcopy
import requests

URL_BASE = "https://api.cloudflare.com/client/v4"
LOG = logging.getLogger("Cloudflare DDNS client")


def build_headers(token, **kwargs) -> dict:
    headers = {"Authorization": f"Bearer {token}"}
    for key, val in kwargs.items():
        header_name = "-".join([x.capitalize() for x in key.split("-")])
        headers[header_name] = val
    return headers


def get_my_ip():
    response = requests.get("https://api.ipify.org?format=json")
    return response.json()["ip"]


class CloudflareApiClient:
    def __init__(self, token):
        self.token = token
        self.session = requests.Session()

    def get(self, *args, **kwargs):
        return self.session.get(*args, headers=build_headers(self.token), **kwargs)

    def put(self, *args, **kwargs):
        headers = build_headers(self.token, content_type="application/json")
        return self.session.put(*args, headers=headers, **kwargs)

    def get_zone_by_name(self, name):
        url = f"{URL_BASE}/zones/"
        response = self.get(url)
        for zone in response.json()["result"]:
            if zone["name"] == name:
                return zone
        return None

    def get_domain_by_name(self, zone_id, domain):
        url = f"{URL_BASE}/zones/{zone_id}/dns_records"
        response = self.get(url)
        result = response.json()["result"]
        for record in result:
            if record["name"] == domain:
                return record
        return None

    def update_domain(self, zone_id, domain_id, domain_name, ip):
        url = f"{URL_BASE}/zones/{zone_id}/dns_records/{domain_id}"
        data = {
            "type": "A",
            "name": domain_name,
            "content": ip,
            "ttl": 1,
            "proxied": True
        }
        response = self.put(url, json=data)
        if response.status_code != 200:
            LOG.info("Something went wrong: %s", response.text)

    def get_domain_ip(self, zone_name, domain_name) -> str:
        zone = client.get_zone_by_name(zone_name)
        domain = client.get_domain_by_name(zone["id"], domain_name)
        return domain["content"]

    def set_domain_ip(self, zone_name, domain_name, ip):
        zone = client.get_zone_by_name(zone_name)
        domain = client.get_domain_by_name(zone["id"], domain_name)
        self.update_domain(zone["id"], domain["id"], domain["name"], ip)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("zone", help="Name of cloudflare zone in which to find the domain")
    parser.add_argument("domain", help="Name of domain to update in the zone")
    parser.add_argument("token", help="Cloudflare api token")
    parser.add_argument("--force", help="Force update the record", action="store_true")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    logging.basicConfig(level="INFO",
                        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    my_ip = get_my_ip()
    client = CloudflareApiClient(args.token)
    zone = client.get_zone_by_name(args.zone)
    domain = client.get_domain_by_name(zone["id"], args.domain)
    if args.force or domain["content"] != my_ip:
        LOG.info("Updating domain %s to %s", domain["name"], my_ip)
        client.update_domain(zone["id"], domain["id"], domain["name"], my_ip)
    else:
        LOG.info("Domain %s is up to date", domain["name"])
