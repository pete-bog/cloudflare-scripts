#!/usr/bin/env python3
import argparse
import logging
import os
from copy import deepcopy
import requests

URL_BASE = "https://api.cloudflare.com/client/v4"
LOG = logging.getLogger("Cloudflare ACME client")
ACME_DOMAIN_TEMPLATE="_acme-challenge.{}"


def build_headers(token, **kwargs) -> dict:
    headers = {"Authorization": f"Bearer {token}"}
    for key, val in kwargs.items():
        header_name = "-".join([x.capitalize() for x in key.split("-")])
        headers[header_name] = val
    return headers


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

    def update_txt_record(self, zone_id, domain_id, domain_name, content):
        url = f"{URL_BASE}/zones/{zone_id}/dns_records/{domain_id}"
        data = {
            "type": "TXT",
            "name": domain_name,
            "content": content,
            "ttl": 1
        }
        response = self.put(url, json=data)
        if response.status_code != 200:
            LOG.info("Something went wrong: %s", response.text)

def parse_args():
    domain = os.getenv("CERTBOT_DOMAIN")
    if domain and domain.startswith("*."):
        domain = domain[2:]
    challenge = os.getenv("CERTBOT_VALIDATION")
    parser = argparse.ArgumentParser()
    parser.add_argument("--token", help="Cloudflare api token", required=True)
    parser.add_argument("--zone", help="Name of cloudflare zone in which to find the domain", required=True)
    parser.add_argument("--domain", help="Name of the domain to renew", default=domain)
    parser.add_argument("--challenge", help="ACME challenge from certbot",
                        default=challenge)
    args = parser.parse_args()
    if not args.zone:
        parser.error("No domain supplied via --zone or $CERTBOT_DOMAIN environment variable!")
    if not args.challenge:
        parser.error("No challenge supplied via --challenge or $CERTBOT_VALIDATION environment variable!")
    return args

if __name__ == "__main__":
    args = parse_args()
    logging.basicConfig(level="INFO",
                        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    client = CloudflareApiClient(args.token)
    zone = client.get_zone_by_name(args.zone)
    domain_name = ACME_DOMAIN_TEMPLATE.format(args.domain)
    domain = client.get_domain_by_name(zone["id"], domain_name)
    LOG.info("Updating domain TXT record to %s to %s", domain["name"], args.challenge)
    client.update_txt_record(zone["id"], domain["id"], domain["name"], args.challenge)
