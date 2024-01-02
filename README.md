# Example ACME crontab with certbot
```
@monthly /snap/bin/certbot renew --manual-auth-hook '/path/to/cloudflare-acme.py --token <cloudflare api token> --zone example.com && sleep 60 && systemctl restart nginx'
```
