# Nginx and HTTPS

[Back to setup](setup.md) | [Next: Services](services.md)

## 1. Install the required packages

```bash
sudo apt update
sudo apt install -y nginx certbot python3-certbot-dns-ovh
```

## 2. Create the OVH credentials file

```bash
sudo mkdir -p /root/.secrets/certbot
sudo nano /root/.secrets/certbot/ovh.ini
```

Use:

```ini
dns_ovh_endpoint = ovh-eu
dns_ovh_application_key = __OVH_APPLICATION_KEY__
dns_ovh_application_secret = __OVH_APPLICATION_SECRET__
dns_ovh_consumer_key = __OVH_CONSUMER_KEY__
```

Then lock it down:

```bash
sudo chmod 600 /root/.secrets/certbot/ovh.ini
```

## 3. Issue the certificate

```bash
sudo certbot certonly \
  --dns-ovh \
  --dns-ovh-credentials /root/.secrets/certbot/ovh.ini \
  -d __APP_DOMAIN__
```

If you also serve `www`, include it explicitly:

```bash
sudo certbot certonly \
  --dns-ovh \
  --dns-ovh-credentials /root/.secrets/certbot/ovh.ini \
  -d __APP_DOMAIN__ \
  -d www.__APP_DOMAIN__
```

Validate:

```bash
sudo certbot certificates
```

## 4. Create the Nginx site

```bash
sudo nano /etc/nginx/sites-available/rust-api.conf
```

Use [nginx.conf](../../../deploy/app/nginx.conf) as the reference.

Replace:
- `__APP_DOMAIN__`

## 5. Enable the site

```bash
sudo ln -sf /etc/nginx/sites-available/rust-api.conf /etc/nginx/sites-enabled/rust-api.conf
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl reload nginx
```

## 6. Validate

```bash
curl -I https://__APP_DOMAIN__
```

You should see a valid HTTPS response from Nginx before deploying the application itself.
