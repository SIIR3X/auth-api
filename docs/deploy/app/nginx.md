# Nginx

[Previous: Services](services.md) | [Back to setup](setup.md) | [Next: Monitoring](monitoring.md)

## 1. Create the site file

```bash
sudo nano /etc/nginx/sites-available/rust-api.conf
```

Use [nginx.conf](../../../deploy/app/nginx.conf) as the reference.

Replace:
- `__APP_DOMAIN__`

## 2. Enable the site

```bash
sudo ln -sf /etc/nginx/sites-available/rust-api.conf /etc/nginx/sites-enabled/rust-api.conf
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl reload nginx
```

## 3. Issue the certificate if needed

```bash
sudo certbot --nginx -d __APP_DOMAIN__
sudo nginx -t
sudo systemctl reload nginx
```

## 4. Validate

```bash
curl -I https://__APP_DOMAIN__
```
