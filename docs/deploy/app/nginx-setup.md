# Nginx Setup

This guide explains how to configure Nginx on the application server.

The repository file:
- [nginx.conf](../../../deploy/proxy/nginx.conf)

is a reference only.
The server is expected to have its own local Nginx configuration file.

## Install Nginx

On Debian or Ubuntu:

```bash
sudo apt update
sudo apt install -y nginx
```

## Create the Nginx Configuration

Create a local site configuration on the server, for example:

```text
/etc/nginx/sites-available/rust-api.conf
```

Use the repository reference file:
- [nginx.conf](../../../deploy/proxy/nginx.conf)

and adapt at least:
- `server_name`
- TLS certificate paths
- upstream target if your local routing differs

## Enable the Site

Enable the configuration:

```bash
sudo ln -s /etc/nginx/sites-available/rust-api.conf /etc/nginx/sites-enabled/rust-api.conf
```

If needed, remove the default site:

```bash
sudo rm -f /etc/nginx/sites-enabled/default
```

## Validate the Configuration

Test the Nginx configuration:

```bash
sudo nginx -t
```

Reload Nginx:

```bash
sudo systemctl reload nginx
```

## Application Settings to Align

When Nginx is used in front of the application, align the application configuration with the proxy:

| Setting | Why it matters |
| --- | --- |
| `APP_PUBLIC_URL` | Must match the public HTTPS URL exposed by Nginx |
| `TRUSTED_PROXY_CIDRS` | Must allow the reverse proxy address range |
| `WEBAUTHN_RP_ORIGIN` | Must match the public origin served through Nginx |
| `WEBAUTHN_RP_ID` | Must match the effective relying party host |
