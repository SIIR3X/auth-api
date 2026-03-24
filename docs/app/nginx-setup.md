# Nginx Setup

This guide explains how to install and configure Nginx as the reverse proxy for the application server.

The reverse proxy is responsible for:
- terminating TLS
- redirecting HTTP to HTTPS
- forwarding requests to the application on `127.0.0.1:3000`
- sending the forwarded IP and scheme headers expected by the application

## Step 1: Install Nginx

On Debian or Ubuntu:

```bash
sudo apt update
sudo apt install -y nginx
```

Verify the installation:

```bash
nginx -v
```

## Step 2: Copy the Configuration

Use the repository file as the reference:
- [nginx.conf](../../deploy/proxy/nginx.conf)

Create the final Nginx config directly on the server, for example:

```bash
sudo mkdir -p /srv/rust-api/proxy
sudo editor /srv/rust-api/proxy/nginx.conf
```

The repository file is only a reference template.
It does not exist automatically on the server.

Then link the server-side file into Nginx:

```bash
sudo ln -sf /srv/rust-api/proxy/nginx.conf /etc/nginx/sites-enabled/rust-api.conf
```

If your distribution uses `sites-available`, you can place the file there first and link it from `sites-enabled`.

## Step 3: Adjust the Configuration

Before enabling it, update:
- `server_name`
- certificate paths
- ACME challenge directory if you use Certbot

The upstream target should remain:

```nginx
server 127.0.0.1:3000;
```

## Step 4: Validate the Configuration

```bash
sudo nginx -t
```

If the configuration is valid, reload Nginx:

```bash
sudo systemctl reload nginx
```

If Nginx is not running yet:

```bash
sudo systemctl enable --now nginx
```

## Step 5: Align Application Configuration

The application server should be configured consistently with the proxy:
- `APP_PUBLIC_URL` must match the public HTTPS URL
- `WEBAUTHN_RP_ORIGIN` must match the public HTTPS origin
- `TRUSTED_PROXY_CIDRS` must include the proxy source range seen by the application

When Nginx runs on the same host and proxies to `127.0.0.1:3000`, this usually means trusting the local proxy path used by your deployment.
