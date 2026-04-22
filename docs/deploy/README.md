# Deployment Guide

Follow the steps in this order for a complete deployment.

## Initial Deployment

1. [Secrets](api/secrets.md) — Insert all secrets into `pass` on the API VPS
2. [Database Deployment](database/deployment.md) — Set up PostgreSQL and Redis on the DB VPS
3. [API Deployment](api/deployment.md) — Deploy the API on the API VPS
4. [Nginx](api/nginx.md) — Set up the reverse proxy

## Updates

- [Deploying a New Release](guides/update.md) — Update the API and run new migrations
