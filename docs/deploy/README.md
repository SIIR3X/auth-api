# Deployment Guide

Follow the steps in this order for a complete deployment.

## Initial Deployment

1. [Secrets](api/secrets.md) - Insert all secrets into `pass` on the API VPS
2. [Database Deployment](database/deployment.md) - Set up PostgreSQL, Redis and Appsmith on the DB VPS
3. [API Deployment](api/deployment.md) - Deploy the API (the NATS broker ships in the same compose file)
4. [Nginx](api/nginx.md) - Reverse proxy configuration on the API VPS

## Updates

- [Deploying a New Release](guides/update.md) - Update the API and run new migrations

## Operations

- [Operations Runbook](guides/operations.md) - Key rotations, backup/restore, Redis outage response, manual interventions, metrics
