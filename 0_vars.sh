#!/bin/bash

# Generate an RSA key
private_key_file="key.pem"
public_key_file="key.pub"
key_id="key1"
token_validity_duration="+60 minute"

storage_account="fakeidp"
container_name="public"
issuer_path="https://${storage_account}.blob.core.windows.net/${container_name}"
subject="OpenSSL self-issued"
audience="api://AzureADTokenExchange"

aadTenant="geuer-pollmann.de"
uami_subscription="chgeuer-msdn"
uami_resource_group="longterm"
uami_name="some-devops-managed-identity"
ado_organization="chgpmsitest1"
