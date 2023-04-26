#!/bin/bash

source ./0_vars.sh

openssl genrsa -out "${private_key_file}" 2048
openssl rsa -in "${private_key_file}" -pubout > "${public_key_file}"

jwks_keys="${issuer_path}/jwks_uri/keys"

openid_config_json="$( \
  echo '{"issuer":"","token_endpoint":"","jwks_uri":"","id_token_signing_alg_values_supported":["RS256"],"token_endpoint_auth_methods_supported":["client_secret_post"],"response_modes_supported":["form_post"],"response_types_supported":["id_token"],"scopes_supported":["openid"],"claims_supported":["sub","iss","aud","exp","iat","name"]}' | \
  jq --arg x "${issuer_path}"  '.issuer=$x'         | \
  jq --arg x "${issuer_path}"  '.token_endpoint=$x' | \
  jq --arg x "${jwks_keys}"    '.jwks_uri=$x'       | \
  jq -c -M "."                                      | \
  iconv --from-code=ascii --to-code=utf-8 )"

echo "${openid_config_json}" > openid-configuration.json

az storage blob upload                       \
   --auth-mode login                         \
   --account-name "${storage_account}"       \
   --container-name "${container_name}"      \
   --content-type "application/json"         \
   --file openid-configuration.json          \
   --name ".well-known/openid-configuration"

modulus="$( openssl rsa -in "${private_key_file}" -modulus -pubout -noout | \
      sed 's/Modulus=//' | \
      xxd -r -p | \
      base64 --wrap=0 )"

## If the public exponent is 65537, it is "AQAB" base64-encoded
# You can run the command below to see the exponent:
#
# openssl rsa -in "${private_key_file}" -text -noout | grep publicExponent | sed 's/publicExponent: //'
#
exponent="AQAB"

jwks_keys_json="$( echo "{}"                         | \
  jq --arg x "RSA"             '.keys[0].kty=$x'     | \
  jq --arg x "${issuer_path}"  '.keys[0].issuer=$x'  | \
  jq --arg x "${key_id}"       '.keys[0].kid=$x'     | \
  jq --arg x "${exponent}"     '.keys[0].e=$x'       | \
  jq --arg x "${modulus}"      '.keys[0].n=$x'       | \
  iconv --from-code=ascii --to-code=utf-8 )"

echo "${jwks_keys_json}" | jq . > keys.json

az storage blob upload                       \
   --auth-mode login                         \
   --account-name "${storage_account}"       \
   --container-name "${container_name}"      \
   --content-type "application/json"         \
   --file keys.json                          \
   --name "jwks_uri/keys"

az identity federated-credential create \
   --subscription "${uami_subscription}" \
   --resource-group "${uami_resource_group}" \
   --identity-name "${uami_name}" \
   --name "openssl" \
   --audiences "${audience}" \
   --issuer "${issuer_path}"  \
   --subject "${subject}"

uami_client_id="$( az identity show \
   --subscription "chgeuer-msdn" \
   --resource-group "longterm" \
   --name "some-devops-managed-identity" \
   | jq -r '.clientId' \
   )"

echo -n "${uami_client_id}" > uami_client_id.guid
