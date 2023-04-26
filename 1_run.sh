#!/bin/bash

source ./0_vars.sh

uami_client_id="$( cat "./uami_client_id.guid" )"

function create_base64_url {
    local base64text="$1"
    echo -n "${base64text}" | sed -E s%=+$%% | sed s%\+%-%g | sed -E s%/%_%g 
}

function json_to_base64 {
    local jsonText="$1"
    create_base64_url "$( echo -n "${jsonText}" | base64 --wrap=0 )"
}

# `jq -c -M` gives a condensed/Monochome(no ANSI codes) representation
header="$( echo "{}"                | \
  jq --arg x "JWT"        '.typ=$x' | \
  jq --arg x "RS256"      '.alg=$x' | \
  jq --arg x "${key_id}"  '.kid=$x' | \
  jq -c -M "."                      | \
  iconv --from-code=ascii --to-code=utf-8 )"

payload="$( echo "{}" | \
  jq --arg x "${issuer_path}"                                    '.iss=$x'              | \
  jq --arg x "${audience}"                                       '.aud=$x'              | \
  jq --arg x "${subject}"                                        '.sub=$x'              | \
  jq --arg x "$( date +%s )"                                     '.iat=($x | fromjson)' | \
  jq --arg x "$( date --date="${token_validity_duration}" +%s )" '.exp=($x | fromjson)' | \
  jq -c -M "."                                                                          | \
  iconv --from-code=ascii --to-code=utf-8 )"

toBeSigned="$( echo -n "$( json_to_base64 "${header}" ).$( json_to_base64 "${payload}" )" | iconv --to-code=ascii )"

# RSASSA-PKCS1-v1_5 using SHA-256 
signature="$( echo -n "${toBeSigned}"                         | \
    openssl dgst -sha256 --binary -sign "${private_key_file}" | \
    base64 --wrap=0                                           | \
    sed    s%\+%-%g                                           | \
    sed -E s%/%_%g                                            | \
    sed -E s%=+$%% )"

self_issued_jwt="${toBeSigned}.${signature}"

resource="https://management.azure.com/.default"

azure_devops_appid="499b84ac-1321-427f-aa17-267ca6975798/.default"
resource="${azure_devops_appid}"

token_response="$( curl \
    --silent \
    --request POST \
    --data-urlencode "response_type=token" \
    --data-urlencode "grant_type=client_credentials" \
    --data-urlencode "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
    --data-urlencode "client_id=${uami_client_id}" \
    --data-urlencode "client_assertion=${self_issued_jwt}" \
    --data-urlencode "scope=${resource}" \
    "https://login.microsoftonline.com/${aadTenant}/oauth2/v2.0/token" )"

access_token="$( echo "${token_response}" | jq -r ".access_token" )"

echo "Self-issued token"
jq -R 'split(".") | .[0],.[1] | @base64d | fromjson' <<< "${self_issued_jwt}"
echo "AAD token"
jq -R 'split(".") | .[0],.[1] | @base64d | fromjson' <<< "${access_token}"

echo "Service response"
curl --silent --get \
   --url "https://dev.azure.com/${ado_organization}/_apis/projects" \
   --header "Authorization: Bearer ${access_token}" \
   | jq .
