#!/usr/bin/env python
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This module creates a list of cron intervals for a node in a group of nodes
# to ensure each node runs a cron in round robbin style.

import argparse
import json
import os
import re
import requests
import sys

if sys.version_info[0] < 3:
    from urllib import quote_plus
else:
    from urllib.parse import quote_plus


def main(argv):
    parser = argparse.ArgumentParser(description=(
        'Generate mod_oidc metadata files for a given identity provider. See '
        'https://github.com/zmartzone/mod_auth_openidc/wiki/Multiple-Providers '
        'for examples of the files this generates.'))

    parser.add_argument('--output-dir', required=True,
                        help=('The directory to output the metadata/cert files '
                              'into.'))
    parser.add_argument('--identity-provider-url', required=True,
                        help=('The fully qualified hostname of the remote '
                              'identity provider.'))
    parser.add_argument('--client-id', required=True,
                        help='the OpenID client public ID')
    parser.add_argument('--client-secret', required=True,
                        help='the OpenID client secret')
    parser.add_argument('--jwt-certificate-path',
                        help=('The fully qualified names of the files that '
                              'contain the X.509 certificates with the RSA '
                              'public keys that can be used for local JWT '
                              'access token verification.'))
    parser.add_argument('--jwt-certificate-transformer', help='')
    parser.add_argument('--jwt-key-path', help='')
    parser.add_argument('--jwt-key-transformer', help='')

    args = parser.parse_args(argv)

    output_dir = args.output_dir
    idp_url = args.identity_provider_url
    client_id = args.client_id
    client_secret = args.client_secret
    jwt_certificate_path = args.jwt_certificate_path
    jwt_certificate_transformer = args.jwt_certificate_transformer
    jwt_key_path = args.jwt_key_path
    jwt_key_transformer = args.jwt_key_transformer

    metadata_dir = os.path.join(output_dir, "metadata")
    certificate_dir = os.path.join(output_dir, "cert")
    file_name = quote_plus(re.sub("https?://", "", idp_url))
    json_provider_url = idp_url + '/.well-known/openid-configuration'

    json_provider = requests.get(json_provider_url).json()
    jwks_uri = json_provider.get("jwks_uri")

    # This variable is an empty json because we are not overriding any configuration
    # and the apache2 OIDC plugin needs an existing config file with a valid json,
    # even if this JSON is an empty one.
    json_conf = {}
    json_client = {'client_id': client_id, 'client_secret': client_secret}

    if not jwt_key_path:
        jwt_key_path = jwks_uri
    if not jwt_certificate_path:
        jwt_certificate_path = jwks_uri

    jwt_key = get_value_by_url(jwt_key_path)
    jwt_certificate = get_value_by_url(jwt_certificate_path)

    if jwt_certificate_transformer:
        jwt_certificate = eval(jwt_certificate_transformer)
    else:
        jwt_certificate = default_jwt_certificate_transformer(jwt_certificate)

    if jwt_key_transformer:
        jwt_key = eval(jwt_key_transformer)
    else:
        jwt_key = default_jwt_key_transformer(jwt_key)

    create_file(metadata_dir, file_name, "provider", json.dumps(json_provider))
    create_file(metadata_dir, file_name, "client", json.dumps(json_client))
    create_file(metadata_dir, file_name, "conf", json.dumps(json_conf))

    if jwt_key and jwt_certificate:
        create_file(certificate_dir, jwt_key, "pem", jwt_certificate)
        print(jwt_key)


def default_jwt_key_transformer(jwt_key):
    keys = json.loads(jwt_key).get("keys")

    return keys[0]["kid"] if keys else None


def default_jwt_certificate_transformer(jwt_certificate):
    keys = json.loads(jwt_certificate).get("keys")

    if keys:
        return '\n'.join([
            '-----BEGIN CERTIFICATE-----',
            keys[0]["x5c"][0],
            '-----END CERTIFICATE-----',
        ])
    else:
        return None


def create_file(file_path, file_name, extension, content):
    path = "%s/%s.%s" % (file_path, file_name, extension)
    with open(path, "w") as file:
        file.write(str(content))


def get_value_by_url(url):
    if 'http' in url:
        return requests.get(url)._content.decode("utf-8")
    if 'file' in url:
        with open(url.replace("file://",""), "r") as file:
            return file.read().decode("utf-8")

    return url


if __name__ == "__main__":
    main(sys.argv[1:])
