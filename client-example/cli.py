import base64
import requests
import time
import random
import string
import requests_aws4auth
import sys
import configparser
import os.path as path

DEBUG = True


def pretty_print_POST(req):
    print('{}\n{}\n{}\n\n{}'.format(
        '-----------START-----------',
        req.method + ' ' + req.url,
        '\n'.join('{}: {}'.format(k, v) for k, v in req.headers.items()),
        req.body,
        ))

def read_aws_credentials():
    config = configparser.ConfigParser()
    config.read(path.join(path.expanduser("~"), ".aws/credentials"))
    return config['default']['aws_access_key_id'], config['default']['aws_secret_access_key']

def aws_request(url, data, operation):
    a = requests_aws4auth.AWS4Auth(*read_aws_credentials(), "eu-west-1", "execute-api")
    req = requests.Request('POST', url=url, json=data, auth=a, headers={"Content-Type": "application/json", "X-Amz-Target": operation})
    prepared = req.prepare()
    if DEBUG:
        pretty_print_POST(prepared)
    r = requests.Session().send(prepared)
    resp_data = r.json()
    if DEBUG:
        print(r.status_code, resp_data)
    return r.status_code, resp_data



def issue(url, policy, csr, arn):
    csr = base64.standard_b64encode(open(csr, "rb").read())
    body_request = {"SigningAlgorithm":"SHA256WITHRSA",
                    "Validity": {"Type": "DAYS", "Value": 3},
                    "CertificateAuthorityArn": arn,
                    "Csr": csr.decode()}
    if policy:
        body_request["VenafiZone"] = policy
    target = "ACMPrivateCAIssueCertificate"
    status_code, data_response = aws_request(url, body_request, target)
    if status_code == 200:
        print(data_response)


def request(url, policy, domain):
    body_request = {"DomainName": domain}
    if policy:
        body_request["VenafiZone"] = policy
    target = "CertificateManagerRequestCertificate"
    status_code, data_response = aws_request(url, body_request, target)
    if status_code == 200:
        print(data_response)



def main():
    import argparse
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('action', metavar='action', type=str, nargs=1,
                        help='Action', choices=['issue', 'request'])
    parser.add_argument('--base-url', dest='url', type=str,
                        help='deployed application api gateway url')
    parser.add_argument('--domain', dest='domain', type=str,
                        help='domain for requesting certificate')
    parser.add_argument('--policy', dest='policy', type=str,
                        help='venafi policy name')
    parser.add_argument('--csr-path', dest='csr', type=str,
                        help='path to csr for issue action')
    parser.add_argument('--arn', dest='arn', type=str,
                        help='acm-pca arn')

    args = parser.parse_args()
    if args.action[0] == "issue":
        issue(args.url, args.policy, args.csr, args.arn)
    elif args.action[0] == "request":
        request(args.url, args.policy, args.domain)



if __name__ == '__main__':
    main()