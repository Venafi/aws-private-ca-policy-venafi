Venafi Policy Enforcement for Amazon Private CA
===============================================

<img src="https://www.venafi.com/sites/default/files/content/body/Light_background_logo.png" width="330px" height="69px"/>

This UNDER DEVELOPMENT solution implements two [AWS Lambda](https://aws.amazon.com/lambda/) functions that allow enforcement of enterprise security policy for certificate requests directed at an [Amazon Certificate Manager Private CA](https://aws.amazon.com/certificate-manager/private-certificate-authority/).  The solution uses the [VCert-Go](https://github.com/Venafi/vcert) library to retrieve enterprise security policy from [Venafi Platform](https://www.venafi.com/platform/trust-protection-platform) or [Venafi Cloud](https://pki.venafi.com/venafi-cloud/).

##### Diagram illustrating how it works: 

![Self-editing Diagram](Diagram.svg)

Note: the "user" will most likely be an application rather than a person and the solution also supports the case where ACM generates the key pair and CSR and returns the certificate, private key, and chain certificates to the "user".

### Prerequisites

1. An [Amazon Certificate Manager Private CA (PCA)](https://docs.aws.amazon.com/en_us/acm-pca/latest/userguide/PCACertInstall.html)

1. The IAM Administrator requires the following access policy (access permissions):  
    - TODO: list least privileges  
1. The AWS Engineer requires the following access policy (access permissions):
    - TODO: list least privileges  
    
## Setup and Configuration
>Note: the following instructions assume you are using a Linux command line, the syntax will differ for Windows.

### IAM Administrator Instructions

#### Create roles for Lambda functions and KMS key for encrypting credentials
1. Create a KMS key for encrypting secrets (you may skip this step if you already have a KMS key that you want to use).
Please review the [AWS KMS documentation](https://docs.aws.amazon.com/cli/latest/reference/kms/index.html) for additional details.  
    ```bash    
    KEY_ID=$(aws kms create-key --description "Encryption key for Venafi credentials" | jq -r .KeyMetadata.KeyId)
    aws kms create-alias --alias-name alias/venafi-encryption-key --target-key-id ${KEY_ID}
    aws kms describe-key --key-id alias/venafi-encryption-key
    ```
1. Download and review the Lambda policy files [VenafiPolicyLambdaRoleTrust.json](aws-policies/VenafiPolicyLambdaRoleTrust.json),
[VenafiPolicyLambdaRolePolicy.json](aws-policies/VenafiPolicyLambdaRolePolicy.json), 
[VenafiRequestLambdaRoleTrust.json](aws-policies/VenafiRequestLambdaRoleTrust.json), and
[VenafiRequestLambdaRolePolicy.json](aws-policies/VenafiRequestLambdaRolePolicy.json).
Change "YOUR_KMS_KEY_ARN_HERE" in `VenafiPolicyLambdaRolePolicy.json` the to the ARN of your KMS key.

1. Create roles for the Venafi Lambda functions and attach policies to them:

    - for the Venafi Policy Lambda:
        ```bash
        aws iam create-role \
            --role-name VenafiPolicyLambdaRole \
            --assume-role-policy-document file://aws-policies/VenafiPolicyLambdaRoleTrust.json

        aws iam put-role-policy \
            --role-name VenafiPolicyLambdaRole \
            --policy-name VenafiPolicyLambdaRolePolicy \
            --policy-document file://aws-policies/VenafiPolicyLambdaRolePolicy.json
        ```
    - for the Venafi Request Lambda:
        ```bash
        aws iam create-role \
            --role-name VenafiRequestLambdaRole \
            --assume-role-policy-document file://aws-policies/VenafiRequestLambdaRoleTrust.json

        aws iam put-role-policy \
            --role-name VenafiRequestLambdaRole \
            --policy-name VenafiRequestLambdaRolePolicy \
            --policy-document file://aws-policies/VenafiRequestLambdaRolePolicy.json
        ```

1. Create KMS key policy allowing it to be used by the Venafi Policy Lambda:
    ```bash
    KMS_KEY_ARN=$(aws kms describe-key --key-id alias/venafi-encryption-key | jq .KeyMetadata.Arn)
    ACCT_ID=$(aws sts get-caller-identity | jq -r .Account)
    cat << EOF > key-policy.json
    {
      "Version" : "2012-10-17",
      "Statement" : [ {
        "Sid" : "EnableIAMUserPermissions",
        "Effect" : "Allow",
        "Principal" : {
          "AWS" : "arn:aws:iam::${ACCT_ID}:root"
        },
        "Action" : "kms:*",
        "Resource" : "${KMS_KEY_ARN}"
      }, {
        "Sid" : "Allow use of the key",
        "Effect" : "Allow",
        "Principal" : {
          "AWS" : "arn:aws:iam::${ACCT_ID}:role/VenafiPolicyLambdaRole"
        },
        "Action" : [ "kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey" ],
        "Resource" : "${KMS_KEY_ARN}"
      }, {
        "Sid" : "Allow attachment of persistent resources",
        "Effect" : "Allow",
        "Principal" : {
          "AWS" : "arn:aws:iam::${ACCT_ID}:role/VenafiPolicyLambdaRole"
        },
        "Action" : [ "kms:CreateGrant", "kms:ListGrants", "kms:RevokeGrant" ],
        "Resource" : "${KMS_KEY_ARN}",
        "Condition" : {
          "Bool" : {
            "kms:GrantIsForAWSResource" : "true"
          }
        }
      } ]
    }
    EOF
    ```

1. Attach the policy to the key:
    ```bash
    aws kms put-key-policy --key-id ${KEY_ID} --policy-name default --policy file://key-policy.json 
    ```
2. Encrypt the credentials for authenticating with the Venafi service. This will be the TPP password for Venafi Platform
and the API key for Venafi Cloud.
    ```bash
    aws kms encrypt --key-id ${KEY_ID} --plaintext <password or API key> | jq -r .CiphertextBlob
    ```
    - Provide this encrypted string to the engineer who will deploy this Venafi serverless application.


### Engineer Instructions

1. Install SAM CLI: https://docs.aws.amazon.com/en_us/serverless-application-model/latest/developerguide/serverless-sam-cli-install.html

1. Login to the AWS web console, select the region where the Venafi Lambda functions will be deployed, then navigate to the
Serverless Appliation Repository, and select the Available Applications page:
https://us-east-1.console.aws.amazon.com/serverlessrepo/home?region=us-east-1#/available-applications

1. Search for "aws-private-ca-policy-venafi" and open it.

1. Enter the appropriate connection parameters for the Venafi service you are using.  `CLOUDAPIKEY` (encrypted string provided by
your IAM administrator) for Venafi Cloud or `TPPURL`, `TPPUSER`, and `TPPPASSWORD` (encrypted string provided by your IAM administrator)
for Venafi Platform.

1. In most cases for Venafi Platform you will need to specify a trust bundle because the Venafi Platform is commonly secured
using a certificate issued by a private enterprise PKI.  Do this by entering the base64-encoded string that represents the
contents of your PEM trust bundle in the `TrustBundle` parameter. This string can be obtained using the following:
    ```bash
    cat /opt/venafi/bundle.pem | base64 --wrap=10000
    ``` 

1. To allow automatic retrieval of Venafi policy when a zone is requested that isn't been loaded, set `SavePolicyFromRequest` to "true".

1. Change `DEFAULTZONE` parameter to the name of the zone that will be used when none is specified in the request.
 
1. Click the Deploy button to deploy the CloudFormation stack for this solution and wait until the deployment is finished.
    
1. Add the `DEFAULTZONE` zone (and any other zones you want to pre-load) to the database so the Venafi policy will be retrieved:
    ```bash
    aws dynamodb put-item --table-name VenafiCertPolicy --item '{"PolicyID": {"S":"Default"}}'
    ```
1. Check the logs to verify the Venafi Lambda functions are working propertly and the Venafi policy is retrieved: 
    ```bash
    sam logs -n VenafiCertPolicyLambda --stack-name serverlessrepo-aws-private-ca-policy-venafi
    sam logs -n VenafiCertRequestLambda --stack-name serverlessrepo-aws-private-ca-policy-venafi
    ```    
1. To view the policy retrieved from Venafi for the zone:
    ```bash
    aws dynamodb get-item --table-name VenafiCertPolicy --key '{"PolicyID": {"S":"Default"}}'
    ```    
1. To get the URL of the API Gateway endpoint:
    ```bash
    aws cloudformation describe-stacks --stack-name serverlessrepo-aws-private-ca-policy-venafi | jq -r .Stacks[].Outputs[].OutputValue
    ```    
1. To check pass-through functionality:
    ```bash
    URL=$(aws cloudformation describe-stacks --stack-name serverlessrepo-aws-private-ca-policy-venafi | jq -r .Stacks[].Outputs[].OutputValue)
    aws acm-pca list-certificate-authorities --endpoint-url $URL
    ```    

## Requesting Certificates

The API for this solution is intentionally almost identical to the Amazon ACM API. Sample client code that demonstrates API usage
is provided in the [client-example/cli.py](client-example/cli.py).  With it you can request a certificate from ACM:
```bash
./cli.py request --domain "example.example.com" --base-url "https://cdvq35y9o2.execute-api.eu-west-1.amazonaws.com/v1/request" --policy Default
```
Or sign your CSR with the ACM Private CA (PCA):
```bash
python3 client-example/cli.py issue --csr-path "/home/user/csr.pem" --base-url "https://cdvq35y9o2.execute-api.eu-west-1.amazonaws.com/v1/request" --policy Default --arn "arn:aws:acm-pca:eu-west-1:497086895112:certificate-authority/cadaae4b-26c7-4c57-9ba1-f00d4e20beb2"
```

### Sample request body using a CSR

```json
{
  "SigningAlgorithm": "SHA256WITHRSA",
  "Validity": {
    "Type": "DAYS",
    "Value": 365
  },
  "CertificateAuthorityArn": "arn:aws:acm-pca:eu-west-1:123456789:certificate-authority/62x54216-14hf-47cd-98h4-a483a73b149f",
  "Csr": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJRlNqQ0NBeklDQVFBd2dhUXhDekFKQmdOVkJBWVRBbGRETVEwd0N3WURWUVFJREFSVmRHRm9NUmN3RlFZRApWUVFIREE1WGNtOXVaeUJNYjJOaGJHbDBlVEVTTUJBR0ExVUVDZ3dKVjNKdmJtY2dUM0puTVJNd0VRWURWUVFMCkRBcFhjbTl1WnlCVmJtbDBNUjR3SEFZSktvWklodmNOQVFrQkZnOWxiV0ZwYkVCM2NtOXVaeTVqYjIweEpEQWkKQmdOVkJBTU1HM1JsYzNRdFkzTnlMVE15TXpFek1UTXhMbmR5YjI1bkxtTnZiVENDQWlJd0RRWUpLb1pJaHZjTgpBUUVCQlFBRGdnSVBBRENDQWdvQ2dnSUJBTHV3RlhqUWswQlkyejM1dVM3cnArdHB6blpTMm95WTFIWkMyWlhiCnc4dklwOVVPb1lhOSs5MTlHbCsyOFpyMUswQ2xXLzRWWTRoL3A5M0h4dWFKMEVtZzlQbEYycUh2d2JSK3VZMS8KblkrME5LMWRlTnk0eEIxRDBSUTl6TVVMelloRlhSRTByeXJjRUZWbWFkNzV0UFFjdm4rczYxRzRpdFkyOHVWdQpkKzdJS2tNQnZmMXQyNTE2ZHdyRDltTVA1bFVaUWFMZ2VNdkJXaC9kRHQ5NEFnL01JY0hvN2NlT1R1TWUxMElJCnRxekJ6Ni9xY0NZdDJnbEtvSkZzbURvbVIzeC8yOTQ1MW5GN29ySUZhZmczZFh1bThMUXkyNlhHOWo4ZmNVVXoKRHhRSFBwNDBrOE9jMnBIdXFLbzdjQ3U5T3FsNFArRjlFR25nMWRKd01tVk9RYnVVajBPZHFrVkh3eWdhYngvdwozV2ZCWnFkRllia3ZPRllKaU1DM2IrN0dzV1B2cWY5L2VBK2w0Vm5xLzhMd1VRYktkdDIzazdNRHp3NzV1cU8vCnNudGtCdzlYZ1Flbnk2cDRzN2IwbExpRm15S3dpS1Njd3MvZHdkUTVzNnkrSDd1NmxRTmZzaWNEaXRUUE1QMjAKRVEzbm5qTTlFTmZFaERsN011aHliK0RBYjdWczFyQVJjNkJPY2x3eFlVRE1OT0VyUkJxZWRSQ3JqMW5jaE94eQpITTROei9Dc24rUGhIeW9PRnVDR2RjMGxydmVnak5GL2luVllsaWN5enFINldVbG5OVWc0azJucmhQSndVbzc5CkZLc0ovVUVzTnZyeFNyNUw3a1g2bC9GNkRLTEhYWDVrVkVGRC84M21UVE9LdzhBV1R3OTZBU0VYN0ozQW1ZN0MKOGYvUEFnTUJBQUdnWURCZUJna3Foa2lHOXcwQkNRNHhVVEJQTUUwR0ExVWRFUVJHTUVTQ0lHRnNkREV0ZEdWegpkQzFqYzNJdE16SXpNVE14TXpFdWQzSnZibWN1WTI5dGdpQmhiSFF5TFhSbGMzUXRZM055TFRNeU16RXpNVE14CkxuZHliMjVuTG1OdmJUQU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FnRUFuVk0zemkrWmVrbnBnM1IvWFR5VllkcFgKMzFFQTBhRGc3U1ZtNmlTSXlEMWlJVFBKUTFmR0RZMy9HYVJVZEQ1VEx6bXlPb2hGUzRkajJGVjJ6Umk5QnpmVQp4cWd5NXpPTkd0WHh6ZWZpRENpY2MxYVAyZWR1aVEvR2cxTlNNb3BPWUs1cHBLZlBIcVNwK2s0TzNvWXBuM29TCmxrb3g3ZGV6ODRndzNUZEE2OEVGaXpFN0pid1JWNkNDaXQ0RVkxWkhNL3R6aEJvZ21yOXlEeGRObE5kMXp6VEwKdFdNUlUydk9WdWJiR0NTY2FwSmVoVEljK2FPY2hOR3J4RGF6bVJ3VnVWRklFNE13KzlBTEpKM3JKdkdxWjZYRgo1RmswVFZTdU9UdG80bTBXSFVBaCtWZXlmVjRaWkVId1J0Q3YweTdlN21wN1pIaUZLSHNHVVQyTGw3U3NwMm8rCmdkdndYclBzV2hrYnZ1TzlDUXVoNzVCUkNEcWdCTzRlVnpJWjVEQnVyNS9IOE5sNnk5TTQ0TWgyTFJSL0ZZcjUKcFN5ZWx2M2pwR091SXE0b2JOY2gyeVlMRHdmdEVtN0t1UUk0WVVwc1pGWlhlTVVtdktvcDFyVkJxTGVqY290SwpOd25rR0hvRzN4ZUNrM3gwMWFmMDlCN1lKZk1uVi9IQ2gzazVnZjhYR2dkcGZOZzRNanNyWVJkRlEvZk5UaXYxCmI3L2pEQkhsWG94NE54cHRnMmFBU0RKUjNpRmZNZEJqdTU0OFNBZUQ5ODRscS9sWGNqSUkyeUw2aDhWa0NRcGQKa0JMQ2JPeWxObkx1L0NHZDkwN2ZwQnBXUTZycHRHTG5WRUFzMmFiMDJtY0QwVWw0aVZBNGxYb0xsajM5Skd5QgpsSUNjV1NBMUdxejM0SUFYSmNvPQotLS0tLUVORCBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0K"
}
```

The `Csr` parameter is a base64-encoded string of the actual PKCS#10 CSR. This request is the same as ACM PCA
[IssueCertificate](https://docs.aws.amazon.com/acm-pca/latest/APIReference/API_IssueCertificate.html) API method.

Additionally you can add `VenafiZone` parameter to indicate the request should be checked against Venafi policy for a non-default zone:

```json
{
  "SigningAlgorithm": "SHA256WITHRSA",
  "Validity": {
    "Type": "DAYS",
    "Value": 365
  },
  "CertificateAuthorityArn": "arn:aws:acm-pca:eu-west-1:123456789:certificate-authority/62x54216-14hf-47cd-98h4-a483a73b149f",
  "Csr": "LS0tLS1CRUd....",
  "VenafiZone": "aws-lambda-policy"
}

```
     
#### Pass-Through
Besides handling certificate requests, the Venafi Certificate Request Lambda can pass-through other ACM actions from native AWS tools
to ACM and ACMPCA.  Sample code for this is provided in [client-example/cli.py](client-example/cli.py).  This is very similar to the
standard Amazon API except the period (.) needs to be removed from the command name in `X-Amz-Target` header
(e.g. `ACMPrivateCA.GetCertificate` transforms to `ACMPrivateCAGetCertificate`).

### Cleanup
To delete deployed stack run:
```bash
aws cloudformation delete-stack --stack-name serverlessrepo-aws-private-ca-policy-venafi
aws cloudformation wait stack-delete-complete --stack-name serverlessrepo-aws-private-ca-policy-venafi
```

## Developer Instructions (for contributions to this solution or customization)

### AWS Configuration Steps:

1. Run `make build` to make binaries

1. Create SAM package, it will also deploy Lambda binary to S3:
    ```bash
    sam package \
        --output-template-file packaged.yaml \
        --s3-bucket venafi-policy-sam
    ```

1. Deploy the SAM package to AWS:
    ```bash
    sam deploy \
        --template-file packaged.yaml \
        --stack-name private-ca-policy-venafi \
        --capabilities CAPABILITY_IAM \
        --region <put your region here>
    ```

1. Copy `aws-policies/api-resource-policy-example.json` to `resource-policy.json` and and customize the settings.

1. Apply the policy to the API endpoint. To get the api-id, run the `aws apigateway get-rest-apis` command.
    Example:
    ```bash
    API_ID=$(aws apigateway get-rest-apis | jq -r .items[].id)
    aws apigateway update-rest-api \
        --rest-api-id ${API_ID} \
        --patch-operations \
        op=replace,path=/policy,value=$(jq -c -a @text resource-policy.json)
    ``` 

## License

Copyright &copy; Venafi, Inc. All rights reserved.

This solution is licensed under the Apache License, Version 2.0. See `LICENSE` for the full license text.

Please direct questions/comments to opensource@venafi.com.
