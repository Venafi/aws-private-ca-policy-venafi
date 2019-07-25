# This is work in progress

## AWS Lambda Venafi integration

#### How it works diagram

![Self-editing Diagram](Diagram.svg)

#### IAM user roles

1. Lambda role should have following policies assigned:
    AWSCertificateManagerPrivateCAUser
    AmazonDynamoDBFullAccess (TODO: this can be and should be reduced)
    
#### Example of user signing request:

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

Csr field is a base64 encoded string of actual CSR. This request is the same as ACM PCA IssueCertificate API - https://docs.aws.amazon.com/acm-pca/latest/APIReference/API_IssueCertificate.html
Additionally you can add VenafiZone field:

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

### AWS Configuration steps (for developers):

1. Create a lambda venafi role named lambda-venafi-role andd attach policies to it:
    ```bash
    aws iam create role --role-name lambda-venafi-role
    aws iam attach-role-policy --role-name lambda-venafi-role --policy-arn arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess
    aws iam attach-role-policy --role-name lambda-venafi-role --policy-arn arn:aws:iam::aws:policy/AWSCertificateManagerPrivateCAUser
    ```
1. Run `make build` to make binaries

1. Create SAM package, it will also deploy lambda binary to s3:
    ```bash
    sam package \
            --output-template-file packaged.yaml \
            --s3-bucket venafi-pca-policy
    ```

1. Deploy the SAM package to AWS:
    ```bash
    sam deploy \
        --template-file packaged.yaml \
        --stack-name venafi-pca-policy \
        --capabilities CAPABILITY_IAM \
        --region <put your region here>
    ```

1. Copy resource-policy-example.json to resource-policy.json and and customize the settings.

1. Apply the policy to the API endpoint. To get the api-id, run the `aws apigateway get-rest-apis` command.
    ```bash
    aws apigateway update-rest-api \
        --rest-api-id api-id \
        --patch-operations \
        op=replace,path=/policy,value=$(jq -c -a @text resource-policy.json)
    ``` 
    
1. Create policy item which will be synced:
    ```bash
    aws dynamodb put-item --table-name cert-policy --item '{"PolicyID": {"S":"Default"}}'
    ```
    
### Usage


To determine request type proper "X-Amz-Target" header must be set.  
TODO: List of headers here
     
#### Pass thru
Venafi lambda can pass standart requests to ACM and ACMPCA thru it. You should specify endpoint url to API deployed url. For example:
```bash
aws acm-pca list-certificate-authorities --endpoint-url http://localhost:3000/request
``` 

TODO: add logs configuration