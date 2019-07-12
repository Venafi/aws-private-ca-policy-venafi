#This is work in progress

##AWS Lambda Venafi integration

###AWS Configuration steps (for developers:

1. Run `make build` to make binaries

1. Run `make sam_package` to create AWS SAM stack

1. Run `make sam_deploy` to deploy stack to AWS

1. Edit resource-policy-example.json

1. Apply policy to API endpoint
    ```bash
    
    ``` 

1. Get your ACM ARN:
    ```
    aws acm-pca list-certificate-authorities|jq .CertificateAuthorities[0].Arn
    ```

1.  