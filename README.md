# This is work in progress

## AWS Lambda Venafi integration

![Self-editing Diagram](Diagram.svg)

### AWS Configuration steps (for developers:

1. Run `make build` to make binaries

1. Create SAM package, it will also deploy lambda binary to s3:
    ```bash
    sam package \
            --output-template-file packaged.yaml \
            --s3-bucket venafi-pca-policy
    ```

1. Deploy stack to AWS:
    ```bash
    sam deploy \
        --template-file packaged.yaml \
        --stack-name venafi-pca-policy \
        --capabilities CAPABILITY_IAM \
        --region <put your region here>
    ```

1. Copy resource-policy-example.json to resource-policy.json and edit it

1. Apply policy to API endpoint (you can api-id by running command `aws apigateway get-rest-apis`)
    ```bash
    aws apigateway update-rest-api \
        --rest-api-id api-id \
        --patch-operations \
        op=replace,path=/policy,value=$(jq -c -a @text resource-policy.json)
    ``` 