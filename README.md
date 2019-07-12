#This is work in progress

##AWS Lambda Venafi integration

###AWS Configuration steps (for developers:

1. Run `make build` to make binaries

1. Run `make sam_package` to create AWS SAM stack

1. Run `make sam_deploy` to deploy stack to AWS

1. Copy resource-policy-example.json to resource-policy.json and edit it

1. Apply policy to API endpoint (you can api-id by running command `aws apigateway get-rest-apis`)
    ```bash
    aws apigateway update-rest-api \
        --rest-api-id api-id \
        --patch-operations \
        op=replace,path=/policy,value=$(jq -c -a @text resource-policy-example.json)
    ``` 