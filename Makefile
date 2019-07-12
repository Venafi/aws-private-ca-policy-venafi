CERT_REQUEST_NAME := cert-request
CERT_REQUEST_LAMBDA_NAME := CertRequestLambda
CERT_REQUEST_VERSION := 0.0.1

CERT_POLICY_NAME := cert-policy
CERT_POLICY_LAMBDA_NAME := CertPolicyLambda
CERT_POLICY_VERSION := 0.0.1

STACK_NAME := private-ca-policy-venafi
REGION := eu-west-1

# List of tests to run
TEST ?= $$(go list ./... | grep -v /vendor/ | grep -v /e2e)
TEST_TIMEOUT?=6m

test:
	go test $(TEST) $(TESTARGS) -v -timeout=$(TEST_TIMEOUT) -parallel=20

build_request:
	rm -rf dist/$(CERT_REQUEST_NAME)
	mkdir -p dist/$(CERT_REQUEST_NAME)
	env GOOS=linux GOARCH=amd64 go build -o dist/$(CERT_REQUEST_NAME)/$(CERT_REQUEST_NAME) ./request
	zip dist/$(CERT_REQUEST_NAME)/$(CERT_REQUEST_NAME).zip dist/$(CERT_REQUEST_NAME)/$(CERT_REQUEST_NAME)

deploy_request:
	aws lambda delete-function --function-name $(CERT_REQUEST_NAME) || echo "Function doesn't exists"
	aws lambda create-function --function-name $(CERT_REQUEST_NAME) --runtime go1.x \
	--role arn:aws:iam::$(ACC_ID):role/lambda-venafi-role \
	--handler $(CERT_REQUEST_NAME) --zip-file fileb://dist/$(CERT_REQUEST_NAME).zip

cloudformation_request:
	aws s3 mb s3://cert-request || echo "exists"
	aws cloudformation package \
	   --template-file templates/cert-request.yml \
	   --output-template-file templates/serverless-deploy-cert-request.yaml \
	   --s3-bucket cert-request
	aws cloudformation deploy \
	--template-file templates/serverless-deploy-cert-request.yaml \
	--stack-name $(CERT_REQUEST_NAME)-$(CERT_REQUEST_VERSION) \
	--capabilities CAPABILITY_IAM

update_request_code:
	aws lambda update-function-code --function-name $(CERT_REQUEST_NAME) \
    --zip-file fileb://dist/$(CERT_REQUEST_NAME).zip

build_policy:
	rm -rf dist/$(CERT_POLICY_NAME)
	mkdir -p dist/$(CERT_POLICY_NAME)
	env GOOS=linux GOARCH=amd64 go build -o dist/$(CERT_POLICY_NAME)/$(CERT_POLICY_NAME) ./policy
	zip dist/$(CERT_POLICY_NAME)/$(CERT_POLICY_NAME).zip dist/$(CERT_POLICY_NAME)/$(CERT_POLICY_NAME)

deploy_policy:
	aws lambda delete-function --function-name $(CERT_POLICY_NAME) || echo "Function doesn't exists"
	aws lambda create-function --function-name $(CERT_POLICY_NAME) --runtime go1.x \
	--role arn:aws:iam::$(ACC_ID):role/lambda-venafi-role \
	--handler $(CERT_POLICY_NAME) --zip-file fileb://dist/$(CERT_POLICY_NAME).zip

update_policy_code:
	aws lambda update-function-code --function-name $(CERT_POLICY_NAME) \
    --zip-file fileb://dist/$(CERT_POLICY_NAME).zip

#ACM commands
list_acm_arn:
	aws acm-pca list-certificate-authorities|jq .CertificateAuthorities[0].Arn

#SAM commands
sam_package:
	sam package \
        --output-template-file packaged.yaml \
        --s3-bucket venafi-policy-sam

sam_deploy:
	sam deploy \
        --template-file packaged.yaml \
        --stack-name $(STACK_NAME) \
        --capabilities CAPABILITY_IAM \
        --region $(REGION)

sam_delete:
	aws cloudformation delete-stack --stack-name $(STACK_NAME)

get_proxy:
	aws cloudformation --region $(REGION) describe-stacks --stack-name $(STACK_NAME) --query "Stacks[0].Outputs[0].OutputValue"

get_logs:
	sam logs -n $(CERT_REQUEST_LAMBDA_NAME) --stack-name $(STACK_NAME)

sam_invoke_request:
	sam local invoke "$(CERT_REQUEST_LAMBDA_NAME)" -e event.json

sam_invoke_policy:
	sam local invoke "CERT_POLICY_LAMBDA_NAME" -e event.json

tests:
	go test -v -cover common/*
	go test -v -cover policy/*
	go test -v -cover request/*