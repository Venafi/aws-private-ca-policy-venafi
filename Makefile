CERT_REQUEST_NAME := cert-request
CERT_REQUEST_LAMBDA_NAME := CertRequestLambda
CERT_REQUEST_DEPLOYED_LAMBDA_NAME := $$(aws lambda list-functions |jq -r '.Functions[].FunctionName|select(.| contains("$(CERT_REQUEST_LAMBDA_NAME)"))')
CERT_REQUEST_VERSION := 0.0.1

CERT_POLICY_NAME := cert-policy
CERT_POLICY_LAMBDA_NAME := CertPolicyLambda
CERT_POLICY_DEPLOYED_LAMBDA_NAME := $$(aws lambda list-functions |jq -r '.Functions[].FunctionName|select(.| contains("$(CERT_POLICY_LAMBDA_NAME)"))')
CERT_POLICY_VERSION := 0.0.1

STACK_NAME := serverlessrepo-aws-private-ca-policy-venafi
REGION := eu-west-1

# List of tests to run
TEST ?= $$(go list ./... | grep -v /vendor/ | grep -v /e2e)
TEST_TIMEOUT?=6m
ARN ?= $$(aws acm-pca list-certificate-authorities|jq -c --arg Status "ACTIVE" '.CertificateAuthorities[] | select(.Status == $$Status)'|jq -r .Arn)

SWITCHABLE_CA_ARN := arn:aws:acm-pca:eu-west-1:497086895112:certificate-authority/cadaae4b-26c7-4c57-9ba1-f00d4e20beb2

test:
	go test $(TEST) $(TESTARGS)  -v -cover -timeout=$(TEST_TIMEOUT) -parallel=20

sam_local_invoke:
	for e in `ls fixtures/events/*-event.json`; do sam local invoke CertRequestLambda -e $$e; done

build: build_request build_policy

deploy: sam_deploy

build_request:
	rm -rf dist/$(CERT_REQUEST_NAME)
	mkdir -p dist/$(CERT_REQUEST_NAME)
	env GOOS=linux GOARCH=amd64 go build -o dist/$(CERT_REQUEST_NAME)/$(CERT_REQUEST_NAME) ./request

deploy_request:
	zip dist/$(CERT_REQUEST_NAME)/$(CERT_REQUEST_NAME).zip dist/$(CERT_REQUEST_NAME)/$(CERT_REQUEST_NAME)
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

deploy_policy:
	zip dist/$(CERT_POLICY_NAME)/$(CERT_POLICY_NAME).zip dist/$(CERT_POLICY_NAME)/$(CERT_POLICY_NAME)
	aws lambda delete-function --function-name $(CERT_POLICY_NAME) || echo "Function doesn't exists"
	aws lambda create-function --function-name $(CERT_POLICY_NAME) --runtime go1.x \
	--role arn:aws:iam::$(ACC_ID):role/lambda-venafi-role \
	--handler $(CERT_POLICY_NAME) --zip-file fileb://dist/$(CERT_POLICY_NAME).zip

update_policy_code:
	aws lambda update-function-code --function-name $(CERT_POLICY_NAME) \
    --zip-file fileb://dist/$(CERT_POLICY_NAME).zip

#SAM commands
sam_package:
	sam package \
        --output-template-file packaged.yaml \
        --s3-bucket aws-private-ca-policy-venafi

sam_deploy_cloud:
	aws cloudformation deploy \
        --template-file packaged.yaml \
        --stack-name $(STACK_NAME) \
        --capabilities CAPABILITY_IAM \
        --region $(REGION) \
        --parameter-overrides CLOUDAPIKEY=$$CLOUDAPIKEY_ENC CLOUDURL=$$CLOUDURL
	aws cloudformation wait stack-create-complete --stack-name $(STACK_NAME)
	aws cloudformation describe-stacks --stack-name $(STACK_NAME)|jq .Stacks[].Outputs

sam_deploy_tpp:
	aws cloudformation deploy \
        --template-file packaged.yaml \
        --stack-name $(STACK_NAME) \
        --capabilities CAPABILITY_IAM \
        --region $(REGION) \
        --parameter-overrides TPPUSER=$$TPPUSER,TPPURL=$$TPPURL,TPPPASSWORD=$$TPPPASSWORD_ENC
	aws cloudformation wait stack-create-complete --stack-name $(STACK_NAME)
	aws cloudformation describe-stacks --stack-name $(STACK_NAME)|jq .Stacks[].Outputs

sam_delete:
	aws cloudformation delete-stack --stack-name $(STACK_NAME)
	aws cloudformation wait stack-delete-complete --stack-name $(STACK_NAME)

sam_update: sam_package
	aws cloudformation update-stack --stack-name $(STACK_NAME) --template-body file://packaged.yaml --capabilities CAPABILITY_AUTO_EXPAND
	aws cloudformation wait stack-update-complete --stack-name $(STACK_NAME)

sam_publish: sam_package
	sam publish \
        --template packaged.yaml \
        --region $(REGION)

get_proxy:
	aws cloudformation --region $(REGION) describe-stacks --stack-name $(STACK_NAME) --query "Stacks[0].Outputs[0].OutputValue"

get_request_logs:
	sam logs -n $(CERT_REQUEST_LAMBDA_NAME) --stack-name $(STACK_NAME)

get_policy_logs:
	sam logs -n $(CERT_POLICY_LAMBDA_NAME) --stack-name $(STACK_NAME)

get_lambdas_config:
	aws lambda get-function-configuration --function-name  $(CERT_POLICY_DEPLOYED_LAMBDA_NAME)
	aws lambda get-function-configuration --function-name  $(CERT_REQUEST_DEPLOYED_LAMBDA_NAME)

#ACM\PCA commands
list_acm_arn:
	aws acm-pca list-certificate-authorities|jq .CertificateAuthorities[0].Arn

acmpca_create:
	aws acm-pca create-certificate-authority --certificate-authority-configuration file://fixtures/acmpca-test-config.json \
	--certificate-authority-type "SUBORDINATE"|jq -r .CertificateAuthorityArn > caarn.txt
	aws acm-pca wait certificate-authority-csr-created --certificate-authority-arn $$(cat caarn.txt)	

create_internal_ca:
	openssl genrsa -out fixtures/InternalCA-Root.key 2048
	openssl req -x509 -new -nodes -key fixtures/InternalCA-Root.key \
    -sha256 -days 3650 -out fixtures/InternalCA-Root.crt \
    -subj "/CN=VenafiInternalCA-Root"

acmpca_import_ca:
	aws acm-pca get-certificate-authority-csr --certificate-authority-arn $$(cat caarn.txt)|jq .Csr|xargs echo -e > fixtures/ACMPCA-CA.csr
	openssl x509 -req -days 365 -in fixtures/ACMPCA-CA.csr \
	-CA fixtures/InternalCA-Root.crt \
	-CAcreateserial \
	-CAkey fixtures/InternalCA-Root.key \
	-extfile fixtures/openssl-ca-extensions.ext \
	-sha256 -out fixtures/ACMPCA-CA.crt
	aws acm-pca import-certificate-authority-certificate --certificate-authority-arn $$(cat caarn.txt) \
	--certificate file://fixtures/ACMPCA-CA.crt --certificate-chain file://fixtures/InternalCA-Root.crt

create_acmpca: acmpca_create create_internal_ca acmpca_import_ca

delete_acmpca:
	aws acm-pca update-certificate-authority --certificate-authority-arn $$(cat caarn.txt) --status DISABLED
	aws acm-pca delete-certificate-authority --certificate-authority-arn $$(cat caarn.txt) --permanent-deletion-time-in-days 7

acmpca_list:
	@aws acm-pca list-certificate-authorities

acmpca_status:
	aws acm-pca list-certificate-authorities | jq .CertificateAuthorities[].Status

acmpca_list_active_ca:
	aws acm-pca list-certificate-authorities|jq -c --arg Status "ACTIVE" '.CertificateAuthorities[] | select(.Status == $$Status)'|jq .

acmpca_get_arn:
	@echo $(ARN)

acmpca_enable:
	aws acm-pca restore-certificate-authority --certificate-authority-arn $(SWITCHABLE_CA_ARN)
	aws acm-pca update-certificate-authority --certificate-authority-arn $(SWITCHABLE_CA_ARN) --status ACTIVE

acmpca_disable:
	aws acm-pca update-certificate-authority --certificate-authority-arn $(SWITCHABLE_CA_ARN) --status DISABLED
	aws acm-pca delete-certificate-authority --certificate-authority-arn $(SWITCHABLE_CA_ARN) --permanent-deletion-time-in-days 30
