CERT_REQUEST_NAME := cert-request
CERT_REQUEST_VERSION := 0.0.1
CERT_POLICY_NAME := cert-policy
CERT_REQUEST_VERSION := 0.0.1
STACK_NAME := private-ca-policy-venafi
REGION := eu-west-1

build_request:
	rm -rf dist/$(CERT_REQUEST_NAME)*
	mkdir -p dist
	env GOOS=linux GOARCH=amd64 go build -o dist/$(CERT_REQUEST_NAME) ./request
	zip dist/$(CERT_REQUEST_NAME).zip dist/$(CERT_REQUEST_NAME)

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
	rm -rf dist/$(CERT_POLICY_NAME)*
	mkdir -p dist
	env GOOS=linux GOARCH=amd64 go build -o dist/$(CERT_POLICY_NAME) ./policy
	zip dist/$(CERT_POLICY_NAME).zip dist/$(CERT_POLICY_NAME)

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