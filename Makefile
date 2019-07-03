CERT_REQUEST_NAME := cert-request
CERT_POLICY_NAME := cert-policy

build_request:
	rm -rf dist/
	mkdir -p dist
	env GOOS=linux GOARCH=amd64 go build -o dist/$(CERT_REQUEST_NAME) ./cmd/cert-request
	zip dist/$(CERT_REQUEST_NAME).zip dist/$(CERT_REQUEST_NAME)

deploy_request:
	aws lambda delete-function --function-name $(CERT_REQUEST_NAME) || echo "Function doesn't exists"
	aws lambda create-function --function-name $(CERT_REQUEST_NAME) --runtime go1.x \
	--role arn:aws:iam::$(ACC_ID):role/lambda-venafi-role \
	--handler $(CERT_REQUEST_NAME) --zip-file fileb://dist/$(CERT_REQUEST_NAME).zip

update_request_code:
	aws lambda update-function-code --function-name $(CERT_REQUEST_NAME) \
    --zip-file fileb://dist/$(CERT_REQUEST_NAME).zip

build_policy:
	rm -rf dist/
	mkdir -p dist
	env GOOS=linux GOARCH=amd64 go build -o dist/$(CERT_POLICY_NAME) ./cmd/cert-policy
	zip dist/$(CERT_POLICY_NAME).zip dist/$(CERT_POLICY_NAME)

deploy_policy:
	aws lambda delete-function --function-name $(CERT_POLICY_NAME) || echo "Function doesn't exists"
	aws lambda create-function --function-name $(CERT_POLICY_NAME) --runtime go1.x \
	--role arn:aws:iam::$(ACC_ID):role/lambda-venafi-role \
	--handler $(CERT_POLICY_NAME) --zip-file fileb://dist/$(CERT_POLICY_NAME).zip

update_policy_code:
	aws lambda update-function-code --function-name $(CERT_POLICY_NAME) \
    --zip-file fileb://dist/$(CERT_POLICY_NAME).zip