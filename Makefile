CERT_REQUEST_NAME := aws-lambda-venafi-cert-request

build:
	rm -rf dist/
	mkdir -p dist
	env GOOS=linux GOARCH=amd64 go build -o dist/$(CERT_REQUEST_NAME) ./cmd/cert-request
	zip dist/$(CERT_REQUEST_NAME).zip dist/$(CERT_REQUEST_NAME)