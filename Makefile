NAME := aws-lambda-venafi

build:
	rm -rf dist/
	mkdir -p dist
	env GOOS=linux GOARCH=amd64 go build -o dist/$(NAME) main.go
	zip dist/$(NAME).zip dist/$(NAME)