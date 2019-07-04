package main

import (
	"context"
	"github.com/Venafi/aws-lambda-venafi/common"
	"github.com/aws/aws-lambda-go/lambda"
	"net/http"
)

func HandleRequest(ctx context.Context) (string, error) {
	http.Get("https://subbot.in/")
	common.GetPolicy("test")
	return "Hello World!", nil
}

func main() {

	lambda.Start(HandleRequest)
}
