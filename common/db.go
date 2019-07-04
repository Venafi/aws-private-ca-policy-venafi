package common

import (
	"github.com/Venafi/vcert/pkg/endpoint"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
)

var db = dynamodb.New(session.New(), aws.NewConfig())

func GetPolicy(name string) (p endpoint.Policy, err error) {

	input := &dynamodb.GetItemInput{
		TableName: aws.String("zones"),
		Key: map[string]*dynamodb.AttributeValue{
			"Key": {
				S: aws.String(name),
			},
		},
	}

	result, err := db.GetItem(input)
	if err != nil {
		return
	}
	if result.Item == nil {
		return
	}

	err = dynamodbattribute.UnmarshalMap(result.Item, &p)
	if err != nil {
		return
	}

	return
}

func SavePolicy(name string, p endpoint.Policy) error {
	av, err := dynamodbattribute.MarshalMap(p)
	if err != nil {
		return err
	}
	input := &dynamodb.PutItemInput{
		Item:      av,
		TableName: aws.String("policies"),
	}

	_, err = db.PutItem(input)
	if err != nil {
		return err
	}
	return nil
}
