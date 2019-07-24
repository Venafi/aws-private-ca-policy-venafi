package common

import (
	"context"
	"github.com/Venafi/vcert/pkg/endpoint"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/external"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/dynamodbattribute"
	"os"
)

var tableName string

const primaryKey = "PolicyID"

type venafiError string

func (e venafiError) Error() string {
	return string(e)
}

const PolicyNotFound venafiError = "policy not found"

func init() {
	tableName = os.Getenv("DYNAMODB_ZONES_TABLE")
	if tableName == "" {
		tableName = "cert-policy"
	}
	cfg, err := external.LoadDefaultAWSConfig()
	if err != nil {
		panic("unable to load SDK config, " + err.Error())
	}
	db = dynamodb.New(cfg)
}

var db *dynamodb.Client

func GetPolicy(name string) (p endpoint.Policy, err error) {

	input := &dynamodb.GetItemInput{
		TableName: aws.String(tableName),
		Key: map[string]dynamodb.AttributeValue{
			primaryKey: {
				S: aws.String(name),
			},
		},
	}

	result, err := db.GetItemRequest(input).Send(context.Background())
	if err != nil {
		return
	}
	if result.Item == nil {
		err = PolicyNotFound
		return
	}

	err = dynamodbattribute.UnmarshalMap(result.Item, &p)
	if err != nil {
		return
	}

	return
}

func CreateEmptyPolicy(name string) error {
	av := make(map[string]dynamodb.AttributeValue)
	av[primaryKey] = dynamodb.AttributeValue{S: aws.String(name)}
	input := &dynamodb.PutItemInput{
		Item:      av,
		TableName: aws.String(tableName),
	}
	_, err := db.PutItemRequest(input).Send(context.Background())
	return err
}

func SavePolicy(name string, p endpoint.Policy) error {
	av, err := dynamodbattribute.MarshalMap(p)
	if err != nil {
		return err
	}
	av[primaryKey] = dynamodb.AttributeValue{S: aws.String(name)}
	input := &dynamodb.PutItemInput{
		Item:      av,
		TableName: aws.String(tableName),
	}

	_, err = db.PutItemRequest(input).Send(context.Background())
	return err
}

func GetAllPoliciesNames() (names []string, err error) {
	var t = db
	result, err := t.ScanRequest(&dynamodb.ScanInput{TableName: &tableName}).Send(context.Background())
	if err != nil {
		return
	}
	names = make([]string, 0, len(result.Items))
	for _, v := range result.Items {
		name := *v[primaryKey].S
		names = append(names, name)
	}
	return
}

func DeletePolicy(name string) error {
	input := &dynamodb.DeleteItemInput{
		TableName: aws.String(tableName),
		Key: map[string]dynamodb.AttributeValue{
			primaryKey: {
				S: aws.String(name),
			},
		},
	}

	_, err := db.DeleteItemRequest(input).Send(context.Background())
	if err != nil {
		return err
	}
	return nil
}
