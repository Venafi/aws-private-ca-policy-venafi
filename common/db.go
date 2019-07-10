package common

import (
	"github.com/Venafi/vcert/pkg/endpoint"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"os"
)

var tableName string

const primaryKey = "PolicyID"

func init() {
	tableName = os.Getenv("DYNAMODB_ZONES_TABLE")
	if tableName == "" {
		tableName = "cert-policy"
	}
}

var db = dynamodb.New(session.New(), aws.NewConfig())

func GetPolicy(name string) (p endpoint.Policy, err error) {

	input := &dynamodb.GetItemInput{
		TableName: aws.String(tableName),
		Key: map[string]*dynamodb.AttributeValue{
			primaryKey: {
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
	av[primaryKey] = &dynamodb.AttributeValue{S: aws.String(name)}
	input := &dynamodb.PutItemInput{
		Item:      av,
		TableName: aws.String(tableName),
	}

	_, err = db.PutItem(input)
	if err != nil {
		return err
	}
	return nil
}

func GetAllPoliciesNames() (names []string, err error) {
	result, err := db.Scan(&dynamodb.ScanInput{TableName: &tableName})
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
		Key: map[string]*dynamodb.AttributeValue{
			primaryKey: {
				S: aws.String(name),
			},
		},
	}

	_, err := db.DeleteItem(input)
	if err != nil {
		return err
	}
	return nil
}
