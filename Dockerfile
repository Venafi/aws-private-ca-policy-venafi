FROM golang:1.7.3 as build
WORKDIR /aws-private-ca-policy-venafi
COPY . .