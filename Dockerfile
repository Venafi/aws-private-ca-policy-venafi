FROM python:latest
WORKDIR /aws-private-ca-policy-venafi
RUN pip install awscli
RUN pip install aws-sam-cli
