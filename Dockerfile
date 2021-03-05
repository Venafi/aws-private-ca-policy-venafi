FROM python:latest
WORKDIR /aws-private-ca-policy-venafi
COPY . .
RUN pip install aws-sam-cli