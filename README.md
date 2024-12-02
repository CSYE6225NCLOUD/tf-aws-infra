# tf-aws-infra

Contains tf files-
variables
main
providers
version

Added yml for CI
commands to import ssl certificate
aws acm import-certificate \  
 --certificate file:///Users/shubhamlakhotia/CloudComputing/demo_shubhamlakhotia_me/cert-base64.pem \
 --private-key file:///Users/shubhamlakhotia/CloudComputing/key-base64.key \
 --certificate-chain file:///Users/shubhamlakhotia/CloudComputing/demo_shubhamlakhotia_me/chain-base64.pem \
 --region us-east-1
