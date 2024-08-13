#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
json_file=enable-crr.json
key_to_check="dest_region" 

# Get the AWS region from the credentials file
aws_region=$(aws configure get region) 

value=$(jq -r ".$key_to_check" $json_file)

if [ "$value" == "$aws_region" ]; then
  echo "You are trying to deploy the CRR Destination Region at the same region as the Origin."
  echo "Please change the value of $key_to_check in $json_file to a different region."
  echo "Origin Region deployed: $value. Destination Region configured: $aws_region"
else
  echo "Deploy Initiated in $value"
  echo ""
  echo ""
  aws lambda invoke --function-name apcManageSetup --cli-binary-format raw-in-base64-out --payload file://enable-crr.json out --log-type Tail --query 'LogResult' --output text |  base64 -d
fi
