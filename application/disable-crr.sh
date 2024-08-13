#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
aws lambda invoke --function-name apcManageSetup --cli-binary-format raw-in-base64-out --payload file://disable-crr.json out --log-type Tail --query 'LogResult' --output text |  base64 -d
