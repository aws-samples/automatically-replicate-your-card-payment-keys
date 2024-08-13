#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
import os

import aws_cdk as cdk
from apc_crr.apc_crr_stack import ApcCrrStack


app = cdk.App()
stack = ApcCrrStack(app, "apc-crr",
                    env=cdk.Environment(account=os.getenv(
                        'CDK_DEFAULT_ACCOUNT'), region=os.getenv('CDK_DEFAULT_REGION'))
                    )
app.synth()
