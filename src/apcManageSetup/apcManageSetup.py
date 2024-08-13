# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
import boto3
import os
import botocore
from boto3.dynamodb.conditions import Key, Attr

AWS_ACCOUNT = os.environ['AWS_ACCOUNT']
ORIGIN_REGION = os.environ['ORIGIN_REGION']
ORIGIN_VPC_ID = os.environ['ORIGIN_VPC_ID']
ORIGIN_VPC_CIDR = os.environ['ORIGIN_VPC_CIDR']
ROLE_ARN = os.environ['ROLE_ARN']
DYNAMODB_TABLE_APC_CRR = os.environ['DYNAMODB_TABLE_APC_CRR']
TEMPLATE_URL = os.environ['TEMPLATE_URL']
DYNAMODB_TABLE_APC_CRR_STACK = os.environ['DYNAMODB_TABLE_APC_CRR_STACK']

dynamoDB = boto3.resource('dynamodb')


def update_item(table, item, key=None, append=None, attr=None):
    table = dynamoDB.Table(table)
    if (key and append):
        expression = 'SET ' + attr + ' = :item'
        table.update_item(
            Key=key,
            UpdateExpression=expression,
            ExpressionAttributeValues={
                ':item': item,
            },
            ReturnValues="UPDATED_NEW",
        )
    elif (key and not append):
        expression = 'SET ' + attr + ' = :item'
        table.update_item(
            Key=key,
            UpdateExpression=expression,
            ExpressionAttributeValues={
                ':item': item,
            }
        )
    else:
        table.put_item(Item=item)


def constructFilterExpression(conditions):
    expression = ""
    for idx, item in enumerate(conditions):
        if idx == 0:
            expression += f"Attr('{conditions[idx][0]}').eq('{conditions[idx][1]}')"
        else:
            expression += f" & Attr('{conditions[idx][0]}').eq('{conditions[idx][1]}')"
    return expression


def query_items(table, key, value, *conditions):
    table = dynamoDB.Table(table)
    try:
        filter_expression = constructFilterExpression(conditions)
        response = table.query(
            KeyConditionExpression=(
                Key(key).eq(value)
            ),
            FilterExpression=eval(filter_expression)
        )
    except botocore.exceptions.ClientError as error:
        raise error

    return response['Items']


def lambda_handler(event, context):
    if event['enabled']:

        dest_region = event['dest_region']
        dest_vpc_name = event['dest_vpc_name']
        dest_vpc_cidr = event['dest_vpc_cidr']
        dest_subnet1_cidr = event['dest_subnet1_cidr']
        dest_subnet2_cidr = event['dest_subnet2_cidr']
        dest_subnets_prefix_name = event['dest_subnets_prefix_name']
        dest_rt_prefix_name = event['dest_rt_prefix_name']

        cf_client = boto3.client('cloudformation', region_name=dest_region)
        crrObj = {
            'account_id': AWS_ACCOUNT,
            'lambda_request_id': context.aws_request_id,
            'origin_region': ORIGIN_REGION
        }
        crrObj['dest_region'] = event['dest_region']
        crrObj['kek_alias'] = 'alias/' + event['kek_alias'] + \
            context.aws_request_id.split("-")[4]
        crrObj['key_algo'] = event['key_algo']
        crrObj['krd_alias'] = 'alias/' + event['krd_alias'] + \
            context.aws_request_id.split("-")[4]
        crrObj['kdh_alias'] = 'alias/' + event['kdh_alias'] + \
            context.aws_request_id.split("-")[4]
        crrObj['sync_status'] = 'RESOURCES_CREATION_PENDING'

        try:
            stackId = cf_client.create_stack(
                StackName='-'.join(['apc-setup-orchestrator',
                                   context.aws_request_id]),
                TemplateURL=TEMPLATE_URL,
                DisableRollback=True,
                RoleARN=ROLE_ARN,
                Parameters=[
                    {
                        'ParameterKey': 'DestVpcCidr',
                        'ParameterValue': dest_vpc_cidr
                    },
                    {
                        'ParameterKey': 'DestVpcName',
                        'ParameterValue': dest_vpc_name
                    },
                    {
                        'ParameterKey': 'DestSubnet1Cidr',
                        'ParameterValue': dest_subnet1_cidr
                    },
                    {
                        'ParameterKey': 'DestSubnet2Cidr',
                        'ParameterValue': dest_subnet2_cidr
                    },
                    {
                        'ParameterKey': 'DestSubnetPrefixName',
                        'ParameterValue': dest_subnets_prefix_name
                    },
                    {
                        'ParameterKey': 'DestRouteTablePrefixName',
                        'ParameterValue': dest_rt_prefix_name
                    },
                    {
                        'ParameterKey': 'DestRegion',
                        'ParameterValue': dest_region
                    },
                    {
                        'ParameterKey': 'OriginRegion',
                        'ParameterValue': ORIGIN_REGION
                    },
                    {
                        'ParameterKey': 'OriginVpcId',
                        'ParameterValue': ORIGIN_VPC_ID
                    },
                    {
                        'ParameterKey': 'OriginVpcCidr',
                        'ParameterValue': ORIGIN_VPC_CIDR
                    },
                ]
            )
        except botocore.exceptions.ClientError as error:
            raise error

        try:
            update_item(DYNAMODB_TABLE_APC_CRR_STACK, {
                        'stack_id': stackId['StackId'], 'dest_region': dest_region, 'dest_vpc_cidr': dest_vpc_cidr, 'account_id': AWS_ACCOUNT, 'lambda_request_id': context.aws_request_id})
            update_item(DYNAMODB_TABLE_APC_CRR, crrObj)
        except botocore.exceptions.ClientError as error:
            raise error

        print('Setup has initiated. A CloudFormation template will be deployed in {0}.'.format(
            dest_region))
        print('Please check the apcStackMonitor log to follow the deployment status.')
        print('You can do that by checking the CloudWatch Logs Log group /aws/apc-crr/apcStackMonitor in the Management Console,')
        print('or by typing on a shell terminal: aws logs tail "/aws/lambda/apcStackMonitor" --follow')
        print('You can also check the CloudFormation Stack in the Management Console: Account {0}, Region {1}'.format(
            AWS_ACCOUNT, dest_region))

    if not event['enabled']:
        print('Deletion has initiated...')
        print('Please check the apcKekSetup log to check if the solution has been successfully disabled.')
        print('You can do that by checking the CloudWatch Logs Log group /aws/apc-crr/apcKekSetup in the Management Console,')
        print('or by typing on a shell terminal: aws logs tail "/aws/lambda/apcKekSetup" --follow')
        print('')
        print('Please check the apcStackMonitor log to follow the stack deletion status.')
        print('You can do that by checking the CloudWatch Logs Log group /aws/apc-crr/apcStackMonitor in the Management Console,')
        print('or by typing on a shell terminal: aws logs tail "/aws/lambda/apcStackMonitor" --follow')

        keys = query_items(DYNAMODB_TABLE_APC_CRR, 'account_id',
                           AWS_ACCOUNT, ('sync_status', 'TR34_KEY_EXCHANGE_COMPLETED'))
        for key in keys:
            key_id = {
                'account_id': key['account_id'],
                'lambda_request_id': key['lambda_request_id'],
            }
            status = 'TR34_KEYS_DELETION_PENDING'
            update_item(DYNAMODB_TABLE_APC_CRR, status, key_id,
                        False, 'sync_status')
