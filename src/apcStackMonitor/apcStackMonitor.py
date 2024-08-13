# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
import boto3
import botocore
import os
import time
from boto3.dynamodb.conditions import Key, Attr

DYNAMODB_TABLE_APC_CRR_STACK = os.environ['DYNAMODB_TABLE_APC_CRR_STACK']
DYNAMODB_TABLE_APC_CRR = os.environ['DYNAMODB_TABLE_APC_CRR']
ORIGIN_VPC_ID = os.environ['ORIGIN_VPC_ID']
ORIGIN_SUBNETS_PREFIX_NAME = os.environ['ORIGIN_SUBNETS_PREFIX_NAME']
APC_VPC_ENDPOINT_SG_ID = os.environ['APC_VPC_ENDPOINT_SG_ID']
AWS_ACCOUNT = os.environ['AWS_ACCOUNT']

dynamoDB = boto3.resource('dynamodb')
vpc_client_origin = boto3.client('ec2')


def delete_item(table, key):
    table = dynamoDB.Table(table)
    try:
        table.delete_item(Key=key)
    except Exception as e:
        print("Exception: " + str(e))


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


def update_origin_vpc_sg(dest_vpc_cidr, direction, operation):
    # Update the Origin VPC SG (Outbound rule)
    # Get VPC SG Group ID
    filters = [{'Name': 'group-id', 'Values': [APC_VPC_ENDPOINT_SG_ID]}]
    origin_vpc_sg = vpc_client_origin.describe_security_groups(
        Filters=filters
    )['SecurityGroups'][0]
    GroupId = origin_vpc_sg['GroupId']
    IpPermissions = [
        {
            'FromPort': 443,
            'ToPort': 443,
            'IpProtocol': 'tcp',
            'IpRanges': [
                {
                    'CidrIp': dest_vpc_cidr,
                    'Description': 'Allow access from Origin VPC CIDR'
                }
            ]
        }
    ]
    if direction == 'egress' and operation == 'create':
        # Create Egress Rule
        origin_sg = vpc_client_origin.authorize_security_group_egress(
            GroupId=GroupId,
            IpPermissions=IpPermissions
        )
    if direction == 'egress' and operation == 'delete':
        # Delete Egress Rule
        origin_sg = vpc_client_origin.revoke_security_group_egress(
            GroupId=GroupId,
            IpPermissions=IpPermissions
        )


def create_route(client, route_table_id, destination_cidr_block, resource, resource_id):
    if resource == 'peering-connection':
        client.create_route(
            RouteTableId=route_table_id,
            DestinationCidrBlock=destination_cidr_block,
            VpcPeeringConnectionId=resource_id
        )


def delete_route(client, route_table_id, destination_cidr_block):
    client.delete_route(
        RouteTableId=route_table_id,
        DestinationCidrBlock=destination_cidr_block
    )


def get_origin_peering_connection(client, vpc_id):
    filters = [{'Name': 'accepter-vpc-info.vpc-id', 'Values': [vpc_id]}]
    vpc_peering_connections = client.describe_vpc_peering_connections(
        Filters=filters
    )
    for vpc_peering_connection in vpc_peering_connections['VpcPeeringConnections']:
        if vpc_peering_connection['Status']['Code'] == 'active':
            return vpc_peering_connection
    return None


def update_origin_rts(dest_vpc_cidr, vpc_peering_connection_id):
    # Update Requester Route Tables
    filters = [{'Name': 'tag:Name', 'Values': [
        '*' + ORIGIN_SUBNETS_PREFIX_NAME + '*']}]
    origin_route_tables = vpc_client_origin.describe_route_tables(
        Filters=filters
    )
    for origin_route_table in origin_route_tables['RouteTables']:
        create_route(
            vpc_client_origin, origin_route_table['RouteTableId'], dest_vpc_cidr, 'peering-connection', vpc_peering_connection_id)


def get_stack_status(cfn_client, stack_id):
    try:
        stack_status = cfn_client.describe_stacks(
            StackName=stack_id)['Stacks'][0]['StackStatus']
    except botocore.exceptions.ClientError as error:
        print('Error getting stack status: {0}'.format(stack_id))
        raise error
    return stack_status


def lambda_handler(event, context):
    for record in event['Records']:
        if record['eventName'] == 'INSERT':
            new_record = record['dynamodb']['NewImage']
            stack_id = new_record['stack_id']['S']
            dest_vpc_cidr = new_record['dest_vpc_cidr']['S']
            dest_region = new_record['dest_region']['S']
            account_id = new_record['account_id']['S']
            lambda_request_id = new_record['lambda_request_id']['S']
            cfn_client = boto3.client(
                'cloudformation', region_name=dest_region)
            stack_status = get_stack_status(cfn_client, stack_id)
            while stack_status == 'CREATE_IN_PROGRESS':
                print('Stack creation in progress. Status: {0}'.format(
                    stack_status))
                stack_status = get_stack_status(cfn_client, stack_id)
                time.sleep(5)
            print('Stack creation completed. Status: {0}'.format(stack_status))
            if stack_status == 'CREATE_COMPLETE':
                try:
                    update_origin_vpc_sg(dest_vpc_cidr, 'egress', 'create')
                    vpc_peering_connection = get_origin_peering_connection(
                        vpc_client_origin, ORIGIN_VPC_ID)
                    update_origin_rts(
                        dest_vpc_cidr, vpc_peering_connection['VpcPeeringConnectionId'])

                except botocore.exceptions.ClientError as error:
                    print('Error updating Origin')
                    raise error

                print('Finishing setup... Hold on.')
                time.sleep(5)
                update_item(DYNAMODB_TABLE_APC_CRR, 'RESOURCES_CREATION_COMPLETED', {
                            'account_id': account_id, 'lambda_request_id': lambda_request_id}, False, 'sync_status')

                print('Resources successfully deployed in: {0}'.format(
                    dest_region))
            else:
                update_item(DYNAMODB_TABLE_APC_CRR, 'RESOURCES_CREATION_FAILED', {
                            'account_id': account_id, 'lambda_request_id': lambda_request_id}, False, 'sync_status')
                print('Stack creation failed with status {0}'.format(
                    stack_status))

        if record['eventName'] == 'MODIFY':
            new_record = record['dynamodb']['NewImage']
            if new_record['sync_status']['S'] == 'TR34_KEYS_DELETION_COMPLETED':
                cfn_client = boto3.client(
                    'cloudformation', region_name=new_record['dest_region']['S'])
                stacks = cfn_client.describe_stacks()
                for stack in stacks['Stacks']:
                    if stack['StackStatus'] == 'CREATE_COMPLETE' and str(stack['StackName']).startswith("apc-setup-orchestrator-"):
                        print(
                            'De-provisioning Resources in the Destination Region. StackName: {0}'.format(stack['StackName']))
                        try:
                            cfn_client.delete_stack(
                                StackName=stack['StackName'])
                        except botocore.exceptions.ClientError as error:
                            print('Error deleting stack {0}'.format(
                                stack['StackName']))
                            raise error
                        stack_status = get_stack_status(
                            cfn_client, stack['StackId'])
                        while stack_status == 'DELETE_IN_PROGRESS':
                            print('Stack deletion in progress. Status: {0}'.format(
                                stack_status))
                            stack_status = get_stack_status(
                                cfn_client, stack['StackId'])
                            time.sleep(5)
                        stack_status = get_stack_status(
                            cfn_client, stack['StackId'])
                        if stack_status == 'DELETE_COMPLETE':
                            print('Stack deletion completed. Status: {0}'.format(
                                stack_status))
                            update_item(DYNAMODB_TABLE_APC_CRR, 'RESOURCES_DELETION_COMPLETED', {
                                'account_id': new_record['account_id']['S'], 'lambda_request_id': new_record['lambda_request_id']['S']}, False, 'sync_status')
                            # Delete Routes from Origin Route Tables
                            filters = [{'Name': 'tag:Name', 'Values': [
                                '*' + ORIGIN_SUBNETS_PREFIX_NAME + '*']}]
                            origin_route_tables = vpc_client_origin.describe_route_tables(
                                Filters=filters
                            )
                            for origin_route_table in origin_route_tables['RouteTables']:
                                for route in origin_route_table['Routes']:
                                    if route['State'] == 'blackhole':
                                        delete_route(
                                            vpc_client_origin, origin_route_table['RouteTableId'], route['DestinationCidrBlock'])
                            # Delete Origin VPC SG Egress Rule
                            try:
                                stack_info = query_items(DYNAMODB_TABLE_APC_CRR_STACK, 'stack_id',
                                                         stack['StackId'], ('account_id', str(AWS_ACCOUNT)))
                                dest_vpc_cidr = stack_info[0]['dest_vpc_cidr']
                                update_origin_vpc_sg(
                                    dest_vpc_cidr, 'egress', 'delete')
                            except botocore.exceptions.ClientError as error:
                                print('Error deleting Origin SG')
                                raise error
                            print('Resources successfully deleted. Status: {0}'.format(
                                stack_status))

                            try:
                                delete_item(DYNAMODB_TABLE_APC_CRR_STACK, {
                                    'stack_id': stack['StackId'],
                                })
                            except botocore.exceptions.ClientError as error:
                                print('Error deleting stack record')
                                raise error
                        else:
                            update_item(DYNAMODB_TABLE_APC_CRR, 'RESOURCES_DELETION_FAILED', {
                                        'account_id': new_record['account_id']['S'], 'lambda_request_id': new_record['lambda_request_id']['S']}, False, 'sync_status')
                            print('Stack deletion failed with status {0}'.format(
                                stack_status))
