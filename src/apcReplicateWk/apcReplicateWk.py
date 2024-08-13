# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
import json
import os
import gzip
import base64
import boto3
import botocore
from datetime import datetime
from boto3.dynamodb.conditions import Key, Attr

dynamoDB = boto3.resource('dynamodb')
AWS_ACCOUNT = os.environ['AWS_ACCOUNT']
REGION = os.environ['REGION']
DYNAMODB_TABLE_APC_CRR = os.environ['DYNAMODB_TABLE_APC_CRR']
DYNAMODB_TABLE_APC_CRR_REPLICATE = os.environ['DYNAMODB_TABLE_APC_CRR_REPLICATE']


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


def get_item(table, item, key):
    table = dynamoDB.Table(table)
    try:
        result = table.get_item(Key={
            key: item
        })
        item_in_dict = "Item" in result
        if not item_in_dict:
            return "not_found"

        return result['Item']

    except Exception as e:
        print("Exception: " + str(e))


def delete_item(table, item, key):
    table = dynamoDB.Table(table)
    try:
        table.delete_item(Key={
            key: item
        })
    except Exception as e:
        print("Exception: " + str(e))


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


def getKeyByAliasName(alias_name, apc):
    try:
        key = apc.get_key(KeyIdentifier=alias_name)
        return key
    except botocore.exceptions.ClientError as error:
        return


def create_alias(alias_name, key_arn, apc):
    try:
        return apc.create_alias(AliasName=alias_name, KeyArn=key_arn)
    except botocore.exceptions.ClientError as error:
        raise error


def exportKey(alias_name, apc, key_material):
    try:
        result = apc.export_key(
            ExportKeyIdentifier=alias_name, KeyMaterial=key_material)
        return result
    except botocore.exceptions.ClientError as error:
        raise error


def importKey(apc, key_material):
    try:
        result = apc.import_key(KeyMaterial=key_material)
        return result
    except botocore.exceptions.ClientError as error:
        raise error


def deleteKey(apc, key_arn):
    try:
        result = apc.delete_key(
            DeleteKeyInDays=3,
            KeyIdentifier=key_arn
        )
        return result
    except botocore.exceptions.ClientError as error:
        print(error)
        return


def getPubKeyCert(alias_name, apc):
    try:
        result = apc.get_public_key_certificate(KeyIdentifier=alias_name)
        return result
    except botocore.exceptions.ClientError as error:
        raise error


def lambda_handler(event, context):
    encoded_zipped_data = event['awslogs']['data']
    zipped_data = base64.b64decode(encoded_zipped_data)
    data = gzip.decompress(zipped_data)
    payload = json.loads(data)

    log_events = payload['logEvents']
    for log_event in log_events:
        message = json.loads(log_event['message'])

        if message['eventSource'] == 'payment-cryptography.amazonaws.com':
            if 'apcKekSetup' not in message['userIdentity']['principalId']:
                if 'apcReplicateWk' not in message['userIdentity']['principalId']:
                    if message['awsRegion'] == REGION:
                        if (message['eventName'] == 'CreateKey' or message['eventName'] == 'ImportKey'):
                            if ('exportable' in message['responseElements']['key'] and message['responseElements']['key']['exportable']):
                                if message['responseElements']['key']['keyState'] == 'CREATE_COMPLETE':
                                    print('This is a WK! Sync in progress...')

                                    keys = query_items(
                                        DYNAMODB_TABLE_APC_CRR, 'account_id', AWS_ACCOUNT, ('sync_status', 'TR34_KEY_EXCHANGE_COMPLETED'))
                                    if not keys:
                                        return print('KEK not found! Cross-Region Replication not enabled!')

                                    first_key = keys[0]
                                    kek_alias_name = first_key['kek_alias']
                                    key_class = message['responseElements']['key']['keyAttributes']['keyClass']
                                    working_key_arn = message['responseElements']['key']['keyArn']
                                    origin_region = first_key['origin_region']
                                    dest_region = first_key['dest_region']

                                    vpce_control_origin = '.'.join(
                                        ['https://controlplane.payment-cryptography', origin_region, 'amazonaws.com'])
                                    vpce_control_dest = '.'.join(
                                        ['https://controlplane.payment-cryptography', dest_region, 'amazonaws.com'])
                                    apc_origin_client = boto3.client(
                                        'payment-cryptography', region_name=origin_region, endpoint_url=vpce_control_origin)
                                    apc_dest_client = boto3.client(
                                        'payment-cryptography', region_name=dest_region, endpoint_url=vpce_control_dest)

                                    if key_class == 'SYMMETRIC_KEY':
                                        print('\n##### Step 1. Exporting {0} {1} from {2} using {3} Key Encryption Key'.format(
                                            key_class, working_key_arn, origin_region, kek_alias_name))
                                        kek_arn_origin = getKeyByAliasName(kek_alias_name, apc_origin_client)[
                                            'Key']['KeyArn']
                                        tr31KeyBlock = {
                                            'WrappingKeyIdentifier': kek_arn_origin}
                                        keyMaterial = {
                                            'Tr31KeyBlock': tr31KeyBlock}
                                        wrappedKeyBlock = exportKey(
                                            working_key_arn, apc_origin_client, keyMaterial)
                                        blockFormat = wrappedKeyBlock['WrappedKey']['WrappedKeyMaterialFormat']
                                        wrappedKeyMaterial = wrappedKeyBlock['WrappedKey']['KeyMaterial']

                                        print('\n##### Step 2. Importing the Wrapped Key to {0}'.format(
                                            dest_region))
                                        tr31KeyBlock = {'WrappingKeyIdentifier': kek_alias_name,
                                                        'WrappedKeyBlock': wrappedKeyMaterial}
                                        keyMaterial = {
                                            'Tr31KeyBlock': tr31KeyBlock}
                                        importedKey = importKey(
                                            apc_dest_client, keyMaterial)
                                        print('Imported {0} key: {1} as {2} in {3}'.format(
                                            key_class, importedKey['Key']['KeyArn'], importedKey['Key']['KeyAttributes']['KeyUsage'], dest_region))

                                        key_map = {
                                            'origin_key_arn': working_key_arn,
                                            'dest_key_arn': importedKey['Key']['KeyArn'],
                                            'replication_timestamp': datetime.now().isoformat(timespec='seconds')
                                        }

                                        update_item(
                                            DYNAMODB_TABLE_APC_CRR_REPLICATE, key_map)
                                else:
                                    print(
                                        'Key is not in a CREATE_COMPLETE state.')

                            else:
                                print(
                                    'Key is not exportable! Or this is an Asymmetric Key!')
                        else:
                            print('This is not CreateKey or ImportKey! So we will be marking a key for Deletion!')
                            if message['eventName'] == 'DeleteKey':
                                key_map = get_item(
                                    DYNAMODB_TABLE_APC_CRR_REPLICATE, message['requestParameters']['keyIdentifier'], 'origin_key_arn')
                                if key_map == "not_found":
                                    return print('Key already deleted!')
                                dest_key_arn = key_map['dest_key_arn']
                                dest_region = dest_key_arn.split(":")[3]
                                vpce_control_dest = '.'.join(
                                    ['https://controlplane.payment-cryptography', dest_region, 'amazonaws.com'])
                                apc_dest_client = boto3.client(
                                    'payment-cryptography', region_name=dest_region, endpoint_url=vpce_control_dest)
                                deleteKey(apc_dest_client, dest_key_arn)
                                print('{0} deleted from {1}.'.format(
                                    dest_key_arn, dest_region))
                                delete_item(
                                    DYNAMODB_TABLE_APC_CRR_REPLICATE, message['requestParameters']['keyIdentifier'], 'origin_key_arn')
                    else:
                        print('Command not executed in the origin region.')
                        if message['eventName'] == 'DeleteKey':
                            print(
                                'You have deleted a key from a region that is not the Origin of replication. Keys will be out of sync!')
                            print(
                                'To keep keys in sync between regions, please delete it from the Origin, where Cross-Region Replication was enabled.')
                else:
                    print('Command executed by apcReplicateWk lambda! All good!')
            else:
                print(
                    'Those are keys generated by the CRR solution and were already replicated.')
        else:
            print('This is not from APC!')
