# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
# CRR is currently only working with TDES
##
import os
import boto3
from datetime import datetime
import botocore
from boto3.dynamodb.conditions import Key, Attr

dynamoDB = boto3.resource('dynamodb')
logs_client = boto3.client('logs')
vpc_client_origin = boto3.client('ec2')
FILTER_NAME = 'APC-Import-Create-Delete-Keys'
LOG_GROUP_CT_LOGS = os.environ['LOG_GROUP_CT_LOGS']
DYNAMODB_TABLE_APC_CRR = os.environ['DYNAMODB_TABLE_APC_CRR']

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


def getKeyByAliasName(alias_name, apc):
    try:
        key_alias = apc.get_alias(AliasName=alias_name)
        key = apc.get_key(KeyIdentifier=key_alias['Alias']['KeyArn'])
        return key
    except botocore.exceptions.ClientError as error:
        return


def create_alias(alias_name, key_arn, apc):
    try:
        return apc.create_alias(AliasName=alias_name, KeyArn=key_arn)
    except botocore.exceptions.ClientError as error:
        raise error


def getOrCreateKeyByAliasName(alias_name, apc, key_attributes, key_status, exportable, region):
    fetched_alias = getKeyByAliasName(alias_name, apc)
    if fetched_alias is None:
        try:
            new_key = apc.create_key(
                Enabled=key_status, Exportable=exportable, KeyAttributes=key_attributes)
        except botocore.exceptions.ClientError as error:
            raise error
        new_alias = create_alias(alias_name, new_key['Key']['KeyArn'], apc)
        return new_alias['Alias']['KeyArn']
    else:
        return fetched_alias['Key']['KeyArn']


def getParametersForImport(apc):
    try:
        result = apc.get_parameters_for_import(
            KeyMaterialType='TR34_KEY_BLOCK', WrappingKeyAlgorithm='RSA_2048')
        return result
    except botocore.exceptions.ClientError as error:
        raise error


def getParametersForExport(apc):
    try:
        result = apc.get_parameters_for_export(
            KeyMaterialType='TR34_KEY_BLOCK', SigningKeyAlgorithm='RSA_2048')
        return result
    except botocore.exceptions.ClientError as error:
        raise error


def importKey(apc, key_material):
    try:
        result = apc.import_key(KeyMaterial=key_material)
        return result
    except botocore.exceptions.ClientError as error:
        raise error


def exportKey(alias_name, apc, key_material):
    try:
        result = apc.export_key(
            ExportKeyIdentifier=alias_name, KeyMaterial=key_material)
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


def deleteAlias(apc, alias):
    try:
        apc.delete_alias(AliasName=alias)
    except botocore.exceptions.ClientError as error:
        print(error)
        return


# def get_loggroup(loggroup_name):
#     paginator = logs_client.get_paginator('describe_log_groups')
#     for page in paginator.paginate():
#         for group in page['logGroups']:
#             if '-'.join(group['logGroupName'].split('-')[:-1]) == loggroup_name:
#                 return group['logGroupName']
#     return 'not_found'


def describe_subscription_filters(loggroup_name, filter_name_prefix):
    filters = logs_client.describe_subscription_filters(
        logGroupName=loggroup_name,
        filterNamePrefix=filter_name_prefix
    )
    return filters['subscriptionFilters']


def put_subscription_filter(*filter_data):
    filterName, logGroupName, filterPattern, destinationArn, distribution = filter_data
    try:
        logs_client.put_subscription_filter(
            filterName=filterName,
            logGroupName=logGroupName,
            filterPattern=filterPattern,
            destinationArn=destinationArn,
            distribution=distribution
        )
    except botocore.exceptions.ClientError as error:
        raise error


def delete_subscription_filter(*filter_data):
    filterName, logGroupName = filter_data
    try:
        logs_client.delete_subscription_filter(
            filterName=filterName,
            logGroupName=logGroupName
        )
    except botocore.exceptions.ClientError as error:
        raise error


def lambda_handler(event, context):
    for record in event['Records']:
        if record['eventName'] == 'MODIFY':
            new_record = record['dynamodb']['NewImage']
            old_record = record['dynamodb']['OldImage']
            if new_record['sync_status']['S'] == 'RESOURCES_CREATION_COMPLETED':
                crrObj = {
                    'account_id': new_record['account_id']['S'],
                    'lambda_request_id': new_record['lambda_request_id']['S'],
                    'origin_region': new_record['origin_region']['S']
                }

                filters = describe_subscription_filters(
                    LOG_GROUP_CT_LOGS, FILTER_NAME)
                for filter in filters:
                    filter_name = filter['filterName']
                    if filter_name == FILTER_NAME:
                        print(
                            'Cross-Region Replication already enabled. Exiting...')
                        return
                destination_arn = ':'.join(context.invoked_function_arn.split(':')[
                    :-1]) + ':apcReplicateWk'
                filterPattern = '{ ($.eventSource = \"payment-cryptography.amazonaws.com\") && ($.eventName = \"ImportKey\" || $.eventName = \"CreateKey\" || $.eventName = \"DeleteKey\") }'
                put_subscription_filter(FILTER_NAME, LOG_GROUP_CT_LOGS,
                                        filterPattern, destination_arn, 'ByLogStream')
                crrObj['dest_region'] = new_record['dest_region']['S']
                crrObj['kek_alias'] = new_record['kek_alias']['S']
                crrObj['key_algo'] = new_record['key_algo']['S']
                crrObj['krd_alias'] = new_record['krd_alias']['S']
                crrObj['kdh_alias'] = new_record['kdh_alias']['S']
                crrObj['sync_status'] = 'TR34_KEY_EXCHANGE_PENDING'
                key_id = {
                    'account_id': new_record['account_id']['S'],
                    'lambda_request_id': new_record['lambda_request_id']['S'],
                }
                status = 'TR34_KEY_EXCHANGE_PENDING'
                try:
                    update_item(DYNAMODB_TABLE_APC_CRR, status,
                                key_id, False, 'sync_status')
                except Exception as e:
                    print("Exception: " + str(e))
                    raise e

                vpce_control_origin = '.'.join(
                    ['https://controlplane.payment-cryptography', crrObj['origin_region'], 'amazonaws.com'])
                apc_control_origin_client = boto3.client(
                    'payment-cryptography', region_name=crrObj['origin_region'], endpoint_url=vpce_control_origin)
                vpce_control_dest = '.'.join(
                    ['https://controlplane.payment-cryptography', crrObj['dest_region'], 'amazonaws.com'])
                apc_control_dest_client = boto3.client(
                    'payment-cryptography', region_name=crrObj['dest_region'], endpoint_url=vpce_control_dest)
                print(
                    '\n##### Step 1. Generating Key Encryption Key (KEK) - Key that will be used to encrypt the Working Keys')
                key_status = True
                exportable = True
                KeyModesOfUse = {'Encrypt': True,
                                 'Decrypt': True, 'Wrap': True, 'Unwrap': True}
                keyAttributes = {'KeyAlgorithm': crrObj['key_algo'], 'KeyUsage': 'TR31_K0_KEY_ENCRYPTION_KEY',
                                 'KeyClass': 'SYMMETRIC_KEY', 'KeyModesOfUse': KeyModesOfUse}
                getOrCreateKeyByAliasName(crrObj['kek_alias'], apc_control_origin_client,
                                          keyAttributes, key_status, exportable, crrObj['origin_region'])
                print('\n##### Step 2. Getting APC Import Parameters from {0}'.format(
                    crrObj['dest_region']))
                import_parameters = getParametersForImport(
                    apc_control_dest_client)
                import_token = import_parameters['ImportToken']
                wrap_key_cert = import_parameters['WrappingKeyCertificate']
                wrap_root_certs = import_parameters['WrappingKeyCertificateChain']
                print('\n##### Step 3. Importing the Root Wrapping Certificates in {0}'.format(
                    crrObj['origin_region']))
                KeyModesOfUse = {'Verify': True}
                keyAttributes = {'KeyAlgorithm': 'RSA_4096', 'KeyUsage': 'TR31_S0_ASYMMETRIC_KEY_FOR_DIGITAL_SIGNATURE',
                                 'KeyClass': 'PUBLIC_KEY', 'KeyModesOfUse': KeyModesOfUse}
                rootCertificatePublicKey = {
                    'KeyAttributes': keyAttributes, 'PublicKeyCertificate': wrap_root_certs}
                keyMaterial = {
                    'RootCertificatePublicKey': rootCertificatePublicKey}
                importedWrappingKey = importKey(
                    apc_control_origin_client, keyMaterial)
                importedWrappingKeyAlias = create_alias(
                    crrObj['krd_alias'], importedWrappingKey['Key']['KeyArn'], apc_control_origin_client)
                print('\n##### Step 4. Getting APC Export Parameters from {0}'.format(
                    crrObj['origin_region']))
                export_parameters = getParametersForExport(
                    apc_control_origin_client)
                export_token = export_parameters['ExportToken']
                sign_key_cert = export_parameters['SigningKeyCertificate']
                sign_root_certs = export_parameters['SigningKeyCertificateChain']
                print('\n##### Step 5. Importing the Root Signing Certificates in {0}'.format(
                    crrObj['dest_region']))
                KeyModesOfUse = {'Verify': True}
                keyAttributes = {'KeyAlgorithm': 'RSA_4096', 'KeyUsage': 'TR31_S0_ASYMMETRIC_KEY_FOR_DIGITAL_SIGNATURE',
                                 'KeyClass': 'PUBLIC_KEY', 'KeyModesOfUse': KeyModesOfUse}
                rootCertificatePublicKey = {
                    'KeyAttributes': keyAttributes, 'PublicKeyCertificate': sign_root_certs}
                keyMaterial = {
                    'RootCertificatePublicKey': rootCertificatePublicKey}
                importedSigningKey = importKey(
                    apc_control_dest_client, keyMaterial)
                importedSigningKeyAlias = create_alias(
                    crrObj['kdh_alias'], importedSigningKey['Key']['KeyArn'], apc_control_dest_client)
                print('\n##### Step 6. Exporting the KEK from {0}'.format(
                    crrObj['origin_region']))
                crrObj['krd_alias'] = getKeyByAliasName(
                    crrObj['krd_alias'], apc_control_origin_client)['Key']['KeyArn']
                kek_arn = getKeyByAliasName(crrObj['kek_alias'], apc_control_origin_client)[
                    'Key']['KeyArn']
                tr34KeyBlock = {'CertificateAuthorityPublicKeyIdentifier': crrObj['krd_alias'],
                                'ExportToken': export_token, 'KeyBlockFormat': 'X9_TR34_2012', 'WrappingKeyCertificate': wrap_key_cert}
                keyMaterial = {'Tr34KeyBlock': tr34KeyBlock}
                wrappedKeyBlock = exportKey(
                    crrObj['kek_alias'], apc_control_origin_client, keyMaterial)
                blockFormat = wrappedKeyBlock['WrappedKey']['WrappedKeyMaterialFormat']
                wrappedKeyMaterial = wrappedKeyBlock['WrappedKey']['KeyMaterial']
                print('\n##### Step 7. Importing the Wrapped KEK to {0}'.format(
                    crrObj['dest_region']))
                tr34KeyBlock = {'CertificateAuthorityPublicKeyIdentifier': crrObj['kdh_alias'], 'ImportToken': import_token,
                                'KeyBlockFormat': 'X9_TR34_2012', 'SigningKeyCertificate': sign_key_cert, 'WrappedKeyBlock': wrappedKeyMaterial}
                keyMaterial = {'Tr34KeyBlock': tr34KeyBlock}
                importedKek = importKey(
                    apc_control_dest_client, keyMaterial)
                importedKekAlias = create_alias(
                    crrObj['kek_alias'], importedKek['Key']['KeyArn'], apc_control_dest_client)
                status = 'TR34_KEY_EXCHANGE_COMPLETED'
                key = {
                    'account_id': crrObj['account_id'],
                    'lambda_request_id': crrObj['lambda_request_id'],
                }
                timestamp = datetime.now().isoformat(timespec='seconds')
                try:
                    update_item(DYNAMODB_TABLE_APC_CRR, status,
                                key, False, 'sync_status')
                    update_item(DYNAMODB_TABLE_APC_CRR, timestamp, key,
                                True, 'replication_timestamp')
                except Exception as e:
                    print("Exception: " + str(e))
                    raise e
                print('\n##### Initial Key Exchange Successfully Completed.')
                print('Keys Generated, Imported and Deleted in {0} are now being automatically replicated to {1}'.format(
                    crrObj['origin_region'], crrObj['dest_region']))
                print(
                    'Keys already present in APC won\'t be replicated. If you want to, it must be done manually.')
            else:
                if new_record['sync_status']['S'] == 'TR34_KEYS_DELETION_PENDING':
                    print("Disabling CRR and Deleting KEKs")
                    # logGroupName = get_loggroup(
                    #     'aws-cloudtrail-logs-' + crrObj['account_id'])
                    delete_subscription_filter(FILTER_NAME, LOG_GROUP_CT_LOGS)
                    keys = query_items(DYNAMODB_TABLE_APC_CRR, 'account_id',
                                       new_record['account_id']['S'], ('sync_status', 'TR34_KEYS_DELETION_PENDING'))
                    for key in keys:
                        vpce_control_origin = '.'.join(
                            ['https://controlplane.payment-cryptography', key['origin_region'], 'amazonaws.com'])
                        apc_control_origin_client = boto3.client(
                            'payment-cryptography', region_name=key['origin_region'], endpoint_url=vpce_control_origin)
                        vpce_control_dest = '.'.join(
                            ['https://controlplane.payment-cryptography', key['dest_region'], 'amazonaws.com'])
                        apc_control_dest_client = boto3.client(
                            'payment-cryptography', region_name=key['dest_region'], endpoint_url=vpce_control_dest)
                        krd_arn = getKeyByAliasName(key['krd_alias'], apc_control_origin_client)[
                            'Key']['KeyArn']
                        origin_kek_arn = getKeyByAliasName(key['kek_alias'], apc_control_origin_client)[
                            'Key']['KeyArn']
                        deleteKey(apc_control_origin_client, krd_arn)
                        deleteKey(apc_control_origin_client, origin_kek_arn)
                        deleteAlias(apc_control_origin_client,
                                    key['krd_alias'])
                        deleteAlias(apc_control_origin_client,
                                    key['kek_alias'])
                        kdh_arn = getKeyByAliasName(key['kdh_alias'], apc_control_dest_client)[
                            'Key']['KeyArn']
                        dest_kek_arn = getKeyByAliasName(key['kek_alias'], apc_control_dest_client)[
                            'Key']['KeyArn']
                        deleteKey(apc_control_dest_client, kdh_arn)
                        deleteKey(apc_control_dest_client, dest_kek_arn)
                        deleteAlias(apc_control_dest_client, key['kdh_alias'])
                        deleteAlias(apc_control_dest_client, key['kek_alias'])
                        print('Keys and aliases deleted from APC.')

                        status = 'TR34_KEYS_DELETION_COMPLETED'
                        key_id = {
                            'account_id': key['account_id'],
                            'lambda_request_id': key['lambda_request_id'],
                        }
                        timestamp = datetime.now().isoformat(timespec='seconds')
                        try:
                            update_item(DYNAMODB_TABLE_APC_CRR, status,
                                        key_id, False, 'sync_status')
                            update_item(DYNAMODB_TABLE_APC_CRR, timestamp, key_id,
                                        True, 'deletion_timestamp')
                            print('DB status updated.')
                        except Exception as e:
                            print("Exception: " + str(e))
                            raise e
