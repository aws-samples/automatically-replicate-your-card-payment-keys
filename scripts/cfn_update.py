# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
import yaml
import json
import os
import secrets
import boto3
import botocore
import hashlib
FILENAME_IN = './templates/ApcCrrOrchestrator-base.yaml'
FILENAME_OUT = './templates/deployment/ApcCrrOrchestrator.yaml'
RAND = secrets.randbelow(100000001)
sts_client = boto3.client('sts')

def read_one_block_of_yaml_data(filename):
    with open(filename, 'r') as f:
        output = yaml.safe_load(f)
    return output


def write_yaml_data(filename, data):
    with open(filename, 'w') as f:
        yaml.dump(data, f, sort_keys=False)
    return True

def read_json_file(filename):
    with open(filename, 'r') as f:
        output = json.load(f)
    return output

def get_current_account(client):
    try:
        response = client.get_caller_identity()
        return response['Account']
    except botocore.exceptions.ClientError as error:
        if error.response['Error']['Code'] == 'InvalidClientTokenId':
            print('Invalid Client Token ID. Exiting...')
        if error.response['Error']['Code'] == 'ExpiredToken':
            print('Invalid Client Token ID. Exiting...')
        exit()


if __name__ == "__main__":
    data = read_one_block_of_yaml_data(FILENAME_IN)
    logical_ids = []
    for key, value in data.items():
        if key == 'Resources':
            for key1, value1 in value.items():
                logical_ids.append(key1)

    new_logical_ids = []
    for logical_id in logical_ids:
        new_logical_id = logical_id + str(RAND)
        data['Resources'][new_logical_id] = data['Resources'][logical_id]
        del data['Resources'][logical_id]
        new_logical_ids.append(new_logical_id)

    for key, value in data.items():
        if key == 'Resources':
            for i in range(0, len(new_logical_ids) - 1):
                for key1, value1 in value.items():
                    value1 = json.dumps(value1).replace(
                        logical_ids[i], new_logical_ids[i])
                    value1 = json.loads(value1)
                    data['Resources'][key1] = value1

        if key == 'Outputs':
            for i in range(0, len(new_logical_ids)):
                for key1, value1 in value.items():
                    value1 = json.dumps(value1).replace(
                        logical_ids[i], new_logical_ids[i])
                    value1 = json.loads(value1)
                    data['Outputs'][key1] = value1

        if key == 'Mappings':
            dest_region = read_json_file(
                'application/enable-crr.json')['dest_region']
            if dest_region == 'us-east-1':
                current_account = get_current_account(sts_client)
                account_hash = hashlib.sha256(
                    current_account.encode('utf-8')).hexdigest()
                dest_azs = read_json_file('cdk.json')[
                    'context']['ENVIRONMENTS']['dev'][account_hash]
                for key1, value1 in value.items():
                    value1[dest_region]['az1'] = dest_azs[0]
                    value1[dest_region]['az2'] = dest_azs[1]
                    data['Mappings'][key1] = value1

    save_to_file = write_yaml_data(FILENAME_OUT, data)
    if save_to_file:
        print('Preparing to deploy...')
    else:
        print('File save failed')
