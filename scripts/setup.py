# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
import json
import boto3
import botocore
import hashlib
import sys
import os.path
import shutil

sts = boto3.client('sts')
ec2 = boto3.client('ec2', region_name='us-east-1')


def whois():
    try:
        return sts.get_caller_identity()
    except botocore.exceptions.ClientError as error:
        if error.response['Error']['Code'] == 'InvalidClientTokenId':
            print('Invalid Client Token ID. Exiting...')
        if error.response['Error']['Code'] == 'ExpiredToken':
            print('Invalid Client Token ID. Exiting...')
        return 1

def read_file(file_path):
    file = None
    try:
        file = open(file_path, 'r')
        content = json.loads(file.read())
        return content
    except FileNotFoundError:
        print(f"Error: File {file_path} not found.")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if file:
            file.close()

if __name__ == "__main__":
    identity = whois()
    if identity == 1:
        exit(1)
    account = identity['Account']
    account_hash = hashlib.sha256(account.encode('utf-8')).hexdigest()
    
    data = read_file('cdk.json')

    if account_hash in data['context']['ENVIRONMENTS']['dev']:
        sys.exit()

    filters = [{'Name': 'zone-id', 'Values': ['use1-az1', 'use1-az2']}]
    azs = ec2.describe_availability_zones(
        Filters=filters)['AvailabilityZones']
    az_list = []
    for az in azs:
        az_list.append(az['ZoneName'])

    data['context']['ENVIRONMENTS']['dev'][account_hash] = az_list

    check_file = os.path.isfile('cdk.json.bkp')
    if not check_file:
        shutil.copyfile('cdk.json', 'cdk.json.bkp')

    with open('cdk.json', 'w') as outfile:
        json.dump(data, outfile, indent=2)
