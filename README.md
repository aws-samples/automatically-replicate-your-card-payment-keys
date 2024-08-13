# AWS Payment Cryptography Cross-Region Replication (APC CRR)

This is a CDK project to deploy the necessary infrastructure to the AWS account where the CRR solution will be enabled.  
This solution uses Private Endpoints, so resources will also be deployed in the AWS Region where you choose to replicate the keys.

Currently available regions: us-east-1, us-east-2, us-west-2, eu-central-1, eu-west-1, ap-northeast-1 and ap-southeast-1

This CDK was developed in Python, and assumes that there is a `python3` (or `python` for Windows) executable in your path.  
It is also assumed that there is a `cdk` executable in your path.  
Python install: https://www.python.org/downloads/  
AWS CLI install: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html  
CDK install: https://docs.aws.amazon.com/cdk/v2/guide/getting_started.html

Tested with versions:  
Python: 3.12.2 (MacOS version)  
AWS CLI: aws-cli/2.15.29 Python/3.11.8 Darwin/22.6.0 exe/x86_64 prompt/off  
AWS CDK: 2.132.1 (build 9df7dd3)

Below are the steps (for MacOS and Linux) to create a `venv` package and deploy the solution.

Step 1: create a virtualenv:

```
$ python3 -m venv .venv
```

Step 2: activate the virtualenv:

```
$ source .venv/bin/activate
```

Step 3: install the required dependencies:

```
$ pip install -r requirements.txt
```

Step 4: if this is the first time deploying with `cdk` in the selected AWS Region, execute below:

```
$ cdk bootstrap
```

Step 5: deploy the solution using `cdk`:

```
$ cdk deploy
```

If the solution is correctly deployed, the create CloudFormation Stack should be in COMPLETE_STATE  
Exepcted output:  
Do you wish to deploy these changes (y/n)? y  
apc-crr: deploying... [1/1]  
apc-crr: creating CloudFormation changeset...

✅ apc-crr

✨ Deployment time: 307.88s

Stack ARN:
arn:aws:cloudformation:<aws_region>:<aws_account>:stack/apc-crr/<stack_id>

✨ Total time: 316.06s

To enable APC CRR solution follow the steps below.

Step 1: On one terminal, tail the apcStackMonitor lambda log to check the deployment of the resources

```
$ aws logs tail "/aws/lambda/apcStackMonitor" --follow
```

Step 2: On a second terminal, tail the apcKekSetup lambda log to check the Setup of the KEK between KDH and KRD

```
$ aws logs tail "/aws/lambda/apcKekSetup" --follow
```

Step 3: On a third terminal, go to the CRR solution folder

```
$ cd application
```

Step 4: execute the enable script. Please check if "jq" is installed (which jq). If not, please install it.

```
$ ./enable-crr.sh
```

Expected output:  
➜ ./enable-crr.sh  
START RequestId: 8aad062a-ff0b-4963-8ca0-f8078346854f Version: $LATEST  
Setup has initiated. A CloudFormation template will be deployed in us-west-2.  
Please check the apcStackMonitor log to follow the deployment status.  
You can do that by checking the CloudWatch Logs Log group /aws/apc-crr/apcStackMonitor in the Management Console,  
or by typing on a shell terminal: aws logs tail "/aws/lambda/apcStackMonitor" --follow  
You can also check the CloudFormation Stack in the Management Console: Account 111122223333, Region us-west-2  
END RequestId: 8aad062a-ff0b-4963-8ca0-f8078346854f  
REPORT RequestId: 8aad062a-ff0b-4963-8ca0-f8078346854f Duration: 1484.53 ms Billed Duration: 1485 ms Memory Size: 128 MB Max Memory Used: 79 MB Init Duration: 400.95 ms

This will trigger a CloudFormation stack to be deployed in the AWS Region where the keys will be replicated to (Destination Region)  
Logs will be presented in the /aws/lambda/apcStackMonitor Log group  
Expected output:  
2024-03-05T15:18:17.870000+00:00 2024/03/05/apcStackMonitor[$LATEST]6e6762b029cb4f7d8963c3206226deac INIT_START Runtime Version: python:3.11.v29 Runtime Version ARN: arn:aws:lambda:us-east-1::runtime:2fb93380dac14772d30092f109b1784b517398458eef71a3f757425231fe6769  
2024-03-05T15:18:18.321000+00:00 2024/03/05/apcStackMonitor[$LATEST]6e6762b029cb4f7d8963c3206226deac START RequestId: 1bdd37b4-e95b-43bd-a49b-9da55e603845 Version: $LATEST  
2024-03-05T15:18:18.933000+00:00 2024/03/05/apcStackMonitor[$LATEST]6e6762b029cb4f7d8963c3206226deac Stack creation in progress. Status: CREATE_IN_PROGRESS  
2024-03-05T15:18:24.017000+00:00 2024/03/05/apcStackMonitor[$LATEST]6e6762b029cb4f7d8963c3206226deac Stack creation in progress. Status: CREATE_IN_PROGRESS  
2024-03-05T15:18:29.108000+00:00 2024/03/05/apcStackMonitor[$LATEST]6e6762b029cb4f7d8963c3206226deac Stack creation in progress. Status: CREATE_IN_PROGRESS  
...  
2024-03-05T15:21:32.302000+00:00 2024/03/05/apcStackMonitor[$LATEST]6e6762b029cb4f7d8963c3206226deac Stack creation in progress. Status: CREATE_IN_PROGRESS  
2024-03-05T15:21:37.390000+00:00 2024/03/05/apcStackMonitor[$LATEST]6e6762b029cb4f7d8963c3206226deac Stack creation completed. Status: CREATE_COMPLETE  
2024-03-05T15:21:38.258000+00:00 2024/03/05/apcStackMonitor[$LATEST]6e6762b029cb4f7d8963c3206226deac Stack successfully deployed. Status: CREATE_COMPLETE  
2024-03-05T15:21:38.354000+00:00 2024/03/05/apcStackMonitor[$LATEST]6e6762b029cb4f7d8963c3206226deac END RequestId: 1bdd37b4-e95b-43bd-a49b-9da55e603845  
2024-03-05T15:21:38.354000+00:00 2024/03/05/apcStackMonitor[$LATEST]6e6762b029cb4f7d8963c3206226deac REPORT RequestId: 1bdd37b4-e95b-43bd-a49b-9da55e603845Duration: 200032.11 ms Billed Duration: 200033 ms Memory Size: 128 MB Max Memory Used: 93 MB Init Duration: 450.87 ms

If the stack is successfully deployed (CREATE_COMPLETE state), then KEK replication will be triggered.  
Logs will be presented in the /aws/lambda/apcKekSetup Log group  
Expected output:  
2024-03-12T14:58:18.954000+00:00 2024/03/12/apcKekSetup[$LATEST]ea4c6a7c85ac42da8a043aa8626d2897 INIT_START Runtime Version: python:3.11.v29 Runtime Version ARN: arn:aws:lambda:us-west-2::runtime:2fb93380dac14772d30092f109b1784b517398458eef71a3f757425231fe6769  
2024-03-12T14:58:19.399000+00:00 2024/03/12/apcKekSetup[$LATEST]ea4c6a7c85ac42da8a043aa8626d2897 START RequestId: a9b60171-dfaf-433a-954c-b0a332d22f50 Version: $LATEST  
2024-03-12T14:58:19.596000+00:00 2024/03/12/apcKekSetup[$LATEST]ea4c6a7c85ac42da8a043aa8626d2897 ##### Step 1. Generating Key Encryption Key (KEK) - Key that will be used to encrypt the Working Keys  
2024-03-12T14:58:19.850000+00:00 2024/03/12/apcKekSetup[$LATEST]ea4c6a7c85ac42da8a043aa8626d2897 ##### Step 2. Getting APC Import Parameters from us-east-1  
2024-03-12T14:58:21.680000+00:00 2024/03/12/apcKekSetup[$LATEST]ea4c6a7c85ac42da8a043aa8626d2897 ##### Step 3. Importing the Root Wrapping Certificates in us-west-2  
2024-03-12T14:58:21.826000+00:00 2024/03/12/apcKekSetup[$LATEST]ea4c6a7c85ac42da8a043aa8626d2897 ##### Step 4. Getting APC Export Parameters from us-west-2  
2024-03-12T14:58:23.193000+00:00 2024/03/12/apcKekSetup[$LATEST]ea4c6a7c85ac42da8a043aa8626d2897 ##### Step 5. Importing the Root Signing Certificates in us-east-1  
2024-03-12T14:58:23.439000+00:00 2024/03/12/apcKekSetup[$LATEST]ea4c6a7c85ac42da8a043aa8626d2897 ##### Step 6. Exporting the KEK from us-west-2  
2024-03-12T14:58:23.555000+00:00 2024/03/12/apcKekSetup[$LATEST]ea4c6a7c85ac42da8a043aa8626d2897 ##### Step 7. Importing the Wrapped KEK to us-east-1  
2024-03-12T14:58:23.840000+00:00 2024/03/12/apcKekSetup[$LATEST]ea4c6a7c85ac42da8a043aa8626d2897 ##### Initial Key Exchange Successfully Completed.  
2024-03-12T14:58:23.840000+00:00 2024/03/12/apcKekSetup[$LATEST]ea4c6a7c85ac42da8a043aa8626d2897 Keys Generated, Imported and Deleted in us-west-2 are now being automatically replicated to us-east-1  
2024-03-12T14:58:23.840000+00:00 2024/03/12/apcKekSetup[$LATEST]ea4c6a7c85ac42da8a043aa8626d2897 Keys already present in APC won't be replicated. If you want to, it must be done manually.  
2024-03-12T14:58:23.844000+00:00 2024/03/12/apcKekSetup[$LATEST]ea4c6a7c85ac42da8a043aa8626d2897 END RequestId: a9b60171-dfaf-433a-954c-b0a332d22f50  
2024-03-12T14:58:23.844000+00:00 2024/03/12/apcKekSetup[$LATEST]ea4c6a7c85ac42da8a043aa8626d2897 REPORT RequestId: a9b60171-dfaf-433a-954c-b0a332d22f50 Duration: 4444.78 ms Billed Duration: 4445 ms Memory Size: 5120 MB Max Memory Used: 95 MB Init Duration: 444.73 ms

After enabling the KEK, you can check which keys were created after CRR is enabled.  
It is expected to have 2 keys created in the region where CRR is deployed and 2 keys created where the Working Keys will be replicated to.

You can start creating and deleting keys in the Account and Region where the CRR solution was deployed.  
Currently the solution only listens to CreateKey, ImportKey and DeleteKey commands.  
CreateAlias and DeleteAlias were not yet implemented.

To tail the replication logs when creating, importing and deleting Working keys execute the following command:

```
$ aws logs tail "/aws/lambda/apcReplicateWk" --follow
```

It takes some time for the replication function to be triggered as it relies on the following steps:  
a - AWS Payment Cryptography (CreateKey, ImportKey or DeleteKey) log event is delivered to CloudTrail trail.  
b - Log event is sent to CloudWatch Logs log group, which triggers the subscription filter and the Lambda code associated with it is triggered.

Expected replication output for ImportKey and CreateKey:  
2024-03-05T15:57:13.871000+00:00 2024/03/05/apcReplicateWk[$LATEST]66dae4eef2bf42f6afd0e4cc70b48606 INIT_START Runtime Version: python:3.11.v29 Runtime Version ARN: arn:aws:lambda:us-east-1::runtime:2fb93380dac14772d30092f109b1784b517398458eef71a3f757425231fe6769  
2024-03-05T15:57:14.326000+00:00 2024/03/05/apcReplicateWk[$LATEST]66dae4eef2bf42f6afd0e4cc70b48606 START RequestId: c7670e9b-6db0-494e-86c4-4c64126695ee Version: $LATEST  
2024-03-05T15:57:14.327000+00:00 2024/03/05/apcReplicateWk[$LATEST]66dae4eef2bf42f6afd0e4cc70b48606 This is a WK! Sync in progress...  
2024-03-05T15:57:14.717000+00:00 2024/03/05/apcReplicateWk[$LATEST]66dae4eef2bf42f6afd0e4cc70b48606 ##### Step 1. Exporting SYMMETRIC_KEY arn:aws:payment-cryptography:us-east-1:111122223333:key/ifx5czt2lwhtxj7b from us-east-1 using alias/CRR_KEK_DO-NOT-DELETE_6e3606a32690 Key Encryption Key  
2024-03-05T15:57:15.044000+00:00 2024/03/05/apcReplicateWk[$LATEST]66dae4eef2bf42f6afd0e4cc70b48606 ##### Step 2. Importing the Wrapped Key to us-west-2  
2024-03-05T15:57:15.661000+00:00 2024/03/05/apcReplicateWk[$LATEST]66dae4eef2bf42f6afd0e4cc70b48606 Imported SYMMETRIC_KEY key: arn:aws:payment-cryptography:us-west-2:111122223333:key/bykk4cwnbyfu3exo as TR31_C0_CARD_VERIFICATION_KEY in us-west-2  
2024-03-05T15:57:15.794000+00:00 2024/03/05/apcReplicateWk[$LATEST]66dae4eef2bf42f6afd0e4cc70b48606 END RequestId: c7670e9b-6db0-494e-86c4-4c64126695ee  
2024-03-05T15:57:15.794000+00:00 2024/03/05/apcReplicateWk[$LATEST]66dae4eef2bf42f6afd0e4cc70b48606 REPORT RequestId: c7670e9b-6db0-494e-86c4-4c64126695ee Duration: 1468.13 ms Billed Duration: 1469 ms Memory Size: 128 MB Max Memory Used: 78 MB Init Duration: 454.02 ms

Expected replication output for DeleteKey:  
2024-03-05T16:02:56.892000+00:00 2024/03/05/apcReplicateWk[$LATEST]66dae4eef2bf42f6afd0e4cc70b48606 START RequestId: d557cb28-6974-4888-bb7b-9f8aa4b78640 Version: $LATEST  
2024-03-05T16:02:56.894000+00:00 2024/03/05/apcReplicateWk[$LATEST]66dae4eef2bf42f6afd0e4cc70b48606 This is not CreateKey or ImportKey!  
2024-03-05T16:02:57.621000+00:00 2024/03/05/apcReplicateWk[$LATEST]66dae4eef2bf42f6afd0e4cc70b48606 arn:aws:payment-cryptography:us-west-2:111122223333:key/bykk4cwnbyfu3exo deleted from us-west-2.  
2024-03-05T16:02:57.691000+00:00 2024/03/05/apcReplicateWk[$LATEST]66dae4eef2bf42f6afd0e4cc70b48606 END RequestId: d557cb28-6974-4888-bb7b-9f8aa4b78640  
2024-03-05T16:02:57.691000+00:00 2024/03/05/apcReplicateWk[$LATEST]66dae4eef2bf42f6afd0e4cc70b48606 REPORT RequestId: d557cb28-6974-4888-bb7b-9f8aa4b78640 Duration: 802.89 ms Billed Duration: 803 ms Memory Size: 128 MB Max Memory Used: 79 MB

To disable the CRR solution execute

```
$ ./disable-crr.sh
```

Expected output:  
➜ ./disable-crr.sh  
START RequestId: bc96659c-3063-460a-8b29-2aa21b967c9a Version: $LATEST  
Deletion has initiated...  
Please check the apcKekSetup log to check if the solution has been successfully disabled.  
You can do that by checking the CloudWatch Logs Log group /aws/apc-crr/apcKekSetup in the Management Console,  
or by typing on a shell terminal: aws logs tail "/aws/lambda/apcKekSetup" --follow

Please check the apcStackMonitor log to follow the stack deletion status.  
You can do that by checking the CloudWatch Logs Log group /aws/apc-crr/apcStackMonitor in the Management Console,  
or by typing on a shell terminal: aws logs tail "/aws/lambda/apcStackMonitor" --follow  
END RequestId: bc96659c-3063-460a-8b29-2aa21b967c9a  
REPORT RequestId: bc96659c-3063-460a-8b29-2aa21b967c9a Duration: 341.94 ms Billed Duration: 342 ms Memory Size: 128 MB Max Memory Used: 76 MB Init Duration: 429.87 ms

Again, follow the logs to check if the resources were correctly deleted.  
First, keys created during the exchange of the KEK will be deleted.  
Logs will be presented in the /aws/lambda/apcKekSetup Log group  
Expected output:  
2024-03-05T16:40:23.510000+00:00 2024/03/05/apcKekSetup[$LATEST]1c97946d8bc747b19cc35d9b1472ff8d INIT_START Runtime Version: python:3.11.v28 Runtime Version ARN: arn:aws:lambda:us-east-1::runtime:7893bafe1f7e5c0681bc8da889edf656777a53c2a26e3f73436bdcbc87ccfbe8  
2024-03-05T16:40:23.971000+00:00 2024/03/05/apcKekSetup[$LATEST]1c97946d8bc747b19cc35d9b1472ff8d START RequestId: fc10b303-f028-4a94-a2cf-b8c0a762ea16 Version: $LATEST  
2024-03-05T16:40:23.971000+00:00 2024/03/05/apcKekSetup[$LATEST]1c97946d8bc747b19cc35d9b1472ff8d Disabling CRR and Deleting KEKs  
2024-03-05T16:40:25.276000+00:00 2024/03/05/apcKekSetup[$LATEST]1c97946d8bc747b19cc35d9b1472ff8d Keys and aliases deleted from APC.  
2024-03-05T16:40:25.294000+00:00 2024/03/05/apcKekSetup[$LATEST]1c97946d8bc747b19cc35d9b1472ff8d DB status updated.  
2024-03-05T16:40:25.297000+00:00 2024/03/05/apcKekSetup[$LATEST]1c97946d8bc747b19cc35d9b1472ff8d END RequestId: fc10b303-f028-4a94-a2cf-b8c0a762ea16  
2024-03-05T16:40:25.297000+00:00 2024/03/05/apcKekSetup[$LATEST]1c97946d8bc747b19cc35d9b1472ff8d REPORT RequestId: fc10b303-f028-4a94-a2cf-b8c0a762ea16 Duration: 1326.39 ms Billed Duration: 1327 ms Memory Size: 5120 MB Max Memory Used: 94 MB Init Duration: 460.29 ms

Second, the CloudFormation stack will be deleted with associated resources.  
Logs will be presented in the /aws/lambda/apcStackMonitor Log group  
Expected output:  
2024-03-05T16:40:25.854000+00:00 2024/03/05/apcStackMonitor[$LATEST]2cb4c9044a08474894ff5fa81940dbec START RequestId: 6b0b8207-19ae-40a1-b889-c92f8a5c243c Version: $LATEST  
2024-03-05T16:40:26.486000+00:00 2024/03/05/apcStackMonitor[$LATEST]2cb4c9044a08474894ff5fa81940dbec De-provisioning Resources in the Destination Region. StackName: apc-setup-orchestrator-77aecbcf-1e4f-4e2a-8faa-6e3606a32690  
2024-03-05T16:40:26.805000+00:00 2024/03/05/apcStackMonitor[$LATEST]2cb4c9044a08474894ff5fa81940dbec Stack deletion in progress. Status: DELETE_IN_PROGRESS  
2024-03-05T16:40:31.889000+00:00 2024/03/05/apcStackMonitor[$LATEST]2cb4c9044a08474894ff5fa81940dbec Stack deletion in progress. Status: DELETE_IN_PROGRESS  
2024-03-05T16:40:36.977000+00:00 2024/03/05/apcStackMonitor[$LATEST]2cb4c9044a08474894ff5fa81940dbec Stack deletion in progress. Status: DELETE_IN_PROGRESS  
2024-03-05T16:40:42.065000+00:00 2024/03/05/apcStackMonitor[$LATEST]2cb4c9044a08474894ff5fa81940dbec Stack deletion in progress. Status: DELETE_IN_PROGRESS  
2024-03-05T16:40:47.152000+00:00 2024/03/05/apcStackMonitor[$LATEST]2cb4c9044a08474894ff5fa81940dbec Stack deletion in progress. Status: DELETE_IN_PROGRESS  
...  
2024-03-05T16:44:10.598000+00:00 2024/03/05/apcStackMonitor[$LATEST]2cb4c9044a08474894ff5fa81940dbec Stack deletion in progress. Status: DELETE_IN_PROGRESS  
2024-03-05T16:44:15.683000+00:00 2024/03/05/apcStackMonitor[$LATEST]2cb4c9044a08474894ff5fa81940dbec Stack deletion in progress. Status: DELETE_IN_PROGRESS  
2024-03-05T16:44:20.847000+00:00 2024/03/05/apcStackMonitor[$LATEST]2cb4c9044a08474894ff5fa81940dbec Stack deletion completed. Status: DELETE_COMPLETE  
2024-03-05T16:44:21.043000+00:00 2024/03/05/apcStackMonitor[$LATEST]2cb4c9044a08474894ff5fa81940dbec Resources successfully deleted. Status: DELETE_COMPLETE  
2024-03-05T16:44:21.601000+00:00 2024/03/05/apcStackMonitor[$LATEST]2cb4c9044a08474894ff5fa81940dbec END RequestId: 6b0b8207-19ae-40a1-b889-c92f8a5c243c  
2024-03-05T16:44:21.601000+00:00 2024/03/05/apcStackMonitor[$LATEST]2cb4c9044a08474894ff5fa81940dbec REPORT RequestId: 6b0b8207-19ae-40a1-b889-c92f8a5c243cDuration: 235746.42 ms Billed Duration: 235747 ms Memory Size: 128 MB Max Memory Used: 94 MB

To change the parameters for enabling and disabling the solution check cdk.json and enable-crr.json.  
cdk.json file contain a key called ENVIRONMENTS. PLEASE, DO NOT CHANGE KEY NAMES, ONLY VALUES. OTHERWISE THE DEPLOYMENT WILL CRASH.  
Example:

```json
"ENVIRONMENTS": {
      "dev": {
        "origin_vpc_cidr": "10.2.0.0/16",
        "origin_vpc_name": "origin-vpc",
        "origin_subnets_mask": 22,
        "origin_subnets_prefix_name": "origin-subnet-private"
      }
    }
```

origin_vpc_cidr, origin_vpc_name and origin_subnets_prefix_name can be changed.  
The solution "as is" is deployed in 2 AZs only.  
After executing the deployment for the first time, a new key/value string will be generated after the origin_subnets_prefix_name entry. DO NOT CHANGE THIS KEY/VALUE. This is internal to the solution and this information can change. It was created as for us-east-1, APC VPC Endpoints are currently available in only 3 AZs. This creates a mapping, for each account, between AZ IDs and AZs:  
https://docs.aws.amazon.com/ram/latest/userguide/working-with-az-ids.html

enable-crr.json file contain the information where to deploy the infrastructure where the keys will be replicated to (Destination Region).  
Example:

```json
{
  "enabled": true,
  "dest_region": "us-west-2",
  "kek_alias": "CRR_KEK_DO-NOT-DELETE_",
  "key_algo": "TDES_3KEY",
  "kdh_alias": "KDH_SIGN_KEY_DO-NOT-DELETE_",
  "krd_alias": "KRD_SIGN_KEY_DO-NOT-DELETE_",
  "dest_vpc_name": "apc-crr/destination-vpc",
  "dest_vpc_cidr": "10.3.0.0/16",
  "dest_subnet1_cidr": "10.3.0.0/22",
  "dest_subnet2_cidr": "10.3.4.0/22",
  "dest_subnets_prefix_name": "apc-crr/destination-vpc/destination-subnet-private",
  "dest_rt_prefix_name": "apc-crr/destination-vpc/destination-rtb-private"
}
```

disable-crr.json file contain only the information to disable the CRR solution.  
Example:

```json
{
  "enabled": false
}
```

To delete the entire infrastructure execute:

```
$ cdk destroy
```

Ensure that the CRR solution was disabled first, otherwise you'll have to manually delete the CloudFormation Stack in the Destination Region and any other provisioned resource.  
Expected output:  
➜ cdk destroy  
Are you sure you want to delete: apc-crr (y/n)? y  
apc-crr: destroying... [1/1]

✅ apc-crr: destroyed

Known issues (still researching how to resolve them) and Enhancements:

1. [Enhancement]After destroying the infrastructure, some CloudWatch Log groups related to Custom Lambdas generated and deployed by the CDK are not deleted.  
   (Log group name: /aws/lambda/apc-crr-AWS*)  
   (Log group name: /aws/lambda/apc-crr-CustomCDKBucketDeployment*)  
   (Log group name: /aws/lambda/apc-crr-CustomS3AutoDeleteObjectsCustomResourcePro*)  
   (Log group name:/aws/lambda/apc-crr-CustomVpcRestrictDefaultSGCustomResourcePr*)

2. [Issue]Lambda functions are being created with XRay default permissions.

3. [Enhancement]If the CloudFormation Stack doesn't finish correctly (CREATE_COMPLETE state) there is no automatic intervention. Stack rollback is disabled to better diagnose the issue.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.
