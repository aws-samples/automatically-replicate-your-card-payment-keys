# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

from aws_cdk import Stack
import aws_cdk as cdk
import aws_cdk.aws_cloudtrail as cloudtrail
import aws_cdk.aws_dynamodb as dynamodb
import aws_cdk.aws_iam as iam
import aws_cdk.aws_lambda as aws_lambda
import aws_cdk.aws_lambda_event_sources as lambda_event_sources
import aws_cdk.aws_logs as logs
import aws_cdk.aws_s3 as s3
import aws_cdk.aws_s3_deployment as s3_deployment
import aws_cdk.aws_ec2 as ec2
import aws_cdk.custom_resources as cr
from aws_cdk import RemovalPolicy
from constructs import Construct
import hashlib
import json

class ApcCrrStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Resources

        environments = self.node.try_get_context('ENVIRONMENTS')
        dev_env = environments.get('dev')
        origin_vpc_cidr = dev_env.get('origin_vpc_cidr')
        origin_vpc_name = dev_env.get('origin_vpc_name')
        origin_subnets_mask = dev_env.get('origin_subnets_mask')
        origin_subnets_prefix_name = dev_env.get('origin_subnets_prefix_name')
        account_hash = hashlib.sha256(self.account.encode('utf-8')).hexdigest()
        azs = dev_env.get(account_hash)

        if self.region != 'us-east-1':
            azs = self.availability_zones[:2]

        getAwsManagedPrefixList = cr.AwsCustomResource(self, 'getAwsManagedPrefixList',
                                                       on_create=cr.AwsSdkCall(
                                                           service='EC2',
                                                           action='describeManagedPrefixLists',
                                                           parameters={
                                                                   "Filters": [{'Name': 'prefix-list-name', 'Values': ['.'.join(['com.amazonaws', self.region, 'dynamodb'])]}]
                                                           },
                                                           physical_resource_id=cr.PhysicalResourceId.of(
                                                               'getAwsManagedPrefixList')
                                                       ),
                                                       policy=cr.AwsCustomResourcePolicy.from_sdk_calls(
                                                           resources=cr.AwsCustomResourcePolicy.ANY_RESOURCE)
                                                       )

        originVpc = ec2.Vpc(self, origin_vpc_name,
                            ip_addresses=ec2.IpAddresses.cidr(origin_vpc_cidr),
                            availability_zones=azs,
                            create_internet_gateway=False,
                            subnet_configuration=[
                                ec2.SubnetConfiguration(
                                    name=origin_subnets_prefix_name,
                                    subnet_type=ec2.SubnetType.PRIVATE_ISOLATED,
                                    cidr_mask=origin_subnets_mask
                                )
                            ],
                            gateway_endpoints={
                                'apc-crr-dynamodb-endpoint': ec2.GatewayVpcEndpointOptions(
                                    service=ec2.GatewayVpcEndpointAwsService.DYNAMODB
                                )
                            }
                            )

        apcVpcEndpointSG = ec2.SecurityGroup(self, 'ApcCrrVPCeSecurityGroup',
                                             vpc=originVpc,
                                             allow_all_outbound=False,
                                             description='Security group for VPC endpoints',
                                             security_group_name='ApcCrrVPCeSecurityGroup'
                                             )

        apcVpcEndpointSG.connections.allow_from(apcVpcEndpointSG,
                                                ec2.Port.all_traffic(), 'allow inbound traffic')

        apcVpcEndpointSG.connections.allow_to(apcVpcEndpointSG,
                                              ec2.Port.tcp(443), 'allow outbound traffic')

        apcVpcEndpointSG.add_egress_rule(
            ec2.Peer.prefix_list(getAwsManagedPrefixList.get_response_field(
                'PrefixLists.0.PrefixListId')),
            ec2.Port.tcp(443), 'allow outbound traffic'
        )

        originVpc.add_interface_endpoint('logs-endpoint',
                                         service=ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_LOGS,
                                         private_dns_enabled=True,
                                         subnets=ec2.SubnetSelection(
                                             subnet_type=ec2.SubnetType.PRIVATE_ISOLATED),
                                         security_groups=[apcVpcEndpointSG]
                                         )

        originVpc.add_interface_endpoint('apc-cp-endpoint',
                                         service=ec2.InterfaceVpcEndpointAwsService(
                                             'payment-cryptography.controlplane'),
                                         private_dns_enabled=True,
                                         subnets=ec2.SubnetSelection(
                                             subnet_type=ec2.SubnetType.PRIVATE_ISOLATED),
                                         security_groups=[apcVpcEndpointSG]
                                         )

        dynamoDbTableApcCrr = dynamodb.Table(self, 'DynamoDbTableApcCrr',
                                             partition_key=dynamodb.Attribute(
                                                   name='account_id', type=dynamodb.AttributeType.STRING),
                                             sort_key=dynamodb.Attribute(
                                                 name='lambda_request_id', type=dynamodb.AttributeType.STRING),
                                             billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
                                             removal_policy=RemovalPolicy.DESTROY,
                                             contributor_insights_enabled=False,
                                             point_in_time_recovery=False,
                                             encryption=dynamodb.TableEncryption.DEFAULT,
                                             stream=dynamodb.StreamViewType.NEW_AND_OLD_IMAGES
                                             )

        dynamoDbTableApcCrrMapping = dynamodb.Table(self, 'DynamoDbTableApcCrrMapping',
                                                    partition_key=dynamodb.Attribute(
                                                          name='origin_key_arn', type=dynamodb.AttributeType.STRING),
                                                    billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
                                                    removal_policy=RemovalPolicy.DESTROY,
                                                    contributor_insights_enabled=False,
                                                    point_in_time_recovery=False,
                                                    encryption=dynamodb.TableEncryption.DEFAULT,
                                                    )

        dynamoDbTableApcCrrStack = dynamodb.Table(self, 'DynamoDbTableApcCrrStack',
                                                  partition_key=dynamodb.Attribute(
                                                      name='stack_id', type=dynamodb.AttributeType.STRING),
                                                  billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
                                                  removal_policy=RemovalPolicy.DESTROY,
                                                  contributor_insights_enabled=False,
                                                  point_in_time_recovery=False,
                                                  encryption=dynamodb.TableEncryption.DEFAULT,
                                                  stream=dynamodb.StreamViewType.NEW_IMAGE
                                                  )

        logGroupApcManageSetup = logs.LogGroup(self, 'LogGroupApcManageSetup',
                                               removal_policy=RemovalPolicy.DESTROY,
                                               log_group_name='/aws/lambda/apcManageSetup',
                                               )

        logGroupApcStackMonitor = logs.LogGroup(self, 'LogGroupApcStackMonitor',
                                                removal_policy=RemovalPolicy.DESTROY,
                                                log_group_name='/aws/lambda/apcStackMonitor',
                                                )

        logGroupApcKekSetup = logs.LogGroup(self, 'LogGroupApcKekSetup',
                                            removal_policy=RemovalPolicy.DESTROY,
                                            log_group_name='/aws/lambda/apcKekSetup',
                                            )

        logGroupApcReplicateWk = logs.LogGroup(self, 'LogGroupApcReplicateWk',
                                               removal_policy=RemovalPolicy.DESTROY,
                                               log_group_name='/aws/lambda/apcReplicateWk',
                                               )

        logsLogGroupCTlogs = logs.LogGroup(self, 'LogsLogGroupCTlogs',
                                           removal_policy=RemovalPolicy.DESTROY,
                                           log_group_name='-'.join([
                                               'aws-cloudtrail-logs',
                                               self.account,
                                               cdk.Fn.select(0, cdk.Fn.split(
                                                   '-', cdk.Fn.select(2, cdk.Fn.split('/', self.stack_id)))),
                                           ])
                                           )

        s3BucketCtLogs = s3.Bucket(self, 's3BucketCTLogs',
                                   block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                                   removal_policy=RemovalPolicy.DESTROY,
                                   auto_delete_objects=True,
                                   object_ownership=s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
                                   encryption=s3.BucketEncryption.S3_MANAGED,
                                   enforce_ssl=True,
                                   bucket_name='-'.join([
                                       'aws-cloudtrail-logs',
                                       self.account,
                                       cdk.Fn.select(0, cdk.Fn.split(
                                           '-', cdk.Fn.select(2, cdk.Fn.split('/', self.stack_id)))),
                                   ])
                                   )

        s3BucketCtLogs.add_to_resource_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                principals=[iam.ServicePrincipal('cloudtrail.amazonaws.com')],
                actions=['s3:GetBucketAcl'],
                resources=[s3BucketCtLogs.bucket_arn],
                conditions={
                    'StringEquals': {
                        'aws:SourceArn': ':'.join([
                            'arn:aws:cloudtrail',
                            self.region,
                            self.account,
                            'trail/management-events',
                        ]),
                    },
                }
            )
        )

        s3BucketCtLogs.add_to_resource_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                principals=[iam.ServicePrincipal('cloudtrail.amazonaws.com')],
                actions=['s3:PutObject'],
                resources=[
                    ''.join([s3BucketCtLogs.bucket_arn, '/AWSLogs/', self.account, '/*'])],
                conditions={
                    'StringEquals': {
                        'aws:SourceArn': ':'.join([
                            'arn:aws:cloudtrail',
                            self.region,
                            self.account,
                            'trail/management-events',
                        ]),
                        's3:x-amz-acl': 'bucket-owner-full-control',
                    },
                }
            )
        )

        s3BucketCfnTemplates = s3.Bucket(self, 's3BucketCfnTemplates',
                                         block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                                         removal_policy=RemovalPolicy.DESTROY,
                                         auto_delete_objects=True,
                                         object_ownership=s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
                                         encryption=s3.BucketEncryption.S3_MANAGED,
                                         enforce_ssl=True,
                                         bucket_name='-'.join([
                                             'apc-crr-cfn-templates',
                                             self.account,
                                             cdk.Fn.select(0, cdk.Fn.split(
                                                 '-', cdk.Fn.select(2, cdk.Fn.split('/', self.stack_id)))),
                                         ])
                                         )

        deployment = s3_deployment.BucketDeployment(self, 'DeployCfnTemplates',
                                                    destination_bucket=s3BucketCfnTemplates,
                                                    sources=[
                                                        s3_deployment.Source.asset(
                                                            './templates/deployment')
                                                    ]
                                                    )

        iamPolicyApcSetupOrchestrator = iam.ManagedPolicy(self, 'IAMPolicyApcSetupOrchestrator',
                                                          description='Policy for Lambda that performs the APC Setup Orchestrator',
                                                          managed_policy_name='APC-CRR-LambdaPolicy-SetupOrchestrator',
                                                          path='/',
                                                          document=(
                                                               iam.PolicyDocument(
                                                                   statements=[
                                                                       iam.PolicyStatement(
                                                                           effect=iam.Effect.ALLOW,
                                                                           actions=[
                                                                               'ec2:AcceptVpcPeeringConnection',
                                                                               'ec2:AssociateRouteTable',
                                                                               'ec2:AuthorizeSecurityGroupIngress',
                                                                               'ec2:AuthorizeSecurityGroupEgress',
                                                                               'ec2:CreateRoute',
                                                                               'ec2:CreateRouteTable',
                                                                               'ec2:CreateSubnet',
                                                                               'ec2:CreateTags',
                                                                               'ec2:CreateVpc',
                                                                               'ec2:CreateVpcEndpoint',
                                                                               'ec2:CreateVpcPeeringConnection',
                                                                               'ec2:CreateSecurityGroup',
                                                                               'ec2:DeleteRoute',
                                                                               'ec2:DeleteRouteTable',
                                                                               'ec2:DeleteSubnet',
                                                                               'ec2:DeleteVpc',
                                                                               'ec2:DeleteVpcEndpoints',
                                                                               'ec2:DeleteVpcPeeringConnection',
                                                                               'ec2:DeleteSecurityGroup',
                                                                               'ec2:DescribeAvailabilityZones',
                                                                               'ec2:DescribeRouteTables',
                                                                               'ec2:DescribeSecurityGroups',
                                                                               'ec2:DescribeTags',
                                                                               'ec2:DescribeVpcEndpoints',
                                                                               'ec2:DescribeVpcPeeringConnections',
                                                                               'ec2:DescribeVpcs',
                                                                               'ec2:DescribeSubnets',
                                                                               'ec2:DisassociateRouteTable',
                                                                               'ec2:ModifyVpcAttribute',
                                                                               'ec2:RevokeSecurityGroupIngress',
                                                                               'ec2:RevokeSecurityGroupEgress',
                                                                               'route53:ListQueryLoggingConfigs',
                                                                               'route53:CreateHostedZone',
                                                                               'route53:DeleteHostedZone',
                                                                               'route53:GetChange',
                                                                               'route53:GetHostedZone',
                                                                           ],
                                                                           resources=[
                                                                               '*'
                                                                           ]),
                                                                       iam.PolicyStatement(
                                                                           effect=iam.Effect.ALLOW,
                                                                           actions=[
                                                                               'route53:AssociateVPCWithHostedZone',
                                                                               'route53:ChangeResourceRecordSets',
                                                                               'route53:DisassociateVPCFromHostedZone'
                                                                           ],
                                                                           resources=[
                                                                               'arn:aws:route53:::hostedzone/*'
                                                                           ]),
                                                                   ]
                                                               )
                                                          )
                                                          )

        iamRoleApcSetupOrchestrator = iam.Role(self, 'IAMRoleApcSetupOrchestrator',
                                               assumed_by=iam.ServicePrincipal(
                                                   'cloudformation.amazonaws.com'),
                                               managed_policies=[
                                                   iam.ManagedPolicy.from_managed_policy_name(
                                                       self, 'iamIPolicyApcSetupOrchestrator', iamPolicyApcSetupOrchestrator.managed_policy_name)
                                               ],
                                               path='/'
                                               )

        iamPolicyApcCrrLambdaManageSetup = iam.ManagedPolicy(self, 'IAMPolicyApcCrrLambdaManageSetup',
                                                             description='Policy for Lambda that manages CRR',
                                                             managed_policy_name='APC-CRR-LambdaManageSetup',
                                                             path='/',
                                                             document=(
                                                                  iam.PolicyDocument(
                                                                      statements=[
                                                                          iam.PolicyStatement(
                                                                              effect=iam.Effect.ALLOW,
                                                                              actions=[
                                                                                  'dynamodb:PutItem',
                                                                                  'dynamodb:Query',
                                                                                  'dynamodb:UpdateItem',
                                                                              ],
                                                                              resources=[
                                                                                  ''.join([
                                                                                      'arn:aws:dynamodb:',
                                                                                      self.region,
                                                                                      ':',
                                                                                      self.account,
                                                                                      ':table/',
                                                                                      dynamoDbTableApcCrr.table_name
                                                                                  ]),
                                                                              ]),
                                                                          iam.PolicyStatement(
                                                                              effect=iam.Effect.ALLOW,
                                                                              actions=[
                                                                                  'dynamodb:PutItem',
                                                                              ],
                                                                              resources=[
                                                                                  ''.join([
                                                                                      'arn:aws:dynamodb:',
                                                                                      self.region,
                                                                                      ':',
                                                                                      self.account,
                                                                                      ':table/',
                                                                                      dynamoDbTableApcCrrStack.table_name
                                                                                  ]),
                                                                              ]),
                                                                          iam.PolicyStatement(
                                                                              effect=iam.Effect.ALLOW,
                                                                              actions=[
                                                                                  'logs:CreateLogStream',
                                                                                  'logs:PutLogEvents',
                                                                              ],
                                                                              resources=[
                                                                                  ''.join([
                                                                                      'arn:aws:logs:',
                                                                                      self.region,
                                                                                      ':',
                                                                                      self.account,
                                                                                      ':log-group:/aws/lambda/apcManageSetup:*',
                                                                                  ]),
                                                                              ]),
                                                                          iam.PolicyStatement(
                                                                              effect=iam.Effect.ALLOW,
                                                                              actions=[
                                                                                  'logs:CreateLogGroup',
                                                                              ],
                                                                              resources=[
                                                                                  ''.join([
                                                                                      'arn:aws:logs:',
                                                                                      self.region,
                                                                                      ':',
                                                                                      self.account,
                                                                                      ':*',
                                                                                  ]),
                                                                              ]),
                                                                          iam.PolicyStatement(
                                                                              effect=iam.Effect.ALLOW,
                                                                              actions=[
                                                                                  'cloudformation:CreateStack',
                                                                                  'cloudformation:DescribeStacks',
                                                                              ],
                                                                              resources=[
                                                                                  ''.join([
                                                                                      'arn:aws:cloudformation:*:',
                                                                                      self.account,
                                                                                      ':stack/*/*',
                                                                                  ]),
                                                                              ]),
                                                                          iam.PolicyStatement(
                                                                              effect=iam.Effect.ALLOW,
                                                                              actions=[
                                                                                  's3:GetObject',
                                                                              ],
                                                                              resources=[
                                                                                  ''.join([
                                                                                      'arn:aws:s3:::',
                                                                                      s3BucketCfnTemplates.bucket_name,
                                                                                      '/ApcCrrOrchestrator.yaml',
                                                                                  ]),
                                                                              ]),
                                                                          iam.PolicyStatement(
                                                                              effect=iam.Effect.ALLOW,
                                                                              actions=[
                                                                                  'iam:PassRole',
                                                                              ],
                                                                              resources=[
                                                                                  iamRoleApcSetupOrchestrator.role_arn
                                                                              ]),
                                                                      ]
                                                                  )
                                                             )
                                                             )

        iamRoleApcManageSetup = iam.Role(self, 'iamRoleApcManageSetup',
                                         assumed_by=iam.ServicePrincipal(
                                             'lambda.amazonaws.com'),
                                         managed_policies=[
                                             iam.ManagedPolicy.from_managed_policy_name(
                                                 self, 'iamIPolicyApcCrrManageSetupLambdaPolicy', iamPolicyApcCrrLambdaManageSetup.managed_policy_name),
                                         ],
                                         )

        iamPolicyApcCrrStackMonitorLambda = iam.ManagedPolicy(self, 'IAMPolicyApcCrrStackMonitorLambda',
                                                              description='Policy for Lambda that monitors CRR',
                                                              managed_policy_name='APC-CRR-StackMonitorLambda',
                                                              path='/',
                                                              document=(
                                                                  iam.PolicyDocument(
                                                                      statements=[
                                                                          iam.PolicyStatement(
                                                                              effect=iam.Effect.ALLOW,
                                                                              actions=[
                                                                                  'dynamodb:DeleteItem',
                                                                                  'dynamodb:Query'
                                                                              ],
                                                                              resources=[
                                                                                  ''.join([
                                                                                      'arn:aws:dynamodb:',
                                                                                      self.region,
                                                                                      ':',
                                                                                      self.account,
                                                                                      ':table/',
                                                                                      dynamoDbTableApcCrrStack.table_name
                                                                                  ]),
                                                                              ]),
                                                                          iam.PolicyStatement(
                                                                              effect=iam.Effect.ALLOW,
                                                                              actions=[
                                                                                  'dynamodb:UpdateItem'
                                                                              ],
                                                                              resources=[
                                                                                  ''.join([
                                                                                      'arn:aws:dynamodb:',
                                                                                      self.region,
                                                                                      ':',
                                                                                      self.account,
                                                                                      ':table/',
                                                                                      dynamoDbTableApcCrr.table_name
                                                                                  ]),
                                                                              ]),
                                                                          iam.PolicyStatement(
                                                                              effect=iam.Effect.ALLOW,
                                                                              actions=[
                                                                                  'logs:CreateLogGroup',
                                                                              ],
                                                                              resources=[
                                                                                  ''.join([
                                                                                      'arn:aws:logs:',
                                                                                      self.region,
                                                                                      ':',
                                                                                      self.account,
                                                                                      ':*',
                                                                                  ]),

                                                                              ]),
                                                                          iam.PolicyStatement(
                                                                              effect=iam.Effect.ALLOW,
                                                                              actions=[
                                                                                  'logs:CreateLogStream',
                                                                                  'logs:PutLogEvents',
                                                                              ],
                                                                              resources=[
                                                                                  ''.join([
                                                                                      'arn:aws:logs:',
                                                                                      self.region,
                                                                                      ':',
                                                                                      self.account,
                                                                                      ':log-group:/aws/lambda/apcStackMonitor:*',
                                                                                  ]),
                                                                              ]),
                                                                          iam.PolicyStatement(
                                                                              effect=iam.Effect.ALLOW,
                                                                              actions=[
                                                                                  'ec2:CreateRoute',
                                                                                  'ec2:DeleteRoute',
                                                                                  'cloudformation:DeleteStack',
                                                                                  'cloudformation:ListStacks'
                                                                              ],
                                                                              resources=[
                                                                                  ''.join([
                                                                                      'arn:aws:ec2:',
                                                                                      self.region,
                                                                                      ':',
                                                                                      self.account,
                                                                                      ':route-table/*',
                                                                                  ]),
                                                                                  ''.join([
                                                                                      'arn:aws:cloudformation:*:',
                                                                                      self.account,
                                                                                      ':stack/*/*',
                                                                                  ]),
                                                                              ]),
                                                                          iam.PolicyStatement(
                                                                              effect=iam.Effect.ALLOW,
                                                                              actions=[
                                                                                  'ec2:AuthorizeSecurityGroupEgress',
                                                                                  'ec2:RevokeSecurityGroupEgress',
                                                                                  'ec2:DescribeVpcPeeringConnections',
                                                                                  'ec2:DescribeRouteTables',
                                                                                  'ec2:DescribeSecurityGroups',
                                                                                  'cloudformation:DescribeStacks',
                                                                              ],
                                                                              resources=[
                                                                                  '*'
                                                                              ]),
                                                                      ])
                                                              )
                                                              )

        iamRoleApcStackMonitor = iam.Role(self, 'iamRoleApcStackMonitor',
                                          assumed_by=iam.ServicePrincipal(
                                              'lambda.amazonaws.com'),
                                          managed_policies=[
                                              iam.ManagedPolicy.from_managed_policy_name(
                                                  self, 'iamIPolicyApcCrrStackMonitorLambdaPolicy', iamPolicyApcCrrStackMonitorLambda.managed_policy_name),
                                          ],
                                          )

        iamPolicyApcCrrLambdaPolicy = iam.ManagedPolicy(self, 'IAMPolicyApcCrrLambdaPolicy',
                                                        description='Policy for Lambda that manages CRR',
                                                        managed_policy_name='APC-CRR-LambdaPolicy',
                                                        path='/',
                                                        document=(
                                                            iam.PolicyDocument(
                                                                statements=[
                                                                    iam.PolicyStatement(
                                                                            effect=iam.Effect.ALLOW,
                                                                        actions=[
                                                                            'payment-cryptography:GetParametersForExport',
                                                                            'payment-cryptography:GetParametersForImport',
                                                                            'logs:DescribeLogGroups',
                                                                            'dynamodb:ListStreams',
                                                                        ],
                                                                        resources=[
                                                                            '*'
                                                                        ]),
                                                                    iam.PolicyStatement(
                                                                        effect=iam.Effect.ALLOW,
                                                                        actions=[
                                                                            'payment-cryptography:ExportKey',
                                                                            'payment-cryptography:GetKey',
                                                                            'payment-cryptography:DeleteKey',
                                                                            'payment-cryptography:ImportKey',
                                                                            'payment-cryptography:CreateKey',
                                                                            'payment-cryptography:CreateAlias',
                                                                            'payment-cryptography:GetAlias',
                                                                            'payment-cryptography:DeleteAlias',
                                                                        ],
                                                                        resources=[
                                                                            ''.join([
                                                                                'arn:aws:payment-cryptography:*:',
                                                                                self.account,
                                                                                ':key/*',
                                                                            ]),
                                                                            ''.join([
                                                                                'arn:aws:payment-cryptography:*:',
                                                                                self.account,
                                                                                ':alias/*',
                                                                            ]),
                                                                        ]),
                                                                    iam.PolicyStatement(
                                                                        effect=iam.Effect.ALLOW,
                                                                        actions=[
                                                                            'logs:CreateLogGroup'
                                                                        ],
                                                                        resources=[
                                                                            ''.join([
                                                                                'arn:aws:logs:',
                                                                                self.region,
                                                                                ':',
                                                                                self.account,
                                                                                ':*',
                                                                            ]),
                                                                        ]),
                                                                    iam.PolicyStatement(
                                                                        effect=iam.Effect.ALLOW,
                                                                        actions=[
                                                                            'logs:DescribeSubscriptionFilters',
                                                                            'logs:PutSubscriptionFilter',
                                                                            'logs:DeleteSubscriptionFilter',
                                                                        ],
                                                                        resources=[
                                                                            ''.join([
                                                                                'arn:aws:logs:',
                                                                                self.region,
                                                                                ':',
                                                                                self.account,
                                                                                ':destination:*',
                                                                            ]),
                                                                            ''.join([
                                                                                'arn:aws:logs:',
                                                                                self.region,
                                                                                ':',
                                                                                self.account,
                                                                                ':log-group:*',
                                                                            ]),
                                                                        ]),
                                                                    iam.PolicyStatement(
                                                                        effect=iam.Effect.ALLOW,
                                                                        actions=[
                                                                            'dynamodb:PutItem',
                                                                            'dynamodb:GetItem',
                                                                            'dynamodb:UpdateItem',
                                                                            'dynamodb:Query',
                                                                        ],
                                                                        resources=[
                                                                            ''.join([
                                                                                'arn:aws:dynamodb:',
                                                                                self.region,
                                                                                ':',
                                                                                self.account,
                                                                                ':table/',
                                                                                dynamoDbTableApcCrr.table_name
                                                                            ]),
                                                                        ]),
                                                                    iam.PolicyStatement(
                                                                        effect=iam.Effect.ALLOW,
                                                                        actions=[
                                                                            'logs:CreateLogStream',
                                                                            'logs:PutLogEvents',
                                                                        ],
                                                                        resources=[
                                                                            ''.join([
                                                                                'arn:aws:logs:',
                                                                                self.region,
                                                                                ':',
                                                                                self.account,
                                                                                ':log-group:/aws/lambda/apcKekSetup:*',
                                                                            ]),
                                                                        ]),
                                                                ]
                                                            )
                                                        )
                                                        )

        iamPolicyApcCrrLambdaVPCPolicy = iam.ManagedPolicy(self, 'IAMPolicyApcCrrLambdaVPCPolicy',
                                                           description='Policy for Lambda that allows VPC resources',
                                                           managed_policy_name='APC-CRR-LambdaVPCPolicy',
                                                           path='/',
                                                           document=(
                                                               iam.PolicyDocument(
                                                                statements=[
                                                                    iam.PolicyStatement(
                                                                        effect=iam.Effect.ALLOW,
                                                                        actions=[
                                                                            'ec2:DescribeNetworkInterfaces',
                                                                            'ec2:DescribeSubnets',
                                                                            'ec2:CreateNetworkInterface',
                                                                            'ec2:DeleteNetworkInterface',
                                                                            'ec2:UnassignPrivateIpAddresses',
                                                                            'ec2:AssignPrivateIpAddresses'
                                                                        ],
                                                                        resources=[
                                                                            '*'
                                                                        ]),
                                                                ]
                                                               )
                                                           )
                                                           )

        iamRoleApcKekSetup = iam.Role(self, 'IAMRoleApcKekSetup',
                                      assumed_by=iam.ServicePrincipal(
                                          'lambda.amazonaws.com'),
                                      managed_policies=[
                                          iam.ManagedPolicy.from_managed_policy_name(
                                              self, 'iamIPolicyApcCrrKekSetupLambdaPolicy', iamPolicyApcCrrLambdaPolicy.managed_policy_name),
                                          iam.ManagedPolicy.from_managed_policy_name(
                                              self, 'iamIPolicyApcCrrKekSetupLambdaVPCPolicy', iamPolicyApcCrrLambdaVPCPolicy.managed_policy_name),
                                      ],
                                      path='/'
                                      )

        iamPolicyApcCrrReplicationLambdaPolicy = iam.ManagedPolicy(self, 'IAMPolicyApcCrrReplicationLambdaPolicy',
                                                                   description='Policy for Lambda that performs the Working Keys Replication between AWS regions',
                                                                   managed_policy_name='APC-CRR-LambdaPolicy-Replication',
                                                                   path='/',
                                                                   document=(
                                                                       iam.PolicyDocument(
                                                                           statements=[
                                                                               iam.PolicyStatement(
                                                                                   effect=iam.Effect.ALLOW,
                                                                                   actions=[
                                                                                       'payment-cryptography:ExportKey',
                                                                                       'payment-cryptography:GetKey',
                                                                                       'payment-cryptography:DeleteKey',
                                                                                       'payment-cryptography:ImportKey',
                                                                                       'payment-cryptography:GetPublicKeyCertificate',
                                                                                   ],
                                                                                   resources=[
                                                                                       ''.join([
                                                                                           'arn:aws:payment-cryptography:*:',
                                                                                           self.account,
                                                                                           ':key/*',
                                                                                       ]),
                                                                                   ]),
                                                                               iam.PolicyStatement(
                                                                                   effect=iam.Effect.ALLOW,
                                                                                   actions=[
                                                                                       'logs:CreateLogGroup',
                                                                                   ],
                                                                                   resources=[
                                                                                       ''.join([
                                                                                           'arn:aws:logs:',
                                                                                           self.region,
                                                                                           ':',
                                                                                           self.account,
                                                                                           ':*',
                                                                                       ]),
                                                                                   ]),
                                                                               iam.PolicyStatement(
                                                                                   effect=iam.Effect.ALLOW,
                                                                                   actions=[
                                                                                       'dynamodb:Query',
                                                                                   ],
                                                                                   resources=[
                                                                                       ''.join([
                                                                                           'arn:aws:dynamodb:',
                                                                                           self.region,
                                                                                           ':',
                                                                                           self.account,
                                                                                           ':table/',
                                                                                           dynamoDbTableApcCrr.table_name
                                                                                       ]),
                                                                                   ]),
                                                                               iam.PolicyStatement(
                                                                                   effect=iam.Effect.ALLOW,
                                                                                   actions=[
                                                                                       'dynamodb:PutItem',
                                                                                       'dynamodb:DeleteItem',
                                                                                       'dynamodb:GetItem',
                                                                                   ],
                                                                                   resources=[
                                                                                       ''.join([
                                                                                           'arn:aws:dynamodb:',
                                                                                           self.region,
                                                                                           ':',
                                                                                           self.account,
                                                                                           ':table/',
                                                                                           dynamoDbTableApcCrrMapping.table_name,
                                                                                       ]),
                                                                                   ]),
                                                                               iam.PolicyStatement(
                                                                                   effect=iam.Effect.ALLOW,
                                                                                   actions=[
                                                                                       'logs:CreateLogStream',
                                                                                       'logs:PutLogEvents',
                                                                                   ],
                                                                                   resources=[
                                                                                       ''.join([
                                                                                           'arn:aws:logs:',
                                                                                           self.region,
                                                                                           ':',
                                                                                           self.account,
                                                                                           ':log-group:/aws/lambda/apcReplicateWk:*',
                                                                                       ]),
                                                                                   ]),
                                                                           ]
                                                                       )
                                                                   )
                                                                   )

        iamRoleApcReplicateWk = iam.Role(self, 'IAMRoleApcReplicateWk',
                                         assumed_by=iam.ServicePrincipal(
                                             'lambda.amazonaws.com'),
                                         managed_policies=[
                                             iam.ManagedPolicy.from_managed_policy_name(
                                                 self, 'iamIPolicyApcCrrReplicationLambdaPolicy', iamPolicyApcCrrReplicationLambdaPolicy.managed_policy_name),
                                             iam.ManagedPolicy.from_managed_policy_name(
                                                 self, 'iamIPolicyApcCrrReplicationLambdaVPCPolicy', iamPolicyApcCrrLambdaVPCPolicy.managed_policy_name),
                                         ],
                                         path='/'
                                         )

        lambdaFunctionApcManageSetup = aws_lambda.Function(self, 'LambdaFunctionApcManageSetup',
                                                           description='APC CRR Setup Management',
                                                           function_name='apcManageSetup',
                                                           memory_size=128,
                                                           runtime=aws_lambda.Runtime.PYTHON_3_11,
                                                           code=aws_lambda.Code.from_asset(
                                                               'src/apcManageSetup/'),
                                                           handler='apcManageSetup.lambda_handler',
                                                           timeout=cdk.Duration.seconds(
                                                               30),
                                                           tracing=aws_lambda.Tracing.PASS_THROUGH,
                                                           logging_format=aws_lambda.LoggingFormat.TEXT,
                                                           log_group=logs.LogGroup.from_log_group_name(
                                                               self, 'logIGroupApcManageSetup', logGroupApcManageSetup.log_group_name),
                                                           role=iam.Role.from_role_name(
                                                               self, 'IAMIRoleApcManageSetup', iamRoleApcManageSetup.role_name),
                                                           retry_attempts=0,
                                                           environment={
                                                               'ORIGIN_REGION': self.region,
                                                               'AWS_ACCOUNT': self.account,
                                                               'ORIGIN_VPC_CIDR': origin_vpc_cidr,
                                                               'ORIGIN_VPC_ID': originVpc.vpc_id,
                                                               'ROLE_ARN': iamRoleApcSetupOrchestrator.role_arn,
                                                               'DYNAMODB_TABLE_APC_CRR': dynamoDbTableApcCrr.table_name,
                                                               'DYNAMODB_TABLE_APC_CRR_STACK': dynamoDbTableApcCrrStack.table_name,
                                                               'TEMPLATE_URL': s3BucketCfnTemplates.url_for_object('ApcCrrOrchestrator.yaml'),
                                                           }
                                                           )

        lambdaFunctionApcStackMonitor = aws_lambda.Function(self, 'LambdaFunctionApcStackMonitor',
                                                            description='APC CRR Lambda function that Monitors Stack Deployment',
                                                            function_name='apcStackMonitor',
                                                            memory_size=128,
                                                            runtime=aws_lambda.Runtime.PYTHON_3_11,
                                                            code=aws_lambda.Code.from_asset(
                                                                'src/apcStackMonitor/'),
                                                            handler='apcStackMonitor.lambda_handler',
                                                            timeout=cdk.Duration.seconds(
                                                                600),
                                                            tracing=aws_lambda.Tracing.PASS_THROUGH,
                                                            logging_format=aws_lambda.LoggingFormat.TEXT,
                                                            log_group=logs.LogGroup.from_log_group_name(
                                                                self, 'logIGroupApcStackMonitor', logGroupApcStackMonitor.log_group_name),
                                                            role=iam.Role.from_role_name(
                                                                self, 'IAMIRoleApcStackMonitor', iamRoleApcStackMonitor.role_name),
                                                            retry_attempts=0,
                                                            environment={
                                                                'DYNAMODB_TABLE_APC_CRR_STACK': dynamoDbTableApcCrrStack.table_name,
                                                                'DYNAMODB_TABLE_APC_CRR': dynamoDbTableApcCrr.table_name,
                                                                'ORIGIN_VPC_ID': originVpc.vpc_id,
                                                                'ORIGIN_SUBNETS_PREFIX_NAME': origin_subnets_prefix_name,
                                                                'APC_VPC_ENDPOINT_SG_ID': apcVpcEndpointSG.security_group_id,
                                                                'AWS_ACCOUNT': self.account,
                                                            }
                                                            )

        lambdaFunctionApcKekSetup = aws_lambda.Function(self, 'LambdaFunctionApcKekSetup',
                                                        description='APC CRR Management',
                                                        function_name='apcKekSetup',
                                                        memory_size=3008,
                                                        runtime=aws_lambda.Runtime.PYTHON_3_11,
                                                        code=aws_lambda.Code.from_asset(
                                                            'src/apcKekSetup/'),
                                                        handler='apcKekSetup.lambda_handler',
                                                        timeout=cdk.Duration.seconds(
                                                            30),
                                                        tracing=aws_lambda.Tracing.PASS_THROUGH,
                                                        logging_format=aws_lambda.LoggingFormat.TEXT,
                                                        log_group=logs.LogGroup.from_log_group_name(
                                                            self, 'logIGroupApcKekSetup', logGroupApcKekSetup.log_group_name),
                                                        role=iam.Role.from_role_name(
                                                            self, 'IAMIRoleApcKekSetup', iamRoleApcKekSetup.role_name),
                                                        vpc=originVpc,
                                                        vpc_subnets=ec2.SubnetSelection(
                                                            subnet_type=ec2.SubnetType.PRIVATE_ISOLATED),
                                                        security_groups=[
                                                            apcVpcEndpointSG],
                                                        retry_attempts=0,
                                                        environment={
                                                            'DYNAMODB_TABLE_APC_CRR': dynamoDbTableApcCrr.table_name,
                                                            'LOG_GROUP_CT_LOGS': logsLogGroupCTlogs.log_group_name,
                                                        }
                                                        )

        lambdaFunctionApcReplicateWk = aws_lambda.Function(self, 'LambdaFunctionApcReplicateWk',
                                                           description='Code responsible for replicating Working Keys between two AWS regions',
                                                           function_name='apcReplicateWk',
                                                           runtime=aws_lambda.Runtime.PYTHON_3_11,
                                                           tracing=aws_lambda.Tracing.PASS_THROUGH,
                                                           handler='apcReplicateWk.lambda_handler',
                                                           timeout=cdk.Duration.seconds(
                                                            15),
                                                           code=aws_lambda.Code.from_asset(
                                                               'src/apcReplicateWk/'),
                                                           log_group=logs.LogGroup.from_log_group_name(
                                                               self, 'logIGroupApcReplicateWk', logGroupApcReplicateWk.log_group_name),
                                                           role=iam.Role.from_role_name(
                                                               self, 'IAMIRoleApcReplicateWk', iamRoleApcReplicateWk.role_name),
                                                           vpc=originVpc,
                                                           vpc_subnets=ec2.SubnetSelection(
                                                               subnet_type=ec2.SubnetType.PRIVATE_ISOLATED),
                                                           security_groups=[
                                                               apcVpcEndpointSG],
                                                           retry_attempts=0,
                                                           environment={
                                                               'REGION': self.region,
                                                               'AWS_ACCOUNT': self.account,
                                                               'DYNAMODB_TABLE_APC_CRR': dynamoDbTableApcCrr.table_name,
                                                               'DYNAMODB_TABLE_APC_CRR_REPLICATE': dynamoDbTableApcCrrMapping.table_name,
                                                           }
                                                           )

        lambdaFunctionApcReplicateWk.add_permission('LambdaPermissionApcReplicateWk',
                                                    action='lambda:InvokeFunction',
                                                    principal=iam.ServicePrincipal(
                                                        'logs.amazonaws.com'),
                                                    source_account=self.account,
                                                    source_arn=logsLogGroupCTlogs.log_group_arn
                                                    )

        lambdaFunctionApcStackMonitor.add_event_source(lambda_event_sources.DynamoEventSource(
            dynamoDbTableApcCrrStack, starting_position=aws_lambda.StartingPosition.LATEST, batch_size=1, retry_attempts=0, filters=[aws_lambda.FilterCriteria.filter({'eventName': aws_lambda.FilterRule.is_equal('INSERT')})]))

        lambdaFunctionApcStackMonitor.add_event_source(lambda_event_sources.DynamoEventSource(
            dynamoDbTableApcCrr, starting_position=aws_lambda.StartingPosition.LATEST, batch_size=1, retry_attempts=0, filters=[aws_lambda.FilterCriteria.filter({'eventName': aws_lambda.FilterRule.is_equal('MODIFY')})]))

        lambdaFunctionApcKekSetup.add_event_source(lambda_event_sources.DynamoEventSource(
            dynamoDbTableApcCrr, starting_position=aws_lambda.StartingPosition.LATEST, batch_size=1, retry_attempts=0, filters=[aws_lambda.FilterCriteria.filter({'eventName': aws_lambda.FilterRule.is_equal('MODIFY')})]))

        ctTrailmanagementevents = cloudtrail.Trail(self, 'CTTrailmanagementevents',
                                                   include_global_service_events=True,
                                                   trail_name='management-events',
                                                   is_multi_region_trail=True,
                                                   enable_file_validation=True,
                                                   bucket=s3.Bucket.from_bucket_name(
                                                       self, 's3IBucketCTLogs', s3BucketCtLogs.bucket_name),
                                                   send_to_cloud_watch_logs=True,
                                                   cloud_watch_log_group=logs.LogGroup.from_log_group_name(
                                                       self, 'logsILogGroupCTlogs', logsLogGroupCTlogs.log_group_name),
                                                   management_events=cloudtrail.ReadWriteType.WRITE_ONLY
                                                   )