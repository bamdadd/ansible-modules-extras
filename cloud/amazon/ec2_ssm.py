#!/usr/bin/python

# 'ec2_ecr'.
import botocore

DOCUMENTATION = '''
---
module: ec2_ssm
short_description: Amazon Simple System Manager
description:
    - Amazon Simple System Manager (SSM)
version_added: 2.1
options:
  instanceids:
    description:
      - The instance IDs where the command should execute. if not specified will execute the command on all the SSM instances
    required: false
  documentname:
    description:
      - The name of the SSM document to execute. This can be an SSM public document or a custom document.
    required: true
  parameters:
    description:
      - The required and optional parameters specified in the SSM document being executed.
    required: true
  comment:
    description:
      - User-specified information about the command, such as a brief description of what the command should do.
    required: false
  timeoutseconds:
    description:
      -  If this time is reached and the command has not already started executing, it will not execute.
      required: false
  region:
    description:
      - region name
    required: false
  profile:
    description:
      - boto profile name
    required: false
extends_documentation_fragment: aws
'''

EXAMPLES = '''
tasks:
  - local_action:
      module: ec2_ssm
      instanceids:
        - i-086d33a7e36e36a9c
        - i-0221eacb8d88ea0a3
      documentname:  "AWS-RunShellScript"
      timeoutseconds: 600
      comment:  Test SSM send command to specific instances
      parameters:
          commands:
            - "docker "
          executionTimeout:
            - "3600"
      profile: nonprod
      region: eu-west-1

  - local_action:
      module: ec2_ssm
      documentname:  "AWS-RunShellScript"
      timeoutseconds: 600
      comment: Test SSM send command to all ssm instances
      parameters:
          commands:
            - "docker "
          executionTimeout:
            - "3600"
      profile: nonprod
      region: eu-west-1

'''

try:
  import boto3
except ImportError:
  print "failed=True msg='boto 3required for this module'"
  sys.exit(1)


def get_aws_connection_info(module, boto3=False):
  # Check module args for credentials, then check environment vars
  # access_key

  ec2_url = module.params.get('ec2_url')
  access_key = module.params.get('aws_access_key')
  secret_key = module.params.get('aws_secret_key')
  security_token = module.params.get('security_token')
  region = module.params.get('region')
  profile_name = module.params.get('profile')
  validate_certs = module.params.get('validate_certs')

  if not ec2_url:
    if 'AWS_URL' in os.environ:
      ec2_url = os.environ['AWS_URL']
    elif 'EC2_URL' in os.environ:
      ec2_url = os.environ['EC2_URL']

  if not access_key:
    if 'AWS_ACCESS_KEY_ID' in os.environ:
      access_key = os.environ['AWS_ACCESS_KEY_ID']
    elif 'AWS_ACCESS_KEY' in os.environ:
      access_key = os.environ['AWS_ACCESS_KEY']
    elif 'EC2_ACCESS_KEY' in os.environ:
      access_key = os.environ['EC2_ACCESS_KEY']
    else:
      # in case access_key came in as empty string
      access_key = None

  if not secret_key:
    if 'AWS_SECRET_ACCESS_KEY' in os.environ:
      secret_key = os.environ['AWS_SECRET_ACCESS_KEY']
    elif 'AWS_SECRET_KEY' in os.environ:
      secret_key = os.environ['AWS_SECRET_KEY']
    elif 'EC2_SECRET_KEY' in os.environ:
      secret_key = os.environ['EC2_SECRET_KEY']
    else:
      # in case secret_key came in as empty string
      secret_key = None

  if not region:
    if 'AWS_REGION' in os.environ:
      region = os.environ['AWS_REGION']
    elif 'AWS_DEFAULT_REGION' in os.environ:
      region = os.environ['AWS_DEFAULT_REGION']
    elif 'EC2_REGION' in os.environ:
      region = os.environ['EC2_REGION']
    else:
      # boto.config.get returns None if config not found
      region = boto.config.get('Boto', 'aws_region')
      if not region:
        region = boto.config.get('Boto', 'ec2_region')

  if not security_token:
    if 'AWS_SECURITY_TOKEN' in os.environ:
      security_token = os.environ['AWS_SECURITY_TOKEN']
    elif 'EC2_SECURITY_TOKEN' in os.environ:
      security_token = os.environ['EC2_SECURITY_TOKEN']
    else:
      # in case security_token came in as empty string
      security_token = None

  if HAS_BOTO3 and boto3:
    boto_params = dict(aws_access_key_id=access_key,
                       aws_secret_access_key=secret_key,
                       aws_session_token=security_token)
    boto_params['verify'] = validate_certs

    if profile_name:
      boto_params['profile_name'] = profile_name

  else:
    boto_params = dict(aws_access_key_id=access_key,
                       aws_secret_access_key=secret_key,
                       security_token=security_token)

    # profile_name only works as a key in boto >= 2.24
    # so only set profile_name if passed as an argument
    if profile_name:
      if not boto_supports_profile_name():
        module.fail_json("boto does not support profile_name before 2.24")
      boto_params['profile_name'] = profile_name

    if HAS_LOOSE_VERSION and LooseVersion(boto.Version) >= LooseVersion("2.6.0"):
      boto_params['validate_certs'] = validate_certs

  return region, ec2_url, boto_params


def setup_profile(profile):
  if profile != '':
    session = botocore.session.get_session()
    session.profile = profile
    boto3.setup_default_session(botocore_session=session)


def setup_region(region):
  if region != '':
    session = botocore.session.get_session()
    session.region_name = region
    boto3.setup_default_session(botocore_session=session)


def repo_exists(ecr, name):
  try:
    describe_repo = ecr.describe_repositories(repositoryNames=[name])
  except botocore.exceptions.ClientError:
    return False
  if describe_repo['repositories'].count > 0:
    return True


def main():
  argument_spec = ec2_argument_spec()
  argument_spec.update(dict(
    instanceids=dict(required=False, type='list', default=[]),
    documentname=dict(required=True, type='str'),
    parameters=dict(required=True, type='dict'),
    timeoutseconds=dict(required=True, type='int'),
    comment=dict(required=False, type='str', default="Ansible SSM send command"),
    region=dict(required=False, type='str'),
    profile=dict(required=False, type='str'),
  )
  )
  module = AnsibleModule(argument_spec=argument_spec)

  instanceids = module.params.get('instanceids')
  documentname = module.params.get('documentname')
  parameters = module.params.get('parameters')
  comment = module.params.get('comment')
  timeoutseconds = module.params.get('timeoutseconds')

  region, ec2_url, aws_connect_kwargs = get_aws_connection_info(module, boto3=True)
  try:
    ssm = boto3_conn(module,
                     conn_type='client',
                     resource='ssm',
                     region=region,
                     endpoint=ec2_url,
                     **aws_connect_kwargs)
  except botocore.exceptions.NoRegionError:
    module.fail_json(msg="AWS Region not specified")
  if instanceids == []:
    all_instances = ssm.describe_instance_information(InstanceInformationFilterList=[{
      'key': 'PlatformTypes',
      'valueSet': [
        'Linux',
      ]
    }])
    instanceids= map(lambda instance: instance['InstanceId'], all_instances['InstanceInformationList'])
  response = ssm.send_command(InstanceIds=instanceids,
                              DocumentName=documentname,
                              TimeoutSeconds=timeoutseconds,
                              Comment=comment,
                              Parameters=parameters)
  module.exit_json(info=response)
  sys.exit(0)


# Import module snippets
from ansible.module_utils.basic import *
from ansible.module_utils.ec2 import *

main()
