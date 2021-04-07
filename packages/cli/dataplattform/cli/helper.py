from pathlib import Path
import os
from subprocess import run
from json import loads, dumps
import boto3
import botocore
from datetime import datetime
from contextlib import contextmanager
from time import sleep


def cloudformation_exports(client=None):
    client = client or boto3.client('cloudformation')
    exports = client.list_exports()['Exports']
    return {x['Name']: x['Value'] for x in exports}


def find_file(filename):
    if Path(os.path.join(os.path.dirname(__file__), filename)).exists():
        return os.path.join(os.path.dirname(__file__), filename)
    elif Path(os.path.join(os.getcwd(), filename)).exists():
        return os.path.join(os.getcwd(), filename)
    else:
        return filename


def load_serverless_config(path, serverless_cli=None, serverless_file=None):
    serverless_cli = serverless_cli or 'serverless'
    serverless_file = os.path.relpath(serverless_file or find_file('serverless.yml'))

    p = run([
        serverless_cli, 'print', '--path', path, '--format', 'json', '--config', serverless_file],
        check=True, capture_output=True, shell=os.name != 'posix', encoding='utf-8')

    return loads(p.stdout)


def serverless_environment(serverless_cli=None, serverless_file=None, serverless_config=None):
    config = serverless_config or load_serverless_config(
        'functions',
        serverless_cli=serverless_cli,
        serverless_file=serverless_file)

    return resovle_cloudformation_imports(next(iter(config.values()))['environment'])


def resovle_cloudformation_imports(environment, exports=None):
    exports = exports or cloudformation_exports()

    def resolve_imports(value):
        if 'Fn::ImportValue' not in value:
            return value
        return exports[value['Fn::ImportValue']]

    return {k: resolve_imports(v) for k, v in environment.items()}


def load_serverless_environment(serverless_cli=None, serverless_file=None, verbose=True):
    env = serverless_environment(serverless_cli, serverless_file)
    for k, v in env.items():
        if verbose:
            print(f'ENVIRONMENT {k}: {v}')
        os.environ[k] = v


@contextmanager
def assume_serverless_role2(serverless_cli=None, serverless_file=None):
    config = load_serverless_config('resources.Resources',
                                    serverless_cli=serverless_cli,
                                    serverless_file=serverless_file)
    config = next(iter([c for c in config.values() if c['Type'] == 'AWS::IAM::Role']))

    client = boto3.client('iam')

    try:
        me = client.get_user()['User']
        role_name = f'LOCAL-{me["UserName"]}-{config["Properties"]["RoleName"]}'

        role = client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=dumps({
                'Version': '2012-10-17',
                'Statement': [{
                    'Effect': 'Allow',
                    'Principal': {
                        'AWS': me['Arn']
                    },
                    'Action': 'sts:AssumeRole'
                }]
            }))['Role']
        role_arn = role['Arn']
    except Exception:
        raise f'Failed to find {config["Properties"]["RoleName"]}, maybe its not deployed?'

    base_session = boto3._get_default_session()._session
    fetcher = botocore.credentials.AssumeRoleCredentialFetcher(
        client_creator=base_session.create_client,
        source_credentials=base_session.get_credentials(),
        role_arn=role_arn)
    creds = botocore.credentials.DeferredRefreshableCredentials(
        method='assume-role',
        refresh_using=fetcher.fetch_credentials,
        time_fetcher=lambda: datetime.datetime.now()
    )
    botocore_session = botocore.session.Session()
    botocore_session._credentials = creds

    boto3.setup_default_session(botocore_session=botocore_session)
    print(f'Assume role "{config["Properties"]["RoleName"]}"')
    try:
        yield
    except Exception:
        import traceback
        print(traceback.format_exc())
    finally:
        boto3.setup_default_session(botocore_session=base_session)
        client.delete_role(RoleName=role_name)


@contextmanager
def assume_serverless_role(serverless_cli=None, serverless_file=None):
    config = load_serverless_config(
        'resources.Resources',
        serverless_cli=serverless_cli,
        serverless_file=serverless_file)
    config = next(iter([c for c in config.values() if c['Type'] == 'AWS::IAM::Role']))
    base_session = boto3._get_default_session()._session
    localrole = None

    try:
        localrole = _create_local_role(config)
        creds = _assume_role(localrole)
        _setup_default_session(creds)
        print(f'Assume role "{config["Properties"]["RoleName"]}"')

        # Return to context
        yield
    except Exception:
        import traceback
        print(traceback.format_exc())
    finally:
        boto3.setup_default_session(botocore_session=base_session)
        if localrole:
            _delete_role(localrole)


def _create_local_role(config):
    iam = boto3.client('iam')
    me = iam.get_user()['User']

    role_name = f'LOCAL-{me["UserName"]}-{config["Properties"]["RoleName"]}'

    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=dumps({
            'Version': '2012-10-17',
            'Statement': [{
                'Effect': 'Allow',
                'Principal': {
                    'AWS': me['Arn']
                },
                'Action': 'sts:AssumeRole'
            }]
        }))['Role']

    for policyArn in config['Properties']['ManagedPolicyArns']:
        iam.attach_role_policy(
            RoleName=role['RoleName'],
            PolicyArn=policyArn)

    for inlinePolicy in config['Properties']['Policies']:
        policyName = f"LOCAL-{me['UserName']}-{inlinePolicy['PolicyName']}"
        iam.put_role_policy(
            RoleName=role['RoleName'],
            PolicyName=policyName,
            PolicyDocument=dumps(inlinePolicy['PolicyDocument']))

    return role


def _assume_role(role, timeout=2.0, retries=3):
    attempts = 0
    creds = None
    sts = boto3.client('sts')

    while not creds:
        try:
            creds = sts.assume_role(
                RoleArn=role['Arn'],
                RoleSessionname=f"{role['RoleName']}-SESSION")['Credentials']
        except Exception as e:
            if attempts < retries:
                print("Could not assume role, backing off and retrying")
                attempts += 1
                sleep(timeout * attempts**2)
            else:
                raise e

    return creds


def _setup_default_session(creds):
    return boto3.setup_default_session(
        aws_access_key_id=creds['AccessKeyId'],
        aws_secret_access_key=creds['SecretAccessKey'],
        aws_session_token=creds['SessionToken'])


def _delete_role(role, config):
    iam = boto3.client('iam')

    for policyArn in config['Properties']['ManagedPolicyArns']:
        iam.detach_role_policy(
            RoleName=role['RoleName'],
            PolicyArn=policyArn)

    iam.delete_role(RoleName=role['RoleName'])


@contextmanager
def assume_serverless_role3(role: str, serverless_cli=None, serverless_file=None):
    config = load_serverless_config(
        # f'resources.Resources.{role}',
        "resources",
        serverless_cli=serverless_cli,
        serverless_file=serverless_file)
    # base_session = boto3._get_default_session()._session
    # localrole = None
    stackname = None
    try:
        stackname = _deploy_as_cloudformation(config)
    except Exception:
        import traceback
        print(traceback.format_exc())
    finally:
        _remove_cloudformation(stackname)


def _deploy_as_cloudformation(config) -> str:
    cf = boto3.client('cloudformation')
    iam = boto3.client('iam')
    me = iam.get_user()['User']
    # role_name = f'LOCAL-{me["UserName"]}-{config["Properties"]["RoleName"]}'
    stackname = f'LOCAL-{me["UserName"]}-Stack'

    print(f"Creating temporary stack {stackname}")
    print(dumps(config))
    print(dumps(cf.get_template_summary(TemplateBody=dumps(config))))
    cf.create_stack(
        StackName=stackname,
        TemplateBody=dumps(config))

    def check_stack_progress() -> bool:
        stacks = cf.describe_stacks(StackName=stackname)['Stacks']
        if "FAILED" in stacks[0]['StackStatus']:
            raise f"Failed to create temporary stack {stackname}"
        elif stacks[0]['StackStatus'] == "CREATE_COMPLETE":
            return True
        else:
            return False

    print("Checking deploy progress")
    while not check_stack_progress():
        print(".", end="")
        sleep(1)
    print("\nDeploy Complete")

    return stackname


def _remove_cloudformation(stackname) -> None:
    cf = boto3.client('cloudformation')
    print(f"Deleting temporary stack {stackname}")
    cf.delete_stack(StackName=stackname)

    def check_stack_progress() -> bool:
        stacks = cf.describe_stacks(StackName=stackname)['Stacks']
        if not stacks:
            return True
        elif "FAILED" in stacks[0]['StackStatus']:
            raise f"Failed to delete temporary stack {stackname}"
        else:
            return False

    print("checking stack delete progress")
    while check_stack_progress():
        print(".", end="")
        sleep(1)
    print("\nDelete complete")
