#!/usr/bin/env python3

import argparse
import configparser
import json
import os

import boto3
import requests


REGION = "us-east-1"


def main():
    args = parse_args()
    sess = configure_boto_session(args)
    identity = get_caller_identity(sess)
    proj_stack = retrieve_cfn_stack(sess, args.stack_name)
    access_role_arn = get_project_role(identity, proj_stack)
    configure_aws_profiles(args, proj_stack, identity, access_role_arn)
    creds = get_forge_credentials(sess, proj_stack, identity, access_role_arn)
    creds_id = configure_forge_credentials(args, creds)
    vpc_stack = retrieve_cfn_stack(sess, "nextflow-vpc")
    configure_tower_compute_env(args, proj_stack, creds_id, vpc_stack)


def parse_args():
    # TODO: Add option to skip AWS config profile creation
    parser = argparse.ArgumentParser()
    parser.add_argument("--stack_name", default=os.environ["STACK_NAME"])
    parser.add_argument("--aws_access_key_id", default=os.environ["AWS_ACCESS_KEY_ID"])
    parser.add_argument(
        "--aws_secret_access_key", default=os.environ["AWS_SECRET_ACCESS_KEY"]
    )
    parser.add_argument("--aws_session_token", default=os.environ["AWS_SESSION_TOKEN"])
    parser.add_argument("--nextflow_tower_token", default=os.environ["NXF_TOWER_TOKEN"])
    parser.add_argument("--region", default=os.environ.get("REGION", "us-east-1"))
    # TODO: Update with production endpoint once deployed
    parser.add_argument(
        "--tower_endpoint",
        default=os.environ.get("NXF_TOWER_ENDPOINT", "https://tower.nf/api"),
    )
    args = parser.parse_args()
    return args


def configure_boto_session(args):
    available_profiles = boto3.session.Session().available_profiles
    if "tower-user" in available_profiles:
        session = boto3.session.Session(profile_name="tower-user")
    else:
        session = boto3.session.Session(
            args.aws_access_key_id,
            args.aws_secret_access_key,
            args.aws_session_token,
        )
    return session


def get_caller_identity(session):
    sts = session.client("sts")
    identity = sts.get_caller_identity()
    identity["SessionName"] = identity["Arn"].split("/")[-1]
    return identity


def retrieve_cfn_stack(session, stack_name):

    cfn = session.client("cloudformation")
    response = cfn.describe_stacks(StackName=stack_name)
    stack = response["Stacks"][0]
    stack["ParametersDict"] = {
        p["ParameterKey"]: p["ParameterValue"] for p in stack["Parameters"]
    }
    stack["OutputsDict"] = {p["OutputKey"]: p["OutputValue"] for p in stack["Outputs"]}
    return stack


def get_project_role(identity, stack):
    role_arn = identity["Arn"]
    stack_params = stack["ParametersDict"]
    read_write_arns = stack_params["ReadWriteAccessArns"].split(",")
    read_only_arns = stack_params["ReadOnlyAccessArns"].split(",")
    is_read_write_access = role_arn in read_write_arns
    is_read_only_access = role_arn in read_only_arns
    assert is_read_write_access or is_read_only_access, (
        "The current user isn't listed under 'ReadWriteAccessArns' "
        "or 'ReadOnlyAccessArns' of the given Tower project."
    )
    if is_read_write_access:
        access_role_arn = stack["OutputsDict"]["ReadWriteAccessRoleArn"]
    else:
        access_role_arn = stack["OutputsDict"]["ReadOnlyAccessRoleArn"]
    return access_role_arn


def configure_aws_profiles(args, stack, identity, access_role_arn):
    aws_config_path = os.environ.get("AWS_CONFIG_FILE", "~/.aws/config")
    aws_config_path = os.path.expanduser(aws_config_path)
    aws_config_path = os.path.normpath(aws_config_path)
    aws_config = configparser.ConfigParser()
    aws_config.read(aws_config_path)
    # Configure Tower user profile
    # TODO: Change from Viewer to TowerUser once JC role is available
    aws_config["profile tower-user"] = {
        "region": args.region,
        "output": "json",
        "sso_region": "us-east-1",
        "sso_account_id": "035458030717",
        "sso_start_url": "https://d-906769aa66.awsapps.com/start",
        "sso_role_name": "Viewer",
    }
    # Configure Tower project profile
    stack_name = stack["StackName"]
    session_name = identity["SessionName"]
    aws_config[f"profile {stack_name}"] = {
        "region": args.region,
        "output": "json",
        "source_profile": "tower-user",
        "role_arn": access_role_arn,
        "role_session_name": session_name,
    }
    with open(aws_config_path, "w") as configfile:
        aws_config.write(configfile)


def get_forge_credentials(session, stack, identity, access_role_arn):
    sts = session.client("sts")
    role_response = sts.assume_role(
        RoleArn=access_role_arn,
        RoleSessionName=identity["SessionName"],
    )
    role_creds = role_response["Credentials"]
    secretsmanager = session.client(
        "secretsmanager",
        aws_access_key_id=role_creds["AccessKeyId"],
        aws_secret_access_key=role_creds["SecretAccessKey"],
        aws_session_token=role_creds["SessionToken"],
    )
    secret_id = stack["OutputsDict"]["TowerForgeServiceUserAccessKeySecretArn"]
    secret_response = secretsmanager.get_secret_value(SecretId=secret_id)
    creds = json.loads(secret_response["SecretString"])
    return creds


def make_tower_request(type, endpoint, args, data={}):
    token = args.nextflow_tower_token
    headers = {
        "Accept": "application/json, application/json",
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    request_fn = getattr(requests, type)
    full_url = args.tower_endpoint + endpoint
    if type == "post":
        response = request_fn(full_url, json=data, headers=headers)
    else:
        response = request_fn(full_url, headers=headers)
    return response


def configure_forge_credentials(args, credentials):
    stack_name = args.stack_name
    # Check if credentials already exist for this stack
    response = make_tower_request("get", "/credentials", args)
    creds = response.json()["credentials"]
    for cred in creds:
        if cred["name"] == stack_name:
            assert cred["provider"] == "aws"
            assert cred["deleted"] is None
            return cred["id"]
    # If not, create them
    data = {
        "credentials": {
            "name": stack_name,
            "provider": "aws",
            "keys": {
                "accessKey": credentials["access_key_id"],
                "secretKey": credentials["secret_access_key"],
                "assumeRoleArn": None,
            },
            "description": f"Credentials for {stack_name} project",
        }
    }
    response = make_tower_request("post", "/credentials", args, data)
    response_data = response.json()
    creds_id = response_data["credentialsId"]
    return creds_id


def configure_tower_compute_env(args, stack, credentials_id, vpc_stack):
    stack_name = args.stack_name
    bucket_name = stack["OutputsDict"]["TowerBucket"]
    # Check if compute environment already exist for this stack
    response = make_tower_request("get", "/compute-envs", args)
    comp_envs = response.json()["computeEnvs"]
    for comp_env in comp_envs:
        if comp_env["name"] == f"{stack_name} (default)":
            assert comp_env["platform"] == "aws-batch"
            assert comp_env["status"] == "AVAILABLE" or comp_env["status"] == "CREATING"
            return comp_env["id"]
    # If not, create it
    vpc_id = vpc_stack["OutputsDict"]["VPCId"]
    subnet_ids = [
        vpc_stack["OutputsDict"]["PrivateSubnet"],
        vpc_stack["OutputsDict"]["PrivateSubnet2"],
        vpc_stack["OutputsDict"]["PrivateSubnet3"],
    ]
    data = {
        "computeEnv": {
            "name": f"{stack_name} (default)",
            "platform": "aws-batch",
            "credentialsId": credentials_id,
            "config": {
                "configMode": "Batch Forge",
                "region": args.region,
                "workDir": f"s3://{bucket_name}/work",
                "credentials": None,
                "computeJobRole": None,
                "headJobRole": None,
                "headJobCpus": None,
                "headJobMemoryMb": None,
                "preRunScript": None,
                "postRunScript": None,
                "cliPath": None,
                "forge": {
                    "vpcId": vpc_id,
                    "subnets": subnet_ids,
                    "fsxMode": "None",
                    "efsMode": "None",
                    "type": "SPOT",
                    "minCpus": 0,
                    "maxCpus": 100,
                    "gpuEnabled": False,
                    "ebsAutoScale": True,
                    "allowBuckets": [],
                    "disposeOnDeletion": True,
                    "instanceTypes": [],
                    "allocStrategy": None,
                    "ec2KeyPair": None,
                    "imageId": None,
                    "securityGroups": [],
                    "ebsBlockSize": None,
                    "fusionEnabled": False,
                    "efsCreate": False,
                    "bidPercentage": None,
                },
            },
        }
    }
    response = make_tower_request("post", "/compute-envs", args, data)
    response_data = response.json()
    comp_env_id = response_data["computeEnvId"]
    return comp_env_id


if __name__ == "__main__":
    main()
