#!/usr/bin/env python3

import argparse
import configparser
import json
import os

import boto3
import requests


# TODO: Update with production endpoint once deployed
TOWER_ENDPOINT = "https://tower-dev.sagebionetworks.org/api"


class TowerConfigurator:
    def __init__(
        self,
        stack_name,
        aws_access_key_id,
        aws_secret_access_key,
        aws_session_token,
        nextflow_tower_token,
        synapse_token,
        aws_config_path,
        region,
        tower_endpoint,
    ):
        # Store initialization variables
        self.stack_name = stack_name
        self.aws_access_key_id = aws_access_key_id
        self.aws_secret_access_key = aws_secret_access_key
        self.aws_session_token = aws_session_token
        self.nextflow_tower_token = nextflow_tower_token
        self.synapse_token = synapse_token
        self.aws_config_path = aws_config_path
        self.region = region
        self.tower_endpoint = tower_endpoint
        # Perform additional setup
        self.session = self.configure_boto_session(
            self.aws_access_key_id,
            self.aws_secret_access_key,
            self.aws_session_token,
            "sandbox",
        )
        self.get_caller_identity()
        self.configure_aws_profiles()

    def configure(self):
        config = self.retrieve_config()
        comp_env_id = self.configure_tower_compute_env(config)
        if self.caller_identity["Arn"] in config["read_write_arns"]:
            self.upload_synapse_config(config)
        config["comp_env_id"] = comp_env_id
        return config

    def configure_boto_session(
        self,
        aws_access_key_id,
        aws_secret_access_key,
        aws_session_token,
        aws_profile_name,
    ):
        available_profiles = boto3.session.Session().available_profiles
        if aws_profile_name in available_profiles:
            session = boto3.session.Session(profile_name=aws_profile_name)
        else:
            session = boto3.session.Session(
                aws_access_key_id,
                aws_secret_access_key,
                aws_session_token,
            )
        return session

    def get_caller_identity(self):
        sts = self.session.client("sts")
        self.caller_identity = sts.get_caller_identity()
        self.session_name = self.caller_identity["Arn"].split("/")[-1]
        return self.caller_identity

    def retrieve_config(self):
        secretsmanager = self.session.client("secretsmanager")
        secret_id = (
            "arn:aws:secretsmanager:us-east-1:035458030717:"
            f"secret:{self.stack_name}-TowerProjectConfiguration"
        )
        response = secretsmanager.get_secret_value(SecretId=secret_id)
        config = json.loads(response["SecretString"])
        return config

    def configure_aws_profiles(self):
        # Check if AWS CLI profiles already exist
        profiles = boto3.session.Session().available_profiles
        if "sandbox" in profiles and "tower" in profiles:
            return
        # Load AWS CLI configuration if need be
        aws_config = configparser.ConfigParser()
        aws_config.read(self.aws_config_path)
        # Add 'sandbox' profile
        if "sandbox" not in profiles:
            aws_config["profile sandbox"] = {
                "region": self.region,
                "output": "json",
                "sso_region": "us-east-1",
                "sso_account_id": "563295687221",
                "sso_start_url": "https://d-906769aa66.awsapps.com/start",
                "sso_role_name": "Developer",
            }
        # Add 'tower' profile
        if "tower" not in profiles:
            aws_config["profile tower"] = {
                "region": self.region,
                "output": "json",
                "sso_region": "us-east-1",
                "sso_account_id": "728882028485",
                "sso_start_url": "https://d-906769aa66.awsapps.com/start",
                "sso_role_name": "TowerViewer",
            }
        # Export new profiles to disk`
        with open(self.aws_config_path, "w") as configfile:
            aws_config.write(configfile)

    def make_tower_request(self, type, endpoint, data=None):
        token = args.nextflow_tower_token
        headers = {
            "Accept": "application/json, application/json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        request_fn = getattr(requests, type)
        full_url = self.tower_endpoint + endpoint
        if type == "post":
            response = request_fn(full_url, json=data, headers=headers)
        else:
            response = request_fn(full_url, headers=headers)
        return response

    def configure_forge_credentials(self, config):
        # Check if credentials already exist for this stack
        response = self.make_tower_request("get", "/credentials")
        creds = response.json()["credentials"]
        for cred in creds:
            if cred["name"] == self.stack_name:
                assert cred["provider"] == "aws"
                assert cred["deleted"] is None
                return cred["id"]
        # If not, create them
        data = {
            "credentials": {
                "name": self.stack_name,
                "provider": "aws",
                "keys": {
                    "accessKey": config["forge_access_key_id"],
                    "secretKey": config["forge_secret_access_key"],
                    "assumeRoleArn": config["forge_service_role_arn"],
                },
                "description": f"Credentials for {self.stack_name} project",
            }
        }
        response = self.make_tower_request("post", "/credentials", data)
        response_data = response.json()
        creds_id = response_data["credentialsId"]
        return creds_id

    def configure_tower_compute_env(self, config):
        bucket_name = config["bucket_name"]
        # Check if compute environment already exist for this stack
        response = self.make_tower_request("get", "/compute-envs")
        comp_envs = response.json()["computeEnvs"]
        for comp_env in comp_envs:
            if (
                comp_env["name"] == f"{args.stack_name} (default)"
                and comp_env["platform"] == "aws-batch"
                and (
                    comp_env["status"] == "AVAILABLE"
                    or comp_env["status"] == "CREATING"
                )
            ):
                return comp_env["id"]
        # If not, create it
        creds_id = self.configure_forge_credentials(config)
        data = {
            "computeEnv": {
                "name": f"{args.stack_name} (default)",
                "platform": "aws-batch",
                "credentialsId": creds_id,
                "config": {
                    "configMode": "Batch Forge",
                    "region": args.region,
                    "workDir": f"s3://{bucket_name}/work",
                    "credentials": None,
                    "computeJobRole": config["forge_work_role_arn"],
                    "headJobRole": config["forge_head_role_arn"],
                    "headJobCpus": None,
                    "headJobMemoryMb": None,
                    "preRunScript": None,
                    "postRunScript": None,
                    "cliPath": None,
                    "forge": {
                        "vpcId": config["vpc_id"],
                        "subnets": config["subnet_ids"].split(","),
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
        response = self.make_tower_request("post", "/compute-envs", data)
        response_data = response.json()
        comp_env_id = response_data["computeEnvId"]
        return comp_env_id

    def upload_synapse_config(self, config):
        bucket_name = config["bucket_name"]
        synapse_config = f"[authentication]\nauthtoken = {self.synapse_token}\n"
        synapse_config = bytes(synapse_config, "utf-8")
        s3 = self.session.client("s3")
        response = s3.put_object(
            Body=synapse_config,
            Bucket=bucket_name,
            Key="synapse-config/synapseConfig",
            ACL="bucket-owner-full-control",
        )
        return response


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
    parser.add_argument("--synapse_token", default=os.environ["SYNAPSE_TOKEN"])
    parser.add_argument(
        "--aws_config_path", default=os.environ.get("AWS_CONFIG_FILE", "~/.aws/config")
    )
    parser.add_argument("--region", default=os.environ.get("REGION", "us-east-1"))
    parser.add_argument(
        "--tower_endpoint",
        default=os.environ.get("NXF_TOWER_ENDPOINT", TOWER_ENDPOINT),
    )
    args = parser.parse_args()
    args.aws_config_path = os.path.expanduser(args.aws_config_path)
    args.aws_config_path = os.path.normpath(args.aws_config_path)
    return args


def store_config(config, args):
    aws_config_dir = os.path.dirname(args.aws_config_path)
    output_dir = os.path.join(aws_config_dir, "tower-projects")
    output_path = os.path.join(output_dir, f"{args.stack_name}.json")
    prompt = f"\nSave configuration in '{output_path}'?\n[y]/n > "
    response = input(prompt)
    if response.lower().strip() in {"", "y", "yes", "true"}:
        print("Saving...")
        os.makedirs(output_dir, exist_ok=True)
        with open(output_path, "w") as outfile:
            if not isinstance(config, str):
                config = json.dumps(config, sort_keys=True, indent=4)
            outfile.write(config)
    else:
        print("Skipping...")


if __name__ == "__main__":
    args = parse_args()
    tower = TowerConfigurator(**vars(args))
    config = tower.configure()
    config_json = json.dumps(config, sort_keys=True, indent=4)
    # store_config(config_json, args)
    print(config_json)
