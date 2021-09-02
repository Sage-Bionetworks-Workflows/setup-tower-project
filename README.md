# Setup Tower Projects

The [`setup-tower-project.py`](setup-tower-project.py) script in this repository is intended to be use in conjunction with the [tower-project.yaml](https://github.com/Sage-Bionetworks-Workflows/aws-workflows-nextflow-infra/blob/main/templates/tower-project.yaml) template in [`aws-workflows-nextflow-infra`](https://github.com/Sage-Bionetworks-Workflows/aws-workflows-nextflow-infra). A Docker image is provided to minimize the burden of installing software dependencies.

## Getting Started

Assuming that you have already exported the relevant enviroment variables, you can run the following command to set up a project in Nextflow Tower:

```
docker run -e STACK_NAME -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_SESSION_TOKEN -e NXF_TOWER_TOKEN -e SYNAPSE_TOKEN -v "$HOME/.aws:/root/.aws" setup-tower-project
```

This command will output the following JSON configuration, which includes important details on the Tower project. You won't need most of it when using the project with the exception for the `bucket_name` for staging data and retrieving output files. Consider redirecting the output to a file for later reference; re-running the command will reproduce the output.

```
{
    "bucket_name": "...",
    "comp_env_id": "...",
    "forge_access_key_id": "...",
    "forge_head_role_arn": "...",
    "forge_secret_access_key": "...",
    "forge_service_role_arn": "...",
    "forge_work_role_arn": "...",
    "read_only_arns": "...",
    "read_write_arns": "...",
    "subnet_ids": "...",
    "vpc_id": "..."
}
```

## Docker Image

Here's how you build and publish a Docker image that contains the script:

```
# Using the 'dev' tag to avoid using the 'latest' tag
docker build -t sagebionetworks/setup-tower-project:dev .
docker push sagebionetworks/setup-tower-project:dev
```
