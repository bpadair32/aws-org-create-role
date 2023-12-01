##############################################################
# AWS-ORG-CREATE-ROLE                                        #
# This is used to create a role across all of the accounts   #
# in an AWS organization. It defaults to granting read only  #
# access via the AWS Read Only managed policy                #
##############################################################
#!/usr/bin/env python3
import boto3
import botocore.exceptions
import json
import argparse

## getAccounts() - Function to get a listing of all of the accounts associated with the organization
def getAccounts(token: str = "", maxResults: int = 20) -> list:
    orgClient = boto3.client('organizations')
    accounts = []
    if token != "": # Check to see if we have already gotten a result with a NextToken in it
        try:
            response = orgClient.list_accounts(NextToken = token, MaxResults = maxResults)
        except botocore.exceptions.ClientError as error:
            print(f"Failed to get account list due to error: {error}")
            exit(1) # We can't do anything without an account list, so if there is a problem, we exit
        accounts.append(response['Accounts'])
        if 'NextToken' in response:
            next = response['NextToken']
            getAccounts(token = next) # If there is a NextToken, there are more accounts to get so call this function again
        else:
            try:
                response = orgClient.list_accounts(MaxResults = maxResults) # The api returns an error if you pass a blank NextToken, so call without it if we dont have one yet.
            except botocore.exceptions.ClientError as error:
                print(f"Failed to get account list due to error: {error}")
                exit(1) # We can't do anyhting without an account list, so if there is a problem, we exit
            accounts.append(response['Accounts'])
            if 'NextToken' in response:
                next = response['NextToken']
                getAccounts(token = next) # If there is a NextToken, there are more accounts to get, so call this function again
    return accounts

# createPolicyDoc() - Function to create the Trust Policy document required by the role creation process. Basically just a template
def createPolicyDoc(accountNum: str) -> str:
    assume_role_doc = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "AWS": f"arn:aws:iam::{accountNum}:root"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    })

    return assume_role_doc

# createRole() - Function to create the role in each account. We need to pass in the account information as the looping is external to this function
def createRole(policyDoc: str = "arn:aws:iam::aws:policy/ReadOnly", account: str, name: str, id: str, key: str, sess: str) -> bool:
    iamClient = boto3.client('iam', region_name="us-east-1", aws_access_key_id=id, aws_secret_access_key=key, aws_session_token=sess)
    try:
        response = iamClient.create_role(AssumeRolePolicyDocument = policyDoc, Path = "/", RoleName = name)
    except botocore.exceptions.ClientError as error:
        print(f"Unable to create role in account: {account} due to {error}")
        return False # Just because this account failed, others may succeed, so just return false instead of exiting
    return True

# attachPolicy() - Function to attach the appropriate policy to the newly-created role
def attachPolicy(role: str, policy: str, id: str, key: str, sess: str) -> bool:
    iamClient = boto3.client('iam', region_name="us-east-1", aws_access_key_id=id, aws_secret_access_key=key, aws_session_token=sess)
    try:
        response = iamClient.attach_role_policy(PolicyArn=policy, RoleName=role)
    except botocore.exceptions.ClientError as error:
        print(f"Unable to attach policy: {policy} to role: {role} due to: {error}")
        return False # Other atttachments may succeed so return false and keep going
    return True

def main() -> None:
    parser = argparse.ArgumentParser(description="Create a role that can be assumed by an outside entity")
    parser.add_argument('extAccount', type=str)
    parser.add_argument('roleName', type=str)
    args = parser.parse_args()
    extAccount = args.extAccount
    roleName = args.roleName

    accounts = getAccounts()
    policyDoc = createPolicyDoc(extAccount)
    for a in accounts:
        for account in a: # We created a list of lists in getAccounts, so we need to double-loop
            accountId = account["Id"]
            stsClient = boto3.client('sts')
            try: # We need to assume a role in each account and perform the role creation and policy attachment there
                response = stsClient.assume_role(RoleArn=f"arn:aws:iam::{accountId}:role/terraform", RoleSessionName="boto")
                session_id = response["Credentials"]["AccessKeyId"]
                session_key = response["Credentials"]["SecretAccessKey"]
                session_token = response["Credentials"]["SessionToken"]
                result = createRole(policyDoc, extAccount, roleName, session_id, session_key, session_token)
                if result == True: 
                    print(f"Role {roleName} created successfully in account {account}")
                policyResult = attachPolicy(role=roleName, policy="arn:aws:iam::aws:policy/ReadOnlyAccess", id=session_id, key=session_key, sess=session_token)
            except botocore.exceptions.ClientError as error:
                print(f"Unable to assume role in {account}, please confirm that the role exists")
                continue # We may still be able to assume the role in other accounts, so let's keep going

if __name__ == "__main__":
    main()

