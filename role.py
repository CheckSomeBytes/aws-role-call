import boto3
import botocore
import re
import yaml
import requests
import os
from configparser import ConfigParser
import argparse


AWS_CONFIG_FILE = os.path.expanduser("~/.aws/credentials")
GITHUB_YAML_URL = "https://raw.githubusercontent.com/fwdcloudsec/known_aws_accounts/main/accounts.yaml"


parser = argparse.ArgumentParser(description="AWS IAM Role Trust Policy Auditor")
parser.add_argument('--profile', help="AWS CLI profile name")
parser.add_argument('-V', '--superVerbose',  action='store_true', help="moreVerbose")
parser.add_argument('-v', '--verbose',  action='store_true', help="verbose")
parser.add_argument('-f', '--custom-file', help="Path to custom YAML file with known accounts")
args = parser.parse_args()
verbose = False
superVerbose = False
verbose = args.verbose
superVerbose = args.superVerbose

def v(printString, printValue):
    if verbose or superVerbose:
        print (str(printString)+": "+str(printValue))

def vv(printString, printValue):
    if superVerbose:
        print (str(printString)+": "+str(printValue))

def create_profile(profile_name, access_key, secret_key):
    config = ConfigParser()
    config.read(AWS_CONFIG_FILE)

    if not config.has_section(profile_name):
        config.add_section(profile_name)

    config.set(profile_name, 'aws_access_key_id', access_key)
    config.set(profile_name, 'aws_secret_access_key', secret_key)

    with open(AWS_CONFIG_FILE, 'w') as configfile:
        config.write(configfile)

    print(f"Created profile '{profile_name}'")

def get_iam_client(profile_name=None):
    if profile_name:
        session = boto3.Session(profile_name=profile_name)
    else:
        choice = input("No profile specified. Do you want to enter AWS credentials to create one? (y/n): ")
        if choice.lower() == 'y':
            profile_name = input("Enter new profile name: ")
            access_key = input("Enter AWS Access Key ID: ")
            secret_key = input("Enter AWS Secret Access Key: ")
            create_profile(profile_name, access_key, secret_key)
            session = boto3.Session(profile_name=profile_name)
        else:
            raise Exception("AWS credentials required. Exiting.")
    return session.client('iam')

def list_roles(iam_client):
    roles = []
    marker = None
    while True:
        if marker:
            response = iam_client.list_roles(Marker=marker)
        else:
            response = iam_client.list_roles()

        roles.extend(response['Roles'])

        if response.get('IsTruncated'):
            marker = response['Marker']
        else:
            break
    vv("roles", roles)
    return roles


def extract_account_ids_from_trust_policies(roles):
    account_to_roles = {}
    account_id_regex = re.compile(r'arn:aws:iam::(\d{12}):root')
    for role in roles:
        role_name = role['RoleName']
        trust_policy = role.get('AssumeRolePolicyDocument', {})
        statements = trust_policy.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]
        for stmt in statements:
            principal = stmt.get('Principal', {})
            aws_principals = principal.get('AWS', [])
            if isinstance(aws_principals, str):
                aws_principals = [aws_principals]
            for principal_arn in aws_principals:
                match = account_id_regex.search(principal_arn)
                if match:
                    account_id = match.group(1)
                    account_to_roles.setdefault(account_id, []).append(role_name)
    return account_to_roles

def get_known_accounts():
    response = requests.get(GITHUB_YAML_URL)
    if response.status_code == 200:
        accounts_list = yaml.safe_load(response.text)
        id_to_vendor = {}
        for entry in accounts_list:
            vendor_name = entry.get('name', 'Unknown')
            for acct_id in entry.get('accounts', []):
                id_to_vendor[acct_id] = vendor_name
        return id_to_vendor
    else:
        raise Exception("Failed to fetch known AWS accounts from GitHub")

def load_custom_accounts(filepath):
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"Custom file not found: {filepath}")
    
    with open(filepath, 'r') as f:
        accounts_list = yaml.safe_load(f)
    
    id_to_vendor = {}
    for entry in accounts_list:
        vendor_name = entry.get('name', 'Unknown')
        for acct_id in entry.get('accounts', []):
            id_to_vendor[acct_id] = vendor_name
    return id_to_vendor

def resolve_vendor(account_id, known_accounts):
    return known_accounts.get(account_id, "Unknown")

def present_results(account_to_roles, known_accounts):
    for account_id, roles in account_to_roles.items():
        vendor = resolve_vendor(account_id, known_accounts)
        print(f"{account_id} - {vendor}")
        for role in roles:
            print(f"- {role}")
        print()

def main():


    iam_client = get_iam_client(args.profile)
    roles = list_roles(iam_client)
    account_to_roles = extract_account_ids_from_trust_policies(roles)
    known_accounts = get_known_accounts()
    if args.custom_file:
        custom_accounts = load_custom_accounts(args.custom_file)
        for acct_id, vendor in custom_accounts.items():
            if acct_id not in known_accounts:
                known_accounts[acct_id] = vendor
    present_results(account_to_roles, known_accounts)

if __name__ == "__main__":
    main()
