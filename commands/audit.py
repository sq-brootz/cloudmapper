import json
import os.path
import ssl
from datetime import datetime
import urllib
import pyjq
import traceback
import sys

from policyuniverse.policy import Policy

from shared.common import parse_arguments, query_aws, get_parameter_file, get_regions
from shared.nodes import Account, Region
from tabulate import tabulate


__description__ = "Identify potential issues such as public S3 buckets"


def audit_s3_buckets(region):
    buckets_json = query_aws(region.account, "s3-list-buckets", region)
    buckets = pyjq.all('.Buckets[].Name', buckets_json)
    public_buckets = []
    private_buckets = []
    bucket_policy_errors = []
    bucket_acl_errors = []

    for bucket in buckets:
        # Check policy
        try:
            policy_file_json = get_parameter_file(region, 's3', 'get-bucket-policy', bucket)
            if policy_file_json is not None:
                # Find the entity we need
                policy_string = policy_file_json['Policy']
                # Load the string value as json
                policy = json.loads(policy_string)
                policy = Policy(policy)
                if policy.is_internet_accessible():
                    public_buckets.append(bucket)
                    #if len(policy.statements) == 1 and len(policy.statements[0].actions) == 1 and 's3:GetObject' in policy.statements[0].actions:
                    #    print('- Internet accessible S3 bucket (only GetObject) {}'.format(bucket))
                    #else:
                    #    print('- Internet accessible S3 bucket {}'.format(bucket))
                else:
                    private_buckets.append(bucket)
        except Exception as e:
            bucket_policy_errors.append(bucket)
            #print('- Couldn\'t check policy of S3 bucket: {}'.format(bucket))

        # Check ACL
        try:
            file_json = get_parameter_file(region, 's3', 'get-bucket-acl', bucket)
            for grant in file_json['Grants']:
                uri = grant['Grantee'].get('URI', "")
                if (uri == 'http://acs.amazonaws.com/groups/global/AllUsers' or
                    uri == 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'):
                    print('- Public grant to S3 bucket via ACL {}: {}'.format(bucket, grant))
        except Exception as e:
            bucket_acl_errors.append(bucket)
            #print('- Couldn\'t check ACL of S3 bucket: {}'.format(bucket))
        
    # S3 Summary
    print('')
    print('*************************')
    print('*****   S3 Summary  *****')
    print('*************************')
    print('')
    print('> You have {} public buckets:'.format(len(public_buckets)))
    for pubbucket in public_buckets:
        print('\t' + pubbucket)
    print('')
    print('> You have {} private buckets'.format(len(private_buckets)))
    print('')
    if len(bucket_policy_errors) > 0:
        print('> Couldn\'t check the policy of {} bucket(s). You probably lack permissions:'.format(len(bucket_policy_errors)))
        for bucket in bucket_policy_errors:
            print('\t' + bucket)
        print('')
    if len(bucket_acl_errors) > 0:
        print('> Couldn\'t check the ACL of {} bucket(s). You probably lack permissions:'.format(len(bucket_acl_errors)))
        for bucket in bucket_acl_errors:
            print('\t' + bucket)
        print('')


def audit_s3_block_policy(region):
    caller_identity_json = query_aws(region.account, "sts-get-caller-identity", region)
    block_policy_json = get_parameter_file(region, 's3control', 'get-public-access-block', caller_identity_json['Account'])
    if block_policy_json is None:
        print('> S3 Control Access Block is not on')
    else:
        conf = block_policy_json['PublicAccessBlockConfiguration']
        if not conf['BlockPublicAcls'] or not conf['BlockPublicPolicy'] or not conf['IgnorePublicAcls'] or not conf['RestrictPublicBuckets']:
            print('- S3 Control Access Block is not blocking all access: {}'.format(block_policy_json))
    print('')


def audit_guardduty(region):
    regions_without = []
    possible_regions = 0
    for region_json in get_regions(region.account):
        region = Region(region.account, region_json)
        detector_list_json = query_aws(region.account, "guardduty-list-detectors", region)
        if not detector_list_json:
            # GuardDuty must not exist in this region (or the collect data is old)
            continue
        possible_regions += 1
        is_enabled = False
        for detector in detector_list_json['DetectorIds']:
            detector_json = get_parameter_file(region, 'guardduty', 'get-detector', detector)
            if detector_json['Status'] == 'ENABLED':
                is_enabled = True
        if not is_enabled:
            regions_without.append(region.name)
    
    # GuardDuty Status
    print('')
    print('*************************')
    print('*** GuardDuty Status ****')
    print('*************************')
    print('')
    if len(regions_without) != 0:
        print('> GuardDuty not turned on for {}/{} regions: {}'.format(len(regions_without), possible_regions, regions_without))
        print('')
    else:
        print('> GuardDuty is enable on ALL THE THINGS!!!')
        print('')


def audit_cloudtrail(region):
    json_blob = query_aws(region.account, "cloudtrail-describe-trails", region)
    if len(json_blob['trailList']) == 0:
        print('- CloudTrail is off')
    else:
        multiregion = False
        for trail in json_blob['trailList']:
            if trail['IsMultiRegionTrail']:
                multiregion = True
                break
        if not multiregion:
            print('- CloudTrail is not multiregion')


def audit_password_policy(region):
    json_blob = query_aws(region.account, "iam-get-account-password-policy", region)
    if json_blob is None or json_blob.get('PasswordPolicy', {}) == {}:
        print('- No password policy set')
    else:
        if json_blob['PasswordPolicy'].get('MinimumPasswordLength', 0) < 12:
            print('- Password policy minimum length set to: {}'.format(json_blob['PasswordPolicy'].get('MinimumPasswordLength', 0)))

        lacking_character_requirements = []
        if not json_blob['PasswordPolicy'].get('RequireNumbers', False):
            lacking_character_requirements.append('RequireNumbers')
        if not json_blob['PasswordPolicy'].get('RequireSymbols', False):
            lacking_character_requirements.append('RequireSymbols')
        if not json_blob['PasswordPolicy'].get('RequireLowercaseCharacters', False):
            lacking_character_requirements.append('RequireLowercaseCharacters')
        if not json_blob['PasswordPolicy'].get('RequireUppercaseCharacters', False):
            lacking_character_requirements.append('RequireUppercaseCharacters')
        if len(lacking_character_requirements) > 0:
            print('- Password policy lacks: {}'.format(", ".join(lacking_character_requirements)))


def audit_root_user(region):
    json_blob = query_aws(region.account, "iam-get-account-summary", region)

    root_user_access_keys = json_blob.get('SummaryMap', {}).get('AccountAccessKeysPresent', 0)
    if root_user_access_keys != 0:
        print('- Root user has {} access keys'.format(root_user_access_keys))

    root_user_mfa = json_blob.get('SummaryMap', {}).get('AccountMFAEnabled', 0)
    if root_user_mfa != 1:
        print('- Root user has no MFA')
        
    
    # Root Account Summary
    print('*************************')
    print('****  Root Account  *****')
    print('*************************')
    print('')
    if root_user_access_keys != 0:
        print('> !!!!!!! Root user has {} access keys'.format(root_user_access_keys))
    elif root_user_mfa != 1:
        print('> !!!!!!! Root user has no MFA')
    else:
        print('> The root account is securely configured.  Hot dog!')
    print('')

def audit_users(region):
    MIN_DAYS_SINCE_LAST_USAGE = 90

    def days_between(s1, s2):
        """s1 and s2 are date strings, such as 2018-04-08T23:33:20+00:00 """
        time_format = "%Y-%m-%dT%H:%M:%S"

        d1 = datetime.strptime(s1.split("+")[0], time_format)
        d2 = datetime.strptime(s2.split("+")[0], time_format)
        return abs((d1-d2).days)

    # TODO: Convert all of this into a table

    json_blob = query_aws(region.account, "iam-get-credential-report", region)
    csv_lines = json_blob['Content'].split('\n')
    collection_date = json_blob['GeneratedTime']

    # Skip header
    csv_lines.pop(0)

    users_with_passwords = 0
    users_with_password_but_no_mfa = [] 
    active_password_accounts = []
    inactive_password_accounts = []
    inactive_key_accounts = []
    unused_password_accounts = []
    unused_key_accounts = []
    multi_key_accounts = []

    # Header:
    # user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,
    # password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,
    # access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,
    # access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,
    # access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,
    # cert_2_active,cert_2_last_rotated
    for line in csv_lines:
        parts = line.split(',')
        user = {
            'user': parts[0],
            'arn': parts[1],
            'user_creation_time': parts[2],
            'password_enabled': parts[3],
            'password_last_used': parts[4],
            'password_last_changed': parts[5],
            'password_next_rotation': parts[6],
            'mfa_active': parts[7],
            'access_key_1_active': parts[8],
            'access_key_1_last_rotated': parts[9],
            'access_key_1_last_used_date': parts[10],
            'access_key_1_last_used_region': parts[11],
            'access_key_1_last_used_service': parts[12],
            'access_key_2_active': parts[13],
            'access_key_2_last_rotated': parts[14],
            'access_key_2_last_used_date': parts[15],
            'access_key_2_last_used_region': parts[16],
            'access_key_2_last_used_service': parts[17],
            'cert_1_active': parts[18],
            'cert_1_last_rotated': parts[19],
            'cert_2_active': parts[20],
            'cert_2_last_rotated': parts[21]
        }

        if user['password_enabled'] == 'true':
            users_with_passwords += 1
            if user['mfa_active'] == 'false':
                users_with_password_but_no_mfa.append(user['user'])
                #print('- User with password login, but no MFA: {}'.format(user['user']))

            if user['password_last_used'] == 'no_information':
                unused_password_accounts.append(user['user'])
                #print('- User has not logged in: {}'.format(user['user']))
            else:
                password_last_used_days = days_between(collection_date, user['password_last_used'])
                if password_last_used_days < MIN_DAYS_SINCE_LAST_USAGE:
                    active_password_accounts.append(user['user'])
                    #print('- User has logged in within the last {} days: {}'.format(password_last_used_days, user['user']))
                else:
                    inactive_password_accounts.append(user['user'])

        if user['access_key_1_active'] == "true" and user['access_key_2_active'] == "true":
            #print('- User with 2 active access keys: {}'.format(user['user']))
            multi_key_accounts.append(user['user'])

        if user['access_key_1_active'] == "true":
            if user['access_key_1_last_used_date'] == "N/A":
                unused_key_accounts.append(user['user'])
                #print('- User has key1, but has never used it: {}'.format(user['user']))
            else:
                days_since_key_use = days_between(collection_date, user['access_key_1_last_used_date'])
                if days_since_key_use > MIN_DAYS_SINCE_LAST_USAGE:
                    inactive_key_accounts.append(user['user'])
                    #print('- User last used key1 {} days ago: {}'.format(days_since_key_use, user['user']))

        if user['access_key_2_active'] == "true":
            if user['access_key_2_last_used_date'] == "N/A":
                unused_key_accounts.append(user['user'])
                #print('- User has key2, but has never used it: {}'.format(user['user']))
            else:
                days_since_key_use = days_between(collection_date, user['access_key_2_last_used_date'])
                if days_since_key_use > MIN_DAYS_SINCE_LAST_USAGE:
                    inactive_key_accounts.append(user['user'])
                    #print('- User has not used key2 in {} days: {}'.format(days_since_key_use, user['user']))

    # Print summary
    print('')
    print('*************************')
    print('***   User Summary   ****')
    print('*************************')
    print('')
    print('>> You have {} total username/password accounts'.format(users_with_passwords))
    print('')
    if len(active_password_accounts) > 0:
        print('>> There are {} active username/password accounts.  This ISN\'T normal. Check it out:'.format(len(active_password_accounts)))
        for acc in active_password_accounts:
            print('\t' + acc)
        print('')
    if len(inactive_password_accounts) > 0:
        print('>> There are {} stale username/password accounts.  See if you can clean them out:'.format(len(inactive_password_accounts)))
        for acc in inactive_password_accounts:
            print('\t' + acc)
        print('')
    if len(unused_password_accounts) > 0:
        print('>> There are {} username/password accounts that have never been logged in to.  Here comes the Ban Hammer!'.format(len(unused_password_accounts)))
        for acc in unused_password_accounts:
            print('\t' + acc)
        print('')
    if users_with_password_but_no_mfa != 0:
        print('>> Of {} users with passwords, {} had no MFA ({:0.2f}%)'.format(users_with_passwords, len(users_with_password_but_no_mfa), float(len(users_with_password_but_no_mfa))/float(users_with_passwords)*100.0))
        for acc in users_with_password_but_no_mfa:
            print('\t' + acc)
        print('')
    if len(multi_key_accounts) > 0:
        print('>> There are {} accounts with 2 MFA keys. You probably don\'t want that and should check it out.'.format(len(multi_key_accounts)))
        for acc in multi_key_accounts:
            print('\t' + acc)
        print('')

def audit_route53(region):
    autorenew_missing = []
    transferlock_missing = []

    json_blob = query_aws(region.account, "route53domains-list-domains", region)
    for domain in json_blob.get('Domains', []):
        if not domain['AutoRenew']:
            autorenew_missing.append(domain['DomainName'])
            #print('- Route53 domain not set to autorenew: {}'.format(domain['DomainName']))
        if not domain['TransferLock']:
            transferlock_missing.append(domain['DomainName'])
            #print('- Route53 domain transfer lock not set: {}'.format(domain['DomainName']))
    
    # Route53 summary
    print('')
    print('**************************')
    print('***  Route53 Summary  ****')
    print('**************************')
    print('')
    if len(autorenew_missing) > 0:
        print('> Route53 domain not set to autorenew on {} domain(s):'.format(len(autorenew_missing)))
        for d in autorenew_missing:
            print('\t' + d)
        print('')
    if len(transferlock_missing) > 0:
        print('> Route53 transferlock missing from {} domain(s):'.format(len(transferlock_missing)))
        for d in transferlock_missing:
            print('\t' + d)
        print('')

             


def audit_ebs_snapshots(region):
    unencrypted_snapshots = 0
    total_snapshots = 0

    json_blob = query_aws(region.account, "ec2-describe-snapshots", region)
    for snaphot in json_blob.get('Snapshots', []):
        total_snapshots += 1
        if not snaphot['Encrypted']:
            unencrypted_snapshots += 1
    for snapshot in json_blob['Snapshots']:
        try:
            file_json = get_parameter_file(region, 'ec2', 'describe-snapshot-attribute', snapshot['SnapshotId'])
            if file_json == None:
                print('- EBS snapshot in {} has no attributes: {}'.format(region.name, snapshot))
                continue
            for attribute in file_json['CreateVolumePermissions']:
                if attribute.get('Group', 'self') != 'self':
                    print('- EBS snapshot in {} is public: {}, entities allowed to restore: {}'.format(region.name, snapshot, attribute['Group']))
        except OSError:
            print('WARNING: Could not open {}'.format(file_name))
    
    # Snapshot summary
    if total_snapshots > 0:
        print('')
        print('**************************')
        print('** EBS Snapshot Summary **')
        print('*** region: {}  ***'.format(region._name))
        print('**************************')
        print('')    
        if unencrypted_snapshots > 0:
            print('You have {} unencrypted EBS snapshots. You probably don\'t want that.'.format(unencrypted_snapshots))
            print('')
        else:
            print('All of you EBS snapshots are encrypted. High five!')
            print('')

def audit_rds_snapshots(region):
    json_blob = query_aws(region.account, "rds-describe-db-snapshots", region)
    for snapshot in json_blob.get('DBSnapshots', []):
        try:
            file_json = get_parameter_file(region, 'rds', 'describe-db-snapshot-attributes', snapshot['DBSnapshotIdentifier'])
            for attribute in file_json['DBSnapshotAttributesResult']['DBSnapshotAttributes']:
                if attribute['AttributeName'] == 'restore':
                    if "all" in attribute['AttributeValues']:
                        print('- RDS snapshot in {} is public: {}, entities allowed to restore: {}'.format(region.name, snapshot, attribute['AttributeValues']))
        except OSError:
            print('WARNING: Could not open {}'.format(file_name))


def audit_rds(region):
    public_db = []
    unencrypted_db = []
    iam_auth = []

    json_blob = query_aws(region.account, "rds-describe-db-instances", region)
    for instance in json_blob.get('DBInstances', []):
        if not instance['StorageEncrypted']:
            unencrypted_db.append(instance['DBInstanceIdentifier'])
        if instance['PubliclyAccessible']:
            public_db.append(instance['DBInstanceIdentifier'])
            print('- RDS instance in {} is public: {}'.format(region.name, instance['DBInstanceIdentifier']))
        if instance['IAMDatabaseAuthenticationEnabled']:
            iam_auth.append(instance['DBInstanceIdentifier'])

    print('')
    print('**************************')
    print('****** RDS Summary *******')
    print('*** region: {}  ***'.format(region._name))
    print('**************************')
    print('')
    if len(unencrypted_db) > 0:
        print('The following RDS instances are NOT encrypted:') 
        print('')
        for db in unencrypted_db:
            print(db)
        print('')
    if len(public_db) > 0:
        print('The following RDS instances are PUBLIC:')
        print('')
        for db in public_db:
            print(db)
        print('')
    if len(iam_auth) > 0:
        print('The following RDS instances are configured for IAM Dabatabse Authentication:')
        print('')
        for db in iam_auth:
            print(db)
        print('')

def audit_amis(region):
    json_blob = query_aws(region.account, "ec2-describe-images", region)
    for image in json_blob.get('Images', []):
        if image['Public']:
            print('- AMI is public: {} in {}'.format(image['ImageId'], region.name))


def audit_ecr_repos(region):
    json_blob = query_aws(region.account, "ecr-describe-repositories", region)
    for repo in json_blob.get('repositories', []):
        name = repo['repositoryName']

        # Check policy
        policy_file_json = get_parameter_file(region, 'ecr', 'get-repository-policy', name)
        if policy_file_json is None:
            # This means only the owner can access the repo, so this is fine.
            # The collect command would have received the exception 
            # `RepositoryPolicyNotFoundException` for this to happen.
            continue
        # Find the entity we need
        policy_string = policy_file_json['policyText']
        # Load the string value as json
        policy = json.loads(policy_string)
        policy = Policy(policy)
        if policy.is_internet_accessible():
            print('- Internet accessible ECR repo {}: {}'.format(name, policy_string))


def audit_redshift(region):
    json_blob = query_aws(region.account, "redshift-describe-clusters", region)
    for cluster in json_blob.get('Clusters', []):
        if cluster['PubliclyAccessible']:
            print('- Redshift is public: {} in {}'.format(cluster['ClusterIdentifier'], region.name))


def audit_es(region):
    json_blob = query_aws(region.account, 'es-list-domain-names', region)
    for domain in json_blob.get('DomainNames', []):
        name = domain['DomainName']

        # Check policy
        policy_file_json = get_parameter_file(region, 'es', 'describe-elasticsearch-domain', name)
        # Find the entity we need
        policy_string = policy_file_json['DomainStatus']['AccessPolicies']
        # Load the string value as json
        policy = json.loads(policy_string)
        policy = Policy(policy)

        # ES clusters or either public, with an "Endpoint" (singular), which is bad, or
        # they are VPC-only, in which case they have an "Endpoints" (plural) array containing a "vpc" element
        if policy_file_json['DomainStatus'].get('Endpoint', '') != '' or policy_file_json['DomainStatus'].get('Endpoints', {}).get('vpc', '') == '':
            if policy.is_internet_accessible():
                print('- Internet accessible ElasticSearch cluster {}: {}'.format(name, policy_string))


def audit_cloudfront(region):
    json_blob = query_aws(region.account, 'cloudfront-list-distributions', region)

    for distribution in json_blob.get('DistributionList', {}).get('Items', []):
        if not distribution['Enabled']:
            continue

        minimum_protocol_version = distribution.get('ViewerCertificate', {}) \
            .get('MinimumProtocolVersion', '')
        if minimum_protocol_version == 'SSLv3':
            print('- CloudFront is using insecure minimum protocol version {} for {} in {}'.format(minimum_protocol_version, distribution['DomainName'], region.name))
        
        domain = distribution['DomainName']


def audit_ec2(region):
    json_blob = query_aws(region.account, 'ec2-describe-instances', region)
    route_table_json = query_aws(region.account, 'ec2-describe-route-tables', region)

    ec2_classic_count = 0
    for reservation in json_blob.get('Reservations', []):
        for instance in reservation.get('Instances', []):
            if instance.get('State', {}).get('Name', '') == 'terminated':
                # Ignore EC2's that are off
                continue

            if 'vpc' not in instance.get('VpcId', ''):
                ec2_classic_count += 1

            if not instance.get('SourceDestCheck', True):
                print('- EC2 SourceDestCheck is off: {}'.format(instance['InstanceId']))

                route_to_instance = None
                for table in route_table_json['RouteTables']:
                    if table['VpcId'] == instance.get('VpcId', ''):
                        for route in table['Routes']:
                            if route.get('InstanceId', '') == instance['InstanceId']:
                                route_to_instance = route
                                break
                    if route_to_instance is not None:
                        break

                if route_to_instance is None:
                    print('  - No routes to instance, SourceDestCheck is not doing anything')
                else:
                    print('  -Routes: {}'.format(route_to_instance))

    if ec2_classic_count != 0:
        print('- EC2 classic instances found: {}'.format(ec2_classic_count))


def audit_elb(region):
    json_blob = query_aws(region.account, 'elb-describe-load-balancers', region)
    for description in json_blob.get('LoadBalancerDescriptions', []):
        if len(description['Instances']) == 0:
            # Checks if there are backend's or not. Not a security risk, just odd that this is so common,
            # and wastes money, but this just clutters my report.
            #print('- ELB has no backend instances: {} in {}'.format(
            #      description['DNSName'],
            #      region.name))
            pass


def audit_sg(region):
    # TODO Check if security groups allow large CIDR range (ex. 1.2.3.4/3)
    # TODO Check if an SG allows overlapping CIDRs, such as 10.0.0.0/8 and then 0.0.0.0/0
    # TODO Check if an SG restricts IPv4 and then opens IPv6 or vice versa.
    unrestricted_sgs = []

    json_blob = query_aws(region.account, "ec2-describe-security-groups", region)
    for group in json_blob.get('SecurityGroups', []):
        for inbound_rule in group.get('IpPermissions', []):
            for cidr_range in inbound_rule.get('IpRanges'):
                if cidr_range.get('CidrIp', '') == '0.0.0.0/0':
                    sg_name = group['GroupName']
                    sg_id = group['GroupId']
                    start_port = inbound_rule['FromPort']
                    end_port = inbound_rule['ToPort']
                    
                    unrestricted_sgs.append({'SecurityGroupName':sg_name, 'SecurityGroupID':sg_id, 'StartPort':start_port, 'EndPort':end_port})

    if len(unrestricted_sgs) > 0:
        header = unrestricted_sgs[0].keys()
        rows = [x.values() for x in unrestricted_sgs]

        print('')
        print('**************************')
        print('** Security Group Audit **')
        print('*** region: {}  ***'.format(region._name))
        print('**************************')
        print('')  
        print('- The following security groups have no IP restrictions')
        print('')
        print (tabulate(rows, header))
        print('')
        #print('- Security Group: {}, {} allows worldwide access to port {}'.format(sg_name, sg_id, start_port))



def audit_lambda(region):
    # Check for publicly accessible functions.  They should be called from apigateway or something else.
    json_blob = query_aws(region.account, "lambda-list-functions", region)
    for function in json_blob.get('Functions', []):
        name = function['FunctionName']

        # Check policy
        policy_file_json = get_parameter_file(region, 'lambda', 'get-policy', name)
        if policy_file_json is None:
            # No policy
            continue

        # Find the entity we need
        policy_string = policy_file_json['Policy']
        # Load the string value as json
        policy = json.loads(policy_string)
        policy = Policy(policy)
        if policy.is_internet_accessible():
            print('- Internet accessible Lambda {}: {}'.format(name, policy_string))


def audit_glacier(region):
    # Check for publicly accessible vaults.
    json_blob = query_aws(region.account, "glacier-list-vaults", region)
    if json_blob is None:
        # Service not supported in the region
        return

    for vault in json_blob.get('VaultList', []):
        name = vault['VaultName']

        # Check policy
        policy_file_json = get_parameter_file(region, 'glacier', 'get-vault-access-policy', name)
        if policy_file_json is None:
            # No policy
            continue

        # Find the entity we need
        policy_string = policy_file_json['policy']['Policy']
        # Load the string value as json
        policy = json.loads(policy_string)
        policy = Policy(policy)
        if policy.is_internet_accessible():
            print('- Internet accessible Glacier vault {}: {}'.format(name, policy_string))


def audit_kms(region):
    # Check for publicly accessible KMS keys.
    json_blob = query_aws(region.account, "kms-list-keys", region)
    if json_blob is None:
        # Service not supported in the region
        return

    for key in json_blob.get('Keys', []):
        name = key['KeyId']

        # Check policy
        policy_file_json = get_parameter_file(region, 'kms', 'get-key-policy', name)
        if policy_file_json is None:
            # No policy
            continue

        # Find the entity we need
        policy_string = policy_file_json['Policy']
        # Load the string value as json
        policy = json.loads(policy_string)
        policy = Policy(policy)
        if policy.is_internet_accessible():
            print('- Internet accessible KMS {}: {}'.format(name, policy_string))


def audit_sqs(region):
    # Check for publicly accessible sqs.
    json_blob = query_aws(region.account, "sqs-list-queues", region)
    if json_blob is None:
        # Service not supported in the region
        return

    for queue in json_blob.get('QueueUrls', []):
        queue_name = queue.split("/")[-1]
        # Check policy
        queue_attributes = get_parameter_file(region, 'sqs', 'get-queue-attributes', queue)
        if queue_attributes is None:
            # No policy
            continue

        # Find the entity we need
        attributes = queue_attributes['Attributes']
        if 'Policy' in attributes:
            policy_string = attributes['Policy']
        else:
            # No policy set
            continue

        # Load the string value as json
        policy = json.loads(policy_string)
        policy = Policy(policy)
        if policy.is_internet_accessible():
            print('- Internet accessible SQS {}: {}'.format(queue_name, policy_string))


def audit_sns(region):
    # Check for publicly accessible sns.
    json_blob = query_aws(region.account, "sns-list-topics", region)
    if json_blob is None:
        # Service not supported in the region
        return

    for topic in json_blob.get('Topics', []):
        # Check policy
        attributes = get_parameter_file(region, 'sns', 'get-topic-attributes', topic['TopicArn'])
        if attributes is None:
            # No policy
            continue

        # Find the entity we need
        attributes = attributes['Attributes']
        if 'Policy' in attributes:
            policy_string = attributes['Policy']
        else:
            # No policy set
            continue

        # Load the string value as json
        policy = json.loads(policy_string)
        policy = Policy(policy)
        if policy.is_internet_accessible():
            print('- Internet accessible SNS {}: {}'.format(topic['TopicArn'], policy_string))


def audit_lightsail(region):
    # Just check if lightsail is in use
    json_blob = query_aws(region.account, "lightsail-get-instances", region)
    if json_blob is None:
        # Service not supported in the region
        return
    
    if len(json_blob.get('instances', [])) > 0:
        print('- Lightsail used ({} instances) in region {}'.format(json_blob['instances'], region.name))
    
    json_blob = query_aws(region.account, "lightsail-get-load-balancers", region)
    if json_blob is None:
        # Service not supported in the region
        return
    
    if len(json_blob.get('loadBalancers', [])) > 0:
        print('- Lightsail used ({} load balancers) in region {}'.format(json_blob['loadBalancers'], region.name))



def audit(accounts, config):
    """Audit the accounts"""
    print('llllllllllllllllllllN                   :+++++++++++++++++++')
    print('lllllllllllllllll++lllN                 :+++++++++++++++++++')
    print('lllllllllllllll++++lllllN               :+++++++++++++++++++')
    print('lllllllllllll++++++lllllllN             :+++++++++++++++++++')
    print('lllllllllll++++++++lllllllllN           :+++++++++++++++++++')
    print('lllllllll++++++++++llllllllllllN        :+++++++++++++++++++')
    print('lllllll++++++++++++llllllllllllllN      :+++++++++++++++++++')
    print('lllll++++++++++++++llllllllllllllllN    :+++++++++++++++++++')
    print('lll++++++++++++++++llllllllllllllllllN  :+++++++++++++++++++')
    print('l++++++++++++++++++llllllllllllllllllllN:+++++++++++++++++++')
    print('+++++++++++++++++++lllllllllllllllllllll:x++++++++++++++++++')
    print('+++++++++++++++++++lllllllllllllllllllll:xxx++++++++++++++++')
    print('+++++++++++++++++++lllllllllllllllllllll:xxxxx++++++++++++++')
    print('+++++++++++++++++++lllllllllllllllllllll:xxxxxxx++++++++++++')
    print('+++++++++++++++++++lllllllllllllllllllll:xxxxxxxxx++++++++++')
    print('+++++++++++++++++++lllllllllllllllllllll:xxxxxxxxxxx++++++++')
    print('+++++++++++++++++++lllllllllllllllllllll:xxxxxxxxxxxxx++++++')
    print('+++++++++++++++++++lllllllllllllllllllll:xxxxxxxxxxxxxxx++++')
    print('+++++++++++++++++++lllllllllllllllllllll:xxxxxxxxxxxxxxxxx++')
    print('+++++++++++++++++++lllllllllllllllllllll:xxxxxxxxxxxxxxxxxxx')
    print('+++++++++++++++++lllNlllllllllllllllllll:xxxxxxxxxxxxxxxxxx+')
    print('+++++++++++++++lllll Nllllllllllllllllll:xxxxxxxxxxxxxxxx+++')
    print('+++++++++++++lllllll   Nllllllllllllllll:xxxxxxxxxxxxxx+++++')
    print('+++++++++++lllllllll     Nllllllllllllll:xxxxxxxxxxxx+++++++')
    print('+++++++++lllllllllll       Nllllllllllll:xxxxxxxxxx+++++++++')
    print('+++++++lllllllllllll         Nllllllllll:xxxxxxxx+++++++++++')
    print('+++++lllllllllllllll           Nllllllll:xxxxxx+++++++++++++')
    print('+++lllllllllllllllll             Nllllll:xxxx+++++++++++++++')
    print('+lllllllllllllllllll               Nllll:xx+++++++++++++++++')
    print('llllllllllllllllllll                 Nll:+++++++++++++++++++')
    print('')
    print('Welcome to the NerdMapper AWS Audit script!')
    print('....or judgyMcJudgeFace.py')
    print('')

    print('Press "ENTER" to start the audit')
    input()

    for account in accounts:
        account = Account(None, account)
        print('Finding resources in account {} ({})'.format(account.name, account.local_id))
        print('')

        for region_json in get_regions(account):
            region = Region(account, region_json)
            try:
                if region.name == 'us-east-1':
                    audit_s3_buckets(region)
                    audit_s3_block_policy(region)
                    audit_cloudtrail(region)
                    audit_password_policy(region)
                    audit_root_user(region)
                    audit_users(region)
                    audit_route53(region)
                    audit_cloudfront(region)
                    audit_guardduty(region)
                audit_ebs_snapshots(region)
                audit_rds_snapshots(region)
                audit_rds(region)
                audit_amis(region)
                audit_ecr_repos(region)
                audit_redshift(region)
                audit_es(region)
                audit_ec2(region)
                audit_elb(region)
                audit_sg(region)
                audit_lambda(region)
                audit_glacier(region)
                audit_kms(region)
                audit_sqs(region)
                audit_sns(region)
                audit_lightsail(region)
            except Exception as e:
                print('Exception in {} in {}'.format(region.account.name, region.name), file=sys.stderr)
                traceback.print_exc()


def run(arguments):
    _, accounts, config = parse_arguments(arguments)
    audit(accounts, config)
