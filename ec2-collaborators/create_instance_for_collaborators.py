import boto3
import time
import json
from pprint import pprint
from select import select
import logging
from logging import Logger
from paramiko import SSHClient
import paramiko
from typing import Any
import os

"""
This script creates all the pieces needed to share data with collaborators on AWS
Change the COLLABORATOR_NAME to something human readable
and the KEY_PAIR to a computer (no spaces or weird characters) name.
This script takes some time. 

It has a few sleep commands with best guesses on the upper limit of how it takes to deploy certain resources. Do not remove the sleep statements!

"""

COLLABORATOR = "2020-01 Sidonie Reupload"
KEY_PAIR = "2020-01-sidonie-reupload"

report_data = {
    'name': COLLABORATOR,
    'computer_name': KEY_PAIR,
}

logger = logging.getLogger('mount_storage')
logger.setLevel(logging.DEBUG)


def initialize_dir():
    """
    We don't want to rewrite any directories
    If directory already exists DIE
    """
    if not os.path.exists(KEY_PAIR):
        os.mkdir(KEY_PAIR)
    else:
        raise Exception('Directory {} already exists. Exiting'.format(KEY_PAIR))


def initialize_ssh(user: str, host: str):
    ssh = paramiko.SSHClient()
    k = paramiko.RSAKey.from_private_key_file('{key_file}'.format(key_file=report_data['ssh_key']['key_file']))
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, username=user, pkey=k)

    sftp = ssh.open_sftp()
    return ssh, sftp


def execute_ssh_command(ssh_client: SSHClient, command: str, logger: Logger, timeout: int = None) -> bool:
    """
    Execute a long running ssh command
    :param ssh_client: paramiko ssh client
        Example:     args = parser.parse_args()
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect('remote-host', username='remote-user')
    :param command: command to execute
    :param logger: logging logger
            import logging
            logger = logging.getLogger('name_of_my_logger')
            logger.setLevel(logging.DEBUG)
    :param timeout:
    :return:
    """
    try:
        if not command:
            raise Exception("no command specified so nothing to execute here.")

        # Auto apply tty when its required in case of sudo
        get_pty = False
        if command.startswith('sudo'):
            get_pty = True

        # set timeout taken as params
        logger.info('Executing command: {}'.format(command))

        stdin, stdout, stderr = ssh_client.exec_command(command=command,
                                                        get_pty=get_pty,
                                                        timeout=timeout
                                                        )
        # get channels
        channel = stdout.channel

        # closing stdin
        stdin.close()
        channel.shutdown_write()

        agg_stdout = b''
        agg_stderr = b''

        # capture any initial output in case channel is closed already
        stdout_buffer_length = len(stdout.channel.in_buffer)

        if stdout_buffer_length > 0:
            agg_stdout += stdout.channel.recv(stdout_buffer_length)

        # read from both stdout and stderr
        while not channel.closed or \
                channel.recv_ready() or \
                channel.recv_stderr_ready():
            readq, _, _ = select([channel], [], [], timeout)
            for c in readq:
                if c.recv_ready():
                    line = stdout.channel.recv(len(c.in_buffer))
                    line = line
                    agg_stdout += line
                    logger.info(line.decode('utf-8').strip('\n'))
                if c.recv_stderr_ready():
                    line = stderr.channel.recv_stderr(len(c.in_stderr_buffer))
                    line = line
                    agg_stderr += line
                    logger.warning(line.decode('utf-8').strip('\n'))
            if stdout.channel.exit_status_ready() \
                    and not stderr.channel.recv_stderr_ready() \
                    and not stdout.channel.recv_ready():
                stdout.channel.shutdown_read()
                stdout.channel.close()
                break

        stdout.close()
        stderr.close()

        exit_status = stdout.channel.recv_exit_status()
        if exit_status is 0:
            # returning output if do_xcom_push is set
            logger.info('Command exited with exitcode 0')

        else:
            error_msg = agg_stderr.decode('utf-8')
            raise Exception("error running cmd: {0}, error: {1}".format(command, error_msg))

    except Exception as e:
        raise Exception("SSH operator error: {0}".format(str(e)))

    return True


def write_key_file():
    """
    Write out the .pem ssh key file
    :return:
    """
    f = open(os.path.join(KEY_PAIR, 'keypair.pem'), 'w+')
    f.write(report_data['ssh_key']['key'])
    f.close()
    os.chmod(os.path.join(KEY_PAIR, 'keypair.pem'), 0o400)
    logger.info(
        'Wrote out ssh key file to {keypair}'.format(
            keypair=
            os.path.abspath(os.path.join(KEY_PAIR, 'keypair.pem'))
        )
    )


def create_key_pair():
    ec2_client = boto3.client('ec2')
    key_pair_response = ec2_client.create_key_pair(KeyName=KEY_PAIR)
    report_data['ssh_key'] = {}
    report_data['ssh_key']['id'] = key_pair_response['KeyPairId']
    report_data['ssh_key']['name'] = key_pair_response['KeyName']
    report_data['ssh_key']['key'] = key_pair_response['KeyMaterial']
    report_data['ssh_key']['key_file'] = os.path.abspath(os.path.join(KEY_PAIR, 'keypair.pem'))
    logger.info('Successfully created ssh key')


def create_instance():
    ec2 = boto3.resource('ec2')
    instance = ec2.create_instances(
        SecurityGroupIds=['sg-0bec93406f5807adf'],
        ImageId='ami-062f7200baf2fa504',
        MinCount=1,
        MaxCount=1,
        InstanceType='t3a.medium',
        KeyName=KEY_PAIR,
        TagSpecifications=[
            {
                'ResourceType': 'instance',
                'Tags': [
                    {
                        'Key': 'Name',
                        'Value': COLLABORATOR
                    },
                ]
            },
        ],
    )
    report_data['ec2'] = {}
    report_data['ec2']['id'] = instance[0].id
    report_data['ec2']['PublicIP'] = None


def get_public_ip():
    print('Waiting for instance to initialize with public IP address...')
    print('This may take some time...')
    time.sleep(10)
    ec2 = boto3.resource('ec2')
    running_instances = ec2.instances.filter(Filters=[
        {
            'Name': 'instance-state-name',
            'Values': ['running']
        },
        {
            'Name': 'instance-id',
            'Values': [report_data['ec2']['id']]
        }
    ])
    for instance in running_instances:
        # Add instance info to a dictionary
        report_data['ec2'] = {
            'instance_id': report_data['ec2']['id'],
            'Type': instance.instance_type,
            'State': instance.state['Name'],
            'PrivateIP': instance.private_ip_address,
            'PublicIP': instance.public_ip_address,
            'LaunchTime': str(instance.launch_time)
        }


def create_efs():
    efs_client = boto3.client('efs')
    efs_response = efs_client.create_file_system(
        Tags=[
            {
                'Key': 'Name',
                'Value': COLLABORATOR,
            },
        ]
    )
    efs_id = efs_response['FileSystemId']
    report_data['efs'] = {}
    report_data['efs']['id'] = efs_id

    time.sleep(120)
    security_groups = ['sg-9e0443d7', 'sg-0bec93406f5807adf']
    subnets = [
        'subnet-3809f85f', 'subnet-e039dfce',
        'subnet-d340fadc', 'subnet-c40506fb',
        'subnet-079d354d', 'subnet-a3cf2bff',
    ]
    for subnet in subnets:
        efs_client.create_mount_target(
            FileSystemId=efs_id,
            SubnetId=subnet,
            SecurityGroups=security_groups
        )
    return efs_id


def mount_storage():
    """
    SSH on over to the instance and run the mount commands
    """
    print('Mounting storage {} on box {}...'.format(
        report_data['efs']['id'],
        report_data['ec2']['PublicIP']
    ))
    print('It can take some time for EFS storage to become available.')
    print('Do not exit this script!')
    time.sleep(1000)
    commands = [
        "sudo yum install -y amazon-efs-utils",
        "sudo mkdir efs",
    ]
    mount_command = "sudo mount -t efs {efs_id}:/ efs".format(efs_id=report_data['efs']['id'])
    report_data['mount_command'] = mount_command
    ssh, sftp = initialize_ssh('ec2-user', report_data['ec2']['PublicIP'])
    for command in commands:
        execute_ssh_command(ssh, command, logger=logging)

    try:
        execute_ssh_command(ssh, mount_command, logger=logging)
    except Exception as e:
        print('EFS availability is taking longer than expected.')
        print('You will need to manually mount the storage before rsyncing data.')
        print('Please ssh over to your instance by:')
        print('###################################')
        print('# SSH Command')
        print(report_data['ssh_command'])
        print('and run:')
        print('###################################')
        print('# Mount storage')
        print(mount_command)
        print('###################################')
        sys.exit(1)

    command = "sudo chown ec2-user:ec2-user /home/ec2-user/efs"
    execute_ssh_command(ssh, command, logger=logging)


def write_report():
    logger.info('Writing report to {}'.format(
        os.path.abspath(os.path.join(KEY_PAIR, 'report.json'))
    ))
    f = open(os.path.abspath(os.path.join(KEY_PAIR, 'report.json'))
             , 'w+')
    json.dump(report_data, f, ensure_ascii=False, indent=4)
    f.close()


def print_helper_commands():
    """
    Print some helper commands for ssh and rsync to the screen
    """
    rsync_command = "rsync -av --progress -e 'ssh -i {key_file}' HOST_DIR ec2-user@{public_id}:/home/ec2-user/efs".format(
        key_file=report_data['ssh_key']['key_file'],
        public_id=report_data['ec2']['PublicIP']
    )
    ssh_command = "ssh -i {key_file} ec2-user@{public_ip}".format(
        key_file=report_data['ssh_key']['key_file'],
        public_ip=report_data['ec2']['PublicIP']
    )
    report_data['ssh_command'] = ssh_command
    report_data['rsync_command'] = rsync_command
    print('Some helpful commands!')
    print('###################################')
    print('# SSH to the instance with: ')
    print(ssh_command)
    print('###################################')

    print('###################################')
    print('# Rsync data to the instance with: ')
    print(rsync_command)
    print('###################################')


def print_end_message():
    print('##################################')
    print('Finished!')
    print('See {dir}/report.json for details'.format(dir=KEY_PAIR))


initialize_dir()
create_key_pair()
write_key_file()
create_instance()
while report_data['ec2']['PublicIP'] is None:
    get_public_ip()
create_efs()
print_helper_commands()
write_report()
mount_storage()
print_end_message()
