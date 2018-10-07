#!/usr/bin/env python

from __future__ import print_function

import paramiko
from xml.dom import minidom
import ast
import time
import os
import sys
import argparse
import logging
import sh
import subprocess
from subprocess import PIPE
log = logging.getLogger()
log.setLevel(logging.INFO)



#Logic to create the appropriate PaloAlto configuration
def create_paloalto_config(gateway,mgmt_ip):

    config_text = []

    # Configure Networking

    config_text.append('configure \n')

    config_text.append('edit network interface')    
    config_text.append('set ethernet ethernet1/1 layer3 ip {}'.format(mgmt_ip))
    config_text.append('set ethernet ethernet1/1 layer3 interface-management-profile DataPlane')
    config_text.append('top')
    config_text.append('set network virtual-router default routing-table ip static-route default-route destination 0.0.0.0/0 nexthop ip-address {}'.format(gateway))
    config_text.append('top')

    for line in config_text: 
        print(line)
    log.debug("Conversion complete")
    return config_text

def pushConfig(ssh, config):
     
    stime = time.time()
    for line in config:
        ssh.send(line+'\n')
        log.info("%s", line)
    
    log.info("Saving backup config...")
    ssh.send('save config to AWS_config.txt\n\n\n\n\n')
    log.info("Backup configuration saved")
    time.sleep(15)

    log.info("Committing Configuration...")
    ssh.send('commit\n')
    time.sleep(30)
    ssh.send('exit\n')

    log.debug("   ... %s seconds ...", (time.time() - stime))

    ssh.send('exit\n')

    log.info("Config Update complete!")
	
def configureNetwork(ip,key,gateway,mgmt_ip):

    print("----------------------------------------------------------------------------------------------------------")
    print("Configure Networking for Palo Alto Node "+ip)
    print("----------------------------------------------------------------------------------------------------------")
    print("Connecting to "+ip)

    try:
    
        privkey = paramiko.RSAKey.from_private_key_file(key)
        session = paramiko.SSHClient()
        session.set_missing_host_key_policy(paramiko.AutoAddPolicy)
        session.connect (ip, username="admin", pkey = privkey)
        connection = session.invoke_shell()		
        node_conf = create_paloalto_config(gateway,mgmt_ip)
        pushConfig(connection,node_conf)
        session.close()            
        print("----------------------- configuration done ----------------------------") 

    except paramiko.AuthenticationException:

        print("AuthenticationException")


def main():
    
    # Get command line arguments
    parser = argparse.ArgumentParser(description="Create VPN Connection")
    parser.add_argument('-v', '--verbose', action='count', help="Verbose (-vv for extra verbose)")
    parser.add_argument('-q', '--quiet', action='store_true', help="No output")   
    parser.add_argument('palo_node_ip', help="Palo alto Node ip")
    parser.add_argument('key', help="Privte key")
    parser.add_argument('gateway', help="gateway")
    parser.add_argument('mgmt_ip', help="mgmt_ip")
    args = parser.parse_args()
    
    
    palo_node_ip = args.palo_node_ip
    palo_key = args.key
    gateway = args.gateway
    mgmt_ip = args.mgmt_ip
    
    ### Set up logger
    # Logging Levels
    # WARNING is 30
    # INFO is 20
    # DEBUG is 10

    if args.verbose is None:
        args.verbose = 0
    if not args.quiet:
        logging_level = 20 - (args.verbose * 10)
        if logging_level <= logging.DEBUG:
            logging_format = '%(levelname)s:%(name)s:%(message)s'
        else:
            logging_format = '%(message)s'
        logging.basicConfig(format=logging_format, level=logging_level)
    
    configureNetwork(palo_node_ip,palo_key,gateway,mgmt_ip)


if __name__ == '__main__':
    main()
