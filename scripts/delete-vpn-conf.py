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
def create_paloalto_config(peer_group,vpn_connection_id):
    path = "/var/lib/jenkins/workspace/DeployStack/scripts"

    vpn_conf_file_path  = path+'/vpn-configurations/'+vpn_connection_id

    f = open(vpn_conf_file_path, 'r')  # open file in append  mode
    fdata = [line.rstrip() for line in f]
  
    config_text = []   
    config_text.append('configure')

    # Delete IPSec Tunnel #1   
    config_text.append('edit network virtual-router default protocol bgp')
    config_text.append('edit peer-group {}'.format(peer_group))
    config_text.append('delete peer {}'.format(fdata[0]))
    config_text.append('top')
    config_text.append('delete network tunnel ipsec {}'.format(fdata[1]))      
    config_text.append('delete zone VPN network layer3 {}'.format(fdata[2]))
    config_text.append('delete network virtual-router default interface {}'.format(fdata[2]))
    config_text.append('delete network interface tunnel units {}'.format(fdata[2]))
    config_text.append('delete network ike gateway {}'.format(fdata[3]))

    # Delete IPSec Tunnel #2
    config_text.append('edit network virtual-router default protocol bgp')
    config_text.append('edit peer-group {}'.format(peer_group))
    config_text.append('delete peer {}'.format(fdata[4]))
    config_text.append('top')
    config_text.append('delete network tunnel ipsec {}'.format(fdata[5]))  
    config_text.append('delete zone VPN network layer3 {}'.format(fdata[6]))
    config_text.append('delete network virtual-router default interface {}'.format(fdata[6]))
    config_text.append('delete network interface tunnel units {}'.format(fdata[6]))
    config_text.append('delete network ike gateway {}'.format(fdata[7]))

    f.close()
    
    os.rename(vpn_conf_file_path, vpn_conf_file_path+".deleted")

    for line in config_text: 
        print(line)

    log.debug("Conversion complete")
    return config_text

def pushConfig(ssh, config):
    
    ssh.send('configure\n')
    
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
	
def deleteVPN(role,ip,vpn_connection_id):

    print("----------------------------------------------------------------------------------------------------------")
    print("Configure VPN connection on Palo Alto Node "+ip+" using extract from AWS file : "+ vpn_connection_id+".txt")
    print("----------------------------------------------------------------------------------------------------------")
    print("Connecting to "+ip)

    try:
    
        paramiko.util.log_to_file("tunnels.log")
        privkey = paramiko.RSAKey.from_private_key_file("pan-key.pem")
        session = paramiko.SSHClient()
        session.set_missing_host_key_policy(paramiko.AutoAddPolicy)
        session.connect (ip, username="admin", pkey = privkey)
        connection = session.invoke_shell()		
        vpn_connection_conf = create_paloalto_config(role,vpn_connection_id)
        pushConfig(connection,vpn_connection_conf)
        session.close()            
        print("----------------------- configuration done ----------------------------") 

    except paramiko.AuthenticationException:

        print("AuthenticationException")


def main():
    
    # Get command line arguments
    parser = argparse.ArgumentParser(description="Create VPN Connection")
    parser.add_argument('-v', '--verbose', action='count', help="Verbose (-vv for extra verbose)")
    parser.add_argument('-q', '--quiet', action='store_true', help="No output")
    parser.add_argument('role', help="Palo alto node role [Active,Passive]")
    parser.add_argument('palo_node_ip', help="Palo alto Node ip")
    parser.add_argument('vpn_connection_id', help="AWS vpn connection id")
    args = parser.parse_args()
    
    palo_role = args.role
    palo_node_ip = args.palo_node_ip
    vpn_connection_id = args.vpn_connection_id

    if args.verbose is None:
        args.verbose = 0
    if not args.quiet:
        logging_level = 20 - (args.verbose * 10)
        if logging_level <= logging.DEBUG:
            logging_format = '%(levelname)s:%(name)s:%(message)s'
        else:
            logging_format = '%(message)s'
        logging.basicConfig(format=logging_format, level=logging_level)
    
        deleteVPN(palo_role,palo_node_ip,vpn_connection_id)

if __name__ == '__main__':
    main()
