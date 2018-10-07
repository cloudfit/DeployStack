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

# Logic to figure out the next available tunnel
def getNextTunnelId(ssh):
    log.info('Start getNextTunnelId')
    output = ''
    prompt(ssh)
    ssh.send('show interface logical \n')
    output = prompt(ssh)

    lastTunnelNum = ''
    for line in output.split('\n'):
       # log.info('line: %s',line)
        if line.strip()[:7] == 'tunnel.':
        #    log.info("%s", line)
            lastTunnelNum = line.strip().partition(' ')[0].replace('tunnel.','')

    #ssh.send('exit\n')

    print("lastTunnelNum : "+lastTunnelNum)
    if lastTunnelNum == '':
        return 1
    else:
        return 1 + int(lastTunnelNum)

def bash(vpn_connection_id,search):
        result = []
        #subprocess.check_output(['aws', 's3', 'cp', 's3://pan-vpn-cfg/'+vpn_connection_id+'.txt', '.'])
        vpn_config_file = vpn_connection_id+".txt"
	content = open(vpn_config_file, 'r')
	content.seek(0)
	for line in content:
    	   if search in line:
              #log.debug(line)
              result.append(line.rstrip('\n').lstrip(' '))

        return result


#Logic to create the appropriate PaloAlto configuration
def create_paloalto_config(vpn_connection_id,tunnel_Id):
    #tunnel_Id+=1
    pre_shared_key = bash(vpn_connection_id,"pre-shared-key")
    local_address = bash(vpn_connection_id,"set local-address ip")
    peer_address = bash(vpn_connection_id,"set peer-address ip")
    tunnel_ip = bash(vpn_connection_id,"set ip")
    local_as = bash(vpn_connection_id,"set local-as")
    peer_group = "Active"
    peer_as = bash(vpn_connection_id,"set peer-as")

    config_text = []

    # IPSec Tunnel #1

    config_text.append('configure \n')
    config_text.append('edit network ike gateway ike-{}-{}'.format(vpn_connection_id,1))
    config_text.append('set protocol ikev1 ike-crypto-profile default exchange-mode main')
    config_text.append('set protocol ikev1 dpd interval 10 retry 3 enable yes')
    config_text.append('{}'.format(pre_shared_key[0]))
    config_text.append('{}'.format(local_address[0]))
    config_text.append('set local-address interface ethernet1/1')
    config_text.append('{}'.format(peer_address[0]))
    config_text.append('top')

    config_text.append('edit network interface tunnel units tunnel.{}'.format(tunnel_Id))
    config_text.append('{}'.format(tunnel_ip[0]))
    config_text.append('set mtu 1427')
    config_text.append('top')

    config_text.append('set zone VPN network layer3 tunnel.{}'.format(tunnel_Id))
    config_text.append('set network virtual-router default interface tunnel.{}'.format(tunnel_Id))

    config_text.append('edit network tunnel ipsec ipsec-{}-{}'.format(vpn_connection_id,tunnel_Id))
    config_text.append('set auto-key ipsec-crypto-profile default')
    config_text.append('set auto-key ike-gateway ike-{}-{}'.format(vpn_connection_id,1))
    config_text.append('set tunnel-interface tunnel.{}'.format(tunnel_Id))
    config_text.append('set anti-replay yes')
    config_text.append('top')

    config_text.append('edit network virtual-router default protocol bgp')
    #config_text.append('set router-id {}'.format(local_address))
    #config_text.append('set enable yes')
    #config_text.append('{}'.format(local_as[0]))
    config_text.append('edit peer-group {}'.format(peer_group))
    config_text.append('edit peer peer-{}-{}'.format(vpn_connection_id,1))
    config_text.append('{}'.format(peer_as[0]))
    config_text.append('set connection-options keep-alive-interval 10')
    config_text.append('set connection-options hold-time 30')
    config_text.append('set enable yes')
    config_text.append('{}'.format(local_address[1]))
    config_text.append('set local-address interface tunnel.{}'.format(tunnel_Id))
    config_text.append('{}'.format(peer_address[1]))
    config_text.append('top')
    
    # IPSec Tunnel #2

    tunnel_Id+=1
    config_text.append('edit network ike gateway ike-{}-{}'.format(vpn_connection_id,2))
    config_text.append('set protocol ikev1 ike-crypto-profile default exchange-mode main')
    config_text.append('set protocol ikev1 dpd interval 10 retry 3 enable yes')
    config_text.append('{}'.format(pre_shared_key[1]))
    config_text.append('{}'.format(local_address[2]))
    config_text.append('set local-address interface ethernet1/1')
    config_text.append('{}'.format(peer_address[2]))
    config_text.append('top')

    config_text.append('edit network interface tunnel units tunnel.{}'.format(tunnel_Id))
    config_text.append('{}'.format(tunnel_ip[1]))
    config_text.append('set mtu 1427')
    config_text.append('top')

    config_text.append('set zone VPN network layer3 tunnel.{}'.format(tunnel_Id))
    config_text.append('set network virtual-router default interface tunnel.{}'.format(tunnel_Id))

    config_text.append('edit network tunnel ipsec ipsec-{}-{}'.format(vpn_connection_id,tunnel_Id))
    config_text.append('set auto-key ipsec-crypto-profile default')
    config_text.append('set auto-key ike-gateway ike-{}-{}'.format(vpn_connection_id,2))
    config_text.append('set tunnel-interface tunnel.{}'.format(tunnel_Id))
    config_text.append('set anti-replay yes')
    config_text.append('top')

    config_text.append('edit network virtual-router default protocol bgp')
    #config_text.append('set router-id {}'.format(local_address[]))
    #config_text.append('set enable yes')
    #config_text.append('{}'.format(local_as[1]))
    config_text.append('edit peer-group {}'.format(peer_group))
    config_text.append('edit peer peer-{}-{}'.format(vpn_connection_id,2))
    config_text.append('{}'.format(peer_as[1]))
    config_text.append('set connection-options keep-alive-interval 10')
    config_text.append('set connection-options hold-time 30')
    config_text.append('set enable yes')
    config_text.append('{}'.format(local_address[3]))
    config_text.append('set local-address interface tunnel.{}'.format(tunnel_Id))
    config_text.append('{}'.format(peer_address[3]))
    config_text.append('top')

    for line in config_text: 
        print(line)
    log.debug("Conversion complete")
    return config_text

#Logic to determine when the prompt has been discovered
def prompt(chan):
    buff = ''
    while not (buff.endswith('% ') or buff.endswith('> ') or buff.endswith('# ')):
        resp = chan.recv(9999)
        buff += resp
        #log.info("response: %s",resp)
    return buff

def pushConfig(ssh, config):
    
    ssh.send('configure\n')
    
    stime = time.time()
    for line in config:
        if line == "WAIT":
            log.debug("Waiting 30 seconds...")
            time.sleep(30)
        else:
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
	
def configureVPN(ip,vpn_connection_id):

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
        tunnelId = getNextTunnelId(connection)
        #vpn_connection_conf = create_paloalto_config(vpn_connection_id,tunnelId)
        #pushConfig(connection,vpn_connection_conf)
        session.close()            
        print("----------------------- configuration done ----------------------------") 

    except paramiko.AuthenticationException:

        print("AuthenticationException")


def main():
    
    # Get command line arguments
    parser = argparse.ArgumentParser(description="Create VPN Connection")
    parser.add_argument('-v', '--verbose', action='count', help="Verbose (-vv for extra verbose)")
    parser.add_argument('-q', '--quiet', action='store_true', help="No output")
    parser.add_argument('node1', help="Palo Node1")
    parser.add_argument('vpn_connection_id_1', help="aws vpn connection id")
    args = parser.parse_args()
    
    palo_node1 = args.node1
    vpn_connection_id_1= args.vpn_connection_id_1
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
    
    configureVPN(palo_node1,vpn_connection_id_1)
    #configureVPN(palo_node2,vpn_connection_id_2)
    

if __name__ == '__main__':
    main()
