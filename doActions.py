""" Module to check and Block IPs based if they matched with corresponding snort rule """

import subprocess
import storeLogs
import time

class doActions(storeLogs.storeLogs):

    def IsIncommingBlocked(self,ip):
    
        """ Function to check does IP already blocked or not in INPUT Tables """ 
        try:
        
            result = subprocess.run(['sudo', 'iptables', '-L', 'INPUT', '-v', '-n'], capture_output=True, text=True, check=True)
            if ip in result.stdout:
                return True
            return False
        except subprocess.CalledProcessError as e:
            print(f"Failed to check iptables rules. Error: {e}")
            return False

    def IsOutgoingBlocked(self,ip):
    
        """ Function to check does IP already blocked or not in the OUTPUT Table """
    
        try:
        
            result = subprocess.run(['sudo', 'iptables', '-L', 'OUTPUT', '-v', '-n'], capture_output=True, text=True, check=True)
            if ip in result.stdout:
                return True
            return False
        except subprocess.CalledProcessError as e:
            print(f"Failed to check iptables rules. Error: {e}")
            return False

    def IncommingIpBlock(self,ip):

        """ Function to Block Incomming Traffic """
    
        if self.IsIncommingBlocked(ip):
            return 0
        else:
            try:
                subprocess.run(['sudo', 'iptables', '-I', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
                print(f"Blocked {ip} Check Logs !!")
                return 1
            
            except subprocess.CalledProcessError as e:
                print(f"Failed to block IP address {ip}. Error: {e}")


    def OutgoingIpBlock(self,ip):

        """ Function to Block Outgoing Traffic """
    
        if self.IsOutgoingBlocked(ip):
            return 0
        else:
            try:
                subprocess.run(['sudo', 'iptables', '-I', 'OUTPUT', '-d', ip, '-j', 'DROP'], check=True)
                print(f"Blocked {ip} Check Logs !!")
                return 1
            
            except subprocess.CalledProcessError as e:
                print(f"Failed to block IP address {ip}. Error: {e}")

    def FindAction(self,rule_info,packet_info):

        """ Function to determine required action and execute it. """
    
        if rule_info['action'] == "alert":

            self.AttackLogs(rule_info['msg'],rule_info['sid'],rule_info['action'])
            print(f"Alert Generate for packet from {packet_info['source_ip']} Check Logs !!")
            return 0

        elif rule_info['action'] == "block":
        
            if rule_info['flow'] == "to_server":
                result = self.IncommingIpBlock(packet_info['source_ip'])
                if result == 1:
                    self.AttackLogs(rule_info['msg'],rule_info['sid'],rule_info['action'])
                              
            elif rule_info['flow'] == "to_client":
                result = self.OutgoingIpBlock(packet_info['destination_ip'])
                if result == 1:
                    self.AttackLogs(rule_info['msg'],rule_info['sid'],rule_info['action'])
            return 0

        elif rule_info['action'] == "drop":

            self.AttackLogs(rule_info['msg'],rule_info['sid'],rule_info['action'])
            print(f"Dropped packet from {packet_info['source_ip']} Check Logs !!")
            return 1

