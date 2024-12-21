""" Module to match the every packet information with a all rules, if any rule matches the corresponding actions could be taken """

import doActions
import re
import time

count_ips = {}

class matchRules(doActions.doActions):
   
   def ExtractRuleInfo(self,rule):
   
      """ Function to extact infomation from give rule """
      
      rule_info = {
         'action':None,
         'protocol': None,
         'source_ip': None,
         'destination_ip': None,
         'source_port': None,
         'destination_port': None,
         'flags': None,
         'icode': None,
         'itype': None,
         'payload': None,
         'count': None,
         'seconds': None,
         'track': None,
         'msg': None,
         'sid': None
     }

      rule_parts=rule.split(" ")
      
      rule_info['action'] = rule_parts[0]
      rule_info['protocol'] = rule_parts[1]
      rule_info['source_ip'] = rule_parts[2]
      rule_info['source_port'] = rule_parts[3]
      rule_info['destination_ip'] = rule_parts[5]
      rule_info['destination_port'] = rule_parts[6]
   
      pattern = r'flags:\s*([a-zA-Z]+)'
      match = re.search(pattern,rule)
      if match:
         rule_info['flags'] = match.group(1)  

      pattern = r'icode:\s*(\d+)'
      match = re.search(pattern,rule)
      if match:
         rule_info['icode'] = match.group(1)

      pattern = r'itype:\s*(\d+)'
      match = re.search(pattern,rule)
      if match:
         rule_info['itype'] = match.group(1)

      pattern = r'content:\s*"([^"]+)"'
      match = re.search(pattern,rule)
      if match:
         content = match.group(1)
         rule_info['payload'] = content 
   
      pattern = r'count:\s*(\d+)'           
      match = re.search(pattern, rule)
      if match:
         rule_info['count'] = match.group(1)

      pattern = r'seconds:\s*(\d+)'       
      match = re.search(pattern,rule)
      if match:
         rule_info['seconds'] = match.group(1)

      pattern = r'track:\s*([a-zA-Z_]+)'
      match = re.search(pattern,rule)
      if match:
         rule_info['track'] = match.group(1)

      pattern = r'(?<=msg: ")[^"]+' 
      match = re.search(pattern,rule)
      if match:
         rule_info['msg'] = match.group(0)
   
      pattern=r'(?<=sid: )\d+'
      match = re.search(pattern,rule)
      if match:
         rule_info['sid'] = match.group(0)
   
      pattern = r'flow:\s*(\S+);'
      match = re.search(pattern,rule)
      if match:
         rule_info['flow'] = match.group(1)
   
      return rule_info
   

   def MatchRules(self,packet_info):
   
      """ Function to perform a match of packet info with rule info if rule matched the corresponding action could be taken """

      file = open("customRules.txt",mode="r")

      while True:
         
         rule = file.readline()   
         if rule:
         
            rule_info = self.ExtractRuleInfo(rule)
               
            if rule_info['protocol'] != packet_info['protocol']:
               continue
            
            if rule_info['source_ip'] != packet_info['source_ip'] and rule_info['source_ip'] != 'any':
               continue
            
            if rule_info['source_port'] != str(packet_info['source_port']) and rule_info['source_port'] != 'any':
               continue
            
            if rule_info['destination_ip'] != packet_info['destination_ip'] and rule_info['destination_ip'] != 'any':
               continue
            
            if rule_info['destination_port'] != str(packet_info['destination_port']) and rule_info['destination_port'] != 'any':
               continue
         
            if packet_info['payload'] is None and rule_info['payload'] is not None:
               continue
          
            elif packet_info['payload'] is not None and rule_info['payload'] is not None:
               
               if isinstance(packet_info['payload'], str) and isinstance(rule_info['payload'], str):
                  if rule_info['payload'] not in packet_info['payload']:
                     continue
            
            if rule_info['flags'] != None:
               if rule_info['flags'] not in packet_info['flags']:
                  continue
         
            if rule_info['icode'] != None:
               if  rule_info['icode'] != packet_info['icode']:
                  continue
         

            if rule_info['itype'] != None:
               if rule_info['itype'] != packet_info['itype']:
                  continue

            action_by_thresold = False
            
            if rule_info['count'] != None:
               
               current_time = int(time.time())
         
               if rule_info['track'] == "by_dst":

                  if packet_info['destination_ip'] not in count_ips:

                     count_ips[packet_info['destination_ip']] = [1,current_time]     
   
                  else:
                  
                     count_ips[packet_info['destination_ip']][0] += 1
                     count_info = count_ips[packet_info['destination_ip']]
                  
                     if int(count_info[0]) >= int(rule_info['count']) and (current_time - count_info[1]) < int(rule_info['seconds']):
                        count_ips.pop(packet_info['destination_ip'])
                        action_by_thresold = True
                        result = self.FindAction(rule_info,packet_info)
                        if result == 1:
                           return 1
                        else: 
                           return 0
            
               if rule_info['track'] == "by_src":
                  
                  if packet_info['source_ip'] not in count_ips:
                     count_ips[packet_info['source_ip']] = [1,current_time]          
                  else:
                  
                     count_ips[packet_info['source_ip']][0] += 1
                     count_info = count_ips[packet_info['source_ip']]
            
                     if int(count_info[0]) >= int(rule_info['count']) and (current_time-count_info[1]) < int(rule_info['seconds']):
                        count_ips.pop(packet_info['source_ip'])
                        action_by_thresold = True
                        result = self.FindAction(rule_info,packet_info)
                        if result == 1:
                           return 1
                        else:
                           return 0 
                        
               else:
                  pass
            if action_by_thresold == False and rule_info['count'] == None:
               result = self.FindAction(rule_info,packet_info)
               if result == 1:
                  return 1
               else:
                  return 0
               
         else:
            break    
      return 0
