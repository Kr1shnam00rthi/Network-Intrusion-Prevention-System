# Network Intrusion Prevention System

Network Intrusion Prevention System (NIPS) with real-time packet inspection, attack detection, custom rule-based mitigation, and detailed logging for analysis.

## Features

+ ```Packet Inspection``` : Inspects network packets in real time to detect and block malicious activities.
+ ```Custom Rules``` : Implements signature-based rules for detecting attacks such as SYN flood, ICMP/UDP floods, SQL injection, XSS, and directory traversal etc.
+ ```Logging``` : Records both attack events and network traffic for monitoring and analysis.
  
## Project Structure

+ ```main.py``` : Entry point; coordinates all modules.
+ ```processPackets.py``` : Queue and Processes raw network packets to extract key attributes.
+ ```matchRules.py``` : Matches packet attributes with Custom rules and triggers actions via ```doActions.py```.
+ ```doActions.py``` : Executes corresponding actions based on detected threats.
+ ```storeLogs.py``` : Stores appropriate logs for various attacks.
+ ```customRules.txt``` : Contains custom rules for threat detection.
+ ```attackLogs.csv``` : Stores logs of detected attacks.
+ ```trafficLogs.csv``` : Stores logs of analyzed network traffic.

## Installation
 
```sh
  sudo apt install iptables
  pip install scapy
  pip install NetfilterQueue
  git clone https://github.com/Kr1shnam00rth1/NetWonIPS/
  cd NetWonIPS
  sudo python3 main.py
```
+ Feel free to customize the ```customRules.txt``` file to define the working of IPS.
