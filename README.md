## Network Intrusion Prevention System

### Description

+ Developed a Network Intrusion Prevention System (NIPS) in Python, leveraging iptables for dynamic packet filtering, using Scapy for real-time packet inspection, and implementing custom rules for threat detection.
+ Crafted 10+ custom rules and tested them to detect ICMP flood, UDP flood, TCP SYN flood, SQL injection, XSS, HTTP directory traversal, and suspicious IP blocking, etc.
+ Implemented logging for security events and network activity, enabling detailed analysis and future threat mitigation.

### Project Structure

+ ```main.py``` : Entry point; coordinates all modules.
+ ```processPackets.py``` : Queue and Processes raw network packets to extract key attributes.
+ ```matchRules.py``` : Matches packet attributes with Custom rules and triggers actions via ```doActions.py```.
+ ```doActions.py``` : Executes corresponding actions based on detected threats.
+ ```storeLogs.py``` : Stores appropriate logs for various attacks.
+ ```customRules.txt``` : Contains custom rules for threat detection.
+ ```attackLogs.csv``` : Stores logs of detected attacks.
+ ```trafficLogs.csv``` : Stores logs of analyzed network traffic.

### Installation
 
```sh
  sudo apt install iptables
  pip install scapy
  pip install NetfilterQueue
  git clone https://github.com/Kr1shnam00rth1/NetWonIPS/
  cd NetWonIPS
  sudo python3 main.py
```
+ Feel free to customize the ```customRules.txt``` file to define the working of IPS.
