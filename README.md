## Network Intrusion Prevention System

### Description


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
