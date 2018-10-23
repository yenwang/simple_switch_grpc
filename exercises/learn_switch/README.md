# Implementing layer2 learning_switch  
---
## Introduction ##  

###### The objective of this implementation is to program a layer2 learning switch using P4_16 as well as to write a python controller which is responsible for dealing with Packet-In event sent from switch.   
###### If you are interested, there are some comments in both learn_switch.p4 and mycontroller.py. 
---
## How to Run ##
1. Open a shell and type make run  
2. Open another shell and run python mycontroller.py.  
3. In mininet prompt type pingall, then you can see all icmp/arp packets are well forwarded.  
---
## Experiment Topology ##
In this implementation, there are 4 hosts connected to a switch.  
---
## Notice ##
I assume that: 
1. The arp table in every host is initially empty, so controller can learn the mapping of hosts' MAC and port connects to switch. 
2. The controller already knows that switch is connected to 4 hosts. (for multicast use)  
---
## Questions ##
I am curious about if there is any mechanism for my controller to request port status from switch using P4 Runtime.  
If there is such a mechanism, then my controller can configure the PRE dynamically.
(In OpenFlow, API "PortStatusRequest" can request the port status from switch.)  
I have studied the p4runtime.proto file, but It seems that there is no such rpc?
