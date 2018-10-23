# simple_switch_grpc
This repository contains my researh on P4
Working Environment(Already support P4 Runtime v1.0.0)
---
+OS: Ubuntu 16.04
+PI: commit 49e23fdc7ed77c187a2d72f459deb6c82d2197e4
+Behavioral-Model: commit f2448b8e3f69328b8fbfc6de8887bd6bb47e8057
+p4c: commit 03a4773596ef662e864cd65662d1601dabf9490e
+mininet: commit 1969669f510a7443f58b27b1640884b06b6867d4
+protobuf: v3.2.0
+grpc: v1.3.2
---
All implementations in this repository have following features:
+ simulated using mininet.
+ using simple_switch_grpc as mininet switch
+ using python controller to manipulate switches
+ written in P4_16
+ using topology.json file to build mininet topology

