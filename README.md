# How to run
p4 switch上meter實作
1. 首先透過make run(細節請參考Makefile及run_exercisy.py)根據topology.json產生對應的mininet topology並使用simple switch
2. 執行python my_controller.py 啟動controller設定switch pipeline並新增rules到switch上
3. 透過simple_switch_CLI < set_meter.sh 去configure ingress_meter_stats array
4. 可以透過simple_switch_CLI < read_meter.sh去確認meter configuration
5. 在mininet中執行h1 bash h1.sh及h2.sh(設定host的arp table)
6. 在mininet中輸入xterm h1 h2啟動h1和h2的terminal
7. 在h2的xterminal中輸入iperf3 -s
8. 在h1的xterminal中輸入iperf3 -c 10.0.1.2 -u -n 100MB
9. 結果取決於設定的rate及burst，可以在s1.log中確認有沒有封包因為meter被drop
