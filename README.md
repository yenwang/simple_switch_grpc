# How to run
* step 1. 首先透過make run(細節請參考Makefile及run_exercisy.py)
* step 2. 執行python my_controller.py 啟動controller設定switch pipeline並新增rules到switch上
* step 3. 透過simple_switch_CLI < set_meter.sh (set_meter_drop.sh)去configure ingress_meter_stats array
* step 4. 可以透過simple_switch_CLI < read_meter.sh去確認meter configuration
* step 5. 在mininet中執行h1 bash h1.sh及h2.sh(設定host的arp table)
* step 6. 在mininet中輸入xterm h1 h2啟動h1和h2的terminal
* step 7. 在h2的xterminal中輸入iperf3 -s
* step 8. 在h1的xterminal中輸入iperf3 -c 10.0.1.2 -u -n 100MB
* step 9. 若在step3使用set_meter_drop.sh則可以在s1.log中看到因為meter被drop的packet
