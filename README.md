# xVpn
作者：jxt-110@qq.com


00 简介
xVpn是一个基于ssl的多用户vpn实现，包含客户端和服务端程序，基于linux平台。
源码中的ca_cert目录，已经包含测试用的CA证书、xVpn服务器端和客户端证书。
也可以指定自己的数字证书。


01 依赖
编译时，依赖于openssl和tun驱动，应确保已安装上述依赖。
For Ubuntu-16.04：
	apt-get install libssl-dev


02 编译
进入源码根目录：
	make
清楚编译：
	make clean


03 运行
vpn server端：
	$ cd server
	$ ./xVpn --port=443 --CAfile=../ca_cert/cacert.pem --cert=../ca_cert/xvpnserver.crt --key=../ca_cert/xvpnserver.pem
vpn client端：
	$ cd client
	$ ./xVpnClient --vpn=192.168.132.0 --vpnserver=192.168.56.114 --serverport=443 --CAfile=../ca_cert/cacert.pem --cert=../ca_cert/xvpnusr1.crt --key=../ca_cert/xvpnusr1.pem


04 Todo
