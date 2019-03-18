#!/bin/bash

OPENRESTY_PATH="/usr/local/openresty"
# 导入 GPG 密钥：
wget -qO - https://openresty.org/package/pubkey.gpg | sudo apt-key add -
# 安装 add-apt-repository 命令
sudo apt-get -y install software-properties-common
# 添加官方 official APT 仓库：
sudo add-apt-repository -y "deb http://openresty.org/package/ubuntu $(lsb_release -sc) main"
# 更新 APT 索引：
sudo apt-get update

sudo apt install nmap python3-pip openresty -y
echo $OPENRESTY_PATH/nginx/logs
chmod -R 777 $OPENRESTY_PATH/nginx/logs
cp -r ./waf $OPENRESTY_PATH/nginx/
pip3 install -r requests.txt
