#!/bin/sh
#潮云在线(kai258@vip.qq.com)
alias echo_date="echo 【$(date +%Y年%m月%d日\ %X)】:"
# export KOOLPROXY=/etc/storage/koolproxy
# judgment=$(sed -n '1p' $KOOLPROXY/create_jd.txt)
separated="—————————————————————"
sh_ver="1.0.0"
# coding_rules="https://raw.githubusercontent.com/kai258/KaiAD/master"

restart_kp(){
  /etc/storage/koolproxy >/dev/null 2>&1
}
rm_cache(){
  cd /tmp
  rm -f installed.txt user-rules.txt
}
# user_rules(){  
    wget --no-check-certificate -O /tmp/user-rules.txt https://raw.githubusercontent.com/kai258/KaiAD/master/user-rules.txt
      if [ "$?"x != "0"x ]; then
        echo_date "下载自用规则失败"
        logger -t "【Koolproxy】" -p cron.error "下载自用规则失败"
        rm_cache
      else          
        user_online=$(sed -n '1p' /tmp/user-rules.txt |  awk -F' ' '{print $3$4}'  | sed  's/-//g' | sed  's/://g')
        user_local=$(sed -n '1p' /etc/storage/koolproxy/data/rules/user.txt |  awk -F' ' '{print $3$4}'  | sed  's/-//g' | sed  's/://g')
        if [ "$user_online" -le "$user_local" ];then
           echo_date "本地自用规则已经最新，无需更新"
           logger -t "【Koolproxy】" -p cron.info "本地自用规则已经最新，无需更新"
           rm_cache
        else
           echo_date "检测到自用规则更新，应用规则中..."
           logger -t "【Koolproxy】" -p cron.info "检测到自用规则更新，应用规则中..."
           cp -f /tmp/user-rules.txt /etc/storage/koolproxy/data/rules/user.txt
           rm_cache;restart_kp
        fi
      fi  
# }
# user_rules(){  
    wget --no-check-certificate -O /tmp/dnsmasq.txt https://raw.githubusercontent.com/kai258/KaiAD/master/dnsmasq.txt
      if [ "$?"x != "0"x ]; then
        echo_date "下载自用规则失败"
        logger -t "【Koolproxy】" -p cron.error "下载自用规则失败"
        rm_cache
      else          
        user_online=$(sed -n '1p' /tmp/dnsmasq.txt |  awk -F' ' '{print $3$4}'  | sed  's/-//g' | sed  's/://g')
        user_local=$(sed -n '1p' /etc/storage/koolproxy/rules_store/dnsmasq.txt |  awk -F' ' '{print $3$4}'  | sed  's/-//g' | sed  's/://g')
        if [ "$user_online" -le "$user_local" ];then
           echo_date "本地自用规则已经最新，无需更新"
           logger -t "【Koolproxy】" -p cron.info "本地自用规则已经最新，无需更新"
           rm_cache
        else
           echo_date "检测到自用规则更新，应用规则中..."
           logger -t "【Koolproxy】" -p cron.info "检测到自用规则更新，应用规则中..."
           cp -f /tmp/dnsmasq.txt /etc/storage/koolproxy/rules_store/dnsmasq.txt
           rm_cache;restart_kp
        fi
      fi  
# }
# user_rules(){  
    wget --no-check-certificate -O /tmp/source.list https://raw.githubusercontent.com/kai258/KaiAD/master/source.list
      if [ "$?"x != "0"x ]; then
        echo_date "下载自用规则失败"
        logger -t "【Koolproxy】" -p cron.error "下载自用规则失败"
        rm_cache
      else          
        user_online=$(sed -n '1p' /tmp/source.list |  awk -F' ' '{print $3$4}'  | sed  's/-//g' | sed  's/://g')
        user_local=$(sed -n '1p' /etc/storage/koolproxy/data/source.list |  awk -F' ' '{print $3$4}'  | sed  's/-//g' | sed  's/://g')
        if [ "$user_online" -le "$user_local" ];then
           echo_date "本地自用规则已经最新，无需更新"
           logger -t "【Koolproxy】" -p cron.info "本地自用规则已经最新，无需更新"
           rm_cache
        else
           echo_date "检测到自用规则更新，应用规则中..."
           logger -t "【Koolproxy】" -p cron.info "检测到自用规则更新，应用规则中..."
           cp -f /tmp/source.list /etc/storage/koolproxy/data/source.list
           rm_cache;restart_kp
        fi
      fi  
# }
