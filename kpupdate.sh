#!/bin/sh
#潮云在线(kai258@vip.qq.com)
alias echo_date="echo 【$(date +%Y年%m月%d日\ %X)】:"
# export KOOLPROXY=/etc/storage/koolproxy
# judgment=$(sed -n '1p' $KOOLPROXY/create_jd.txt)
separated="—————————————————————"
sh_ver="1.0.0"
# coding_rules="https://raw.githubusercontent.com/kai258/KaiAD/master"

# rules_dir(){ 
    dir="/etc/storage/koolproxy/rules_store"
      if [ ! -d "$dir" ];then
        mkdir $dir
        echo "创建成功"
      else
        echo "不需要创建"
      fi
# }

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
# dnsmsaq(){  
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
# source(){  
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
# koolproxy(){  
    wget --no-check-certificate -O /tmp/koolproxy.txt https://raw.githubusercontent.com/kai258/KaiAD/master/koolproxy.txt
      if [ "$?"x != "0"x ]; then
        echo_date "下载自用规则失败"
        logger -t "【Koolproxy】" -p cron.error "下载自用规则失败"
        rm_cache
      else          
        user_online=$(sed -n '1p' /tmp/koolproxy.txt |  awk -F' ' '{print $3$4}'  | sed  's/-//g' | sed  's/://g')
        user_local=$(sed -n '1p' /etc/storage/koolproxy/data/rules/koolproxy.txt |  awk -F' ' '{print $3$4}'  | sed  's/-//g' | sed  's/://g')
        if [ "$user_online" -le "$user_local" ];then
           echo_date "本地自用规则已经最新，无需更新"
           logger -t "【Koolproxy】" -p cron.info "本地自用规则已经最新，无需更新"
           rm_cache
        else
           echo_date "检测到自用规则更新，应用规则中..."
           logger -t "【Koolproxy】" -p cron.info "检测到自用规则更新，应用规则中..."
           cp -f /tmp/koolproxy.txt /etc/storage/koolproxy/data/rules/koolproxy.txt
           rm_cache;restart_kp
        fi
      fi  
# }
# daily(){  
    wget --no-check-certificate -O /tmp/daily.txt https://raw.githubusercontent.com/kai258/KaiAD/master/daily.txt
      if [ "$?"x != "0"x ]; then
        echo_date "下载自用规则失败"
        logger -t "【Koolproxy】" -p cron.error "下载自用规则失败"
        rm_cache
      else          
        user_online=$(sed -n '1p' /tmp/daily.txt |  awk -F' ' '{print $3$4}'  | sed  's/-//g' | sed  's/://g')
        user_local=$(sed -n '1p' /etc/storage/koolproxy/data/rules/daily.txt |  awk -F' ' '{print $3$4}'  | sed  's/-//g' | sed  's/://g')
        if [ "$user_online" -le "$user_local" ];then
           echo_date "本地自用规则已经最新，无需更新"
           logger -t "【Koolproxy】" -p cron.info "本地自用规则已经最新，无需更新"
           rm_cache
        else
           echo_date "检测到自用规则更新，应用规则中..."
           logger -t "【Koolproxy】" -p cron.info "检测到自用规则更新，应用规则中..."
           cp -f /tmp/daily.txt /etc/storage/koolproxy/data/rules/daily.txt
           rm_cache;restart_kp
        fi
      fi  
# }
# kp(){  
    wget --no-check-certificate -O /tmp/kp.dat https://raw.githubusercontent.com/user1121114685/koolproxyR/master/koolproxyR/koolproxyR/data/rules/kp.dat
      if [ "$?"x != "0"x ]; then
        echo_date "下载自用规则失败"
        logger -t "【Koolproxy】" -p cron.error "下载自用规则失败"
        rm_cache
      else          
        user_online=$(sed -n '1p' /tmp/kp.dat |  awk -F' ' '{print $3$4}'  | sed  's/-//g' | sed  's/://g')
        user_local=$(sed -n '1p' /etc/storage/koolproxy/data/rules/kp.dat |  awk -F' ' '{print $3$4}'  | sed  's/-//g' | sed  's/://g')
        if [ "$user_online" -le "$user_local" ];then
           echo_date "本地自用规则已经最新，无需更新"
           logger -t "【Koolproxy】" -p cron.info "本地自用规则已经最新，无需更新"
           rm_cache
        else
           echo_date "检测到自用规则更新，应用规则中..."
           logger -t "【Koolproxy】" -p cron.info "检测到自用规则更新，应用规则中..."
           cp -f /tmp/kp.dat /etc/storage/koolproxy/data/rules/kp.dat
           rm_cache;restart_kp
        fi
      fi  
# }
