#!/bin/sh
#潮云在线(kai258@vip.qq.com)
alias echo_date="echo 【$(date +%Y年%m月%d日\ %X)】:"
# export KOOLPROXY=/etc/koolproxy
# judgment=$(sed -n '1p' $KOOLPROXY/create_jd.txt)
separated="—————————————————————"
sh_ver="1.0.0"
# coding_rules="https://raw.githubusercontent.com/kai258/KaiAD/master"

restart_kp(){
  /etc/koolproxy >/dev/null 2>&1
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
        user_local=$(sed -n '1p' /etc/adbyby_user.txt |  awk -F' ' '{print $3$4}'  | sed  's/-//g' | sed  's/://g')
        if [ "$user_online" -le "$user_local" ];then
           echo_date "本地自用规则已经最新，无需更新"
           logger -t "【Koolproxy】" -p cron.info "本地自用规则已经最新，无需更新"
           rm_cache
        else
           echo_date "检测到自用规则更新，应用规则中..."
           logger -t "【Koolproxy】" -p cron.info "检测到自用规则更新，应用规则中..."
           cp -f /tmp/user-rules.txt /etc/adbyby_user.txt
           rm_cache;restart_kp
        fi
      fi  
# }