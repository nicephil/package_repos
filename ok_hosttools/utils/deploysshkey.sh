ip=$1
ssh root@$ip 'tee -a /etc/dropbear/authorized_keys' < /home/llwang/.ssh/id_rsa.pub
