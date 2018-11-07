ip=$1
ssh -p 22001 root@$ip 'tee -a /etc/dropbear/authorized_keys' < /home/llwang/.ssh/id_rsa.pub
