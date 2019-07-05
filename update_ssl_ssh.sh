#!/bin/bash

################################################################################

#                       install ssl and ssh script                             #

################################################################################



#run user is root 

run_user_id=`id -u`

if [ $run_user_id -ne 0 ]; then

  echo this script need to be run as root
  
  exit

fi



#date time now
date_time_now=`date +%Y%m%d%H%M%S`
echo now time is $date_time_now

#system version (telnet service and install openssl-devel or install openssl-libs)

os_version_num=`cat /etc/redhat-release | awk '{for(i=1;i<=NF;i++)if($i ~/[[:digit:]][[:digit:]]*/){print $i}}' | awk -F. '{print $1}'`

echo system_version is $os_version_num


#32 bit or 64 bit
server_long_bit=`getconf LONG_BIT`

echo system arch is $server_long_bit



#telnet service is run 

xinetd_install_state=`rpm -qa  | grep -c xinetd`
telnet_server_install_state=`rpm -qa | grep -c telnet-server`
telnet_install_state=`rpm -qa | grep -c "telnet-[[:digit:]][[:digit:]]*"`
  if [ $xinetd_install_state -eq 0 ]; then
    echo now install xinetd 
    yum install -y xinetd
  fi
  if [ $telnet_server_install_state -eq 0 ]; then
    echo now install telnet-server 
    yum install -y telnet-server
  fi
  if [ $telnet_install_state -eq 0 ]; then
    echo now install telnet 
    yum install -y telnet
  fi
netstat -an | grep -w LISTEN | grep -w 23

telnet_init_state=$?
if [ $telnet_init_state -eq 0 ] ; then

  echo telnet init is on
  
fi



if [ $os_version_num -lt 7 ]
; then
  if [ -f "/etc/xinetd.d/telnet" ];then
    service xinetd status
    xinetd_service_runtime_state=$?
    telnet_service_boot_state=`cat /etc/xinetd.d/telnet | grep disable | awk '{print $3}'`
    echo telnet init config is $telnet_service_boot_state
    if [ "$telnet_service_boot_state" == "yes" ]; then
      sed -i s/disable[[:space:]]*=[[:space:]]yes/disable[[:space:]]*=[[:space:]]no/ /etc/xinetd.d/telnet
    fi
    if [ $xinetd_service_runtime_state -eq 0 ]; then
      service xinetd restart
    else
      service xinetd start
    fi
  fi
else
  xinetd_runtime_state=`systemctl status xinetd.service | grep Active | awk '{print $2}'`
  echo xinetd init is $xinetd_runtime_state
  telnet_runtime_state=`systemctl status telnet.socket | grep Active | awk '{print $2}'`
  echo telnet init is $telnet_runtime_state
  if [ "$xinetd_runtime_state" == "inactive" ]; then
    systemctl start xinetd.service
  fi
  if [ "$telnet_runtime_state" == "inactive" ]; then
    systemctl start telnet.socket
  fi
fi
netstat -an | grep -w LISTEN | grep -w 23

telnet_now_state=$?
if [ $telnet_now_state -eq 0 ] ; then

  echo telnet now is on
  
fi



#selinux set  ploicy is permissive

init_selinux_state=`getenforce`

echo selinux init is $init_selinux_state
if [ "$init_selinux_state" == "Enforcing" ]; then

  setenforce 0

fi


#before install
#ssl path
openssl_init_dir_path=`openssl version -a | grep OPENSSLDIR | awk '{print $2}' |sed s/\"//g`
echo openssl init dir path is $openssl_init_dir_path
#if [ "$openssl_init_dir_path"  ==  "/etc/pki/tls"  ]; then

openssl_init_bin_tmp_path=`which openssl`

if [ -L $openssl_init_bin_tmp_path ] ; then
  openssl_init_bin_last_path=`ls -l $openssl_init_bin_tmp_path | awk -F'->' '{print $2}' | sed s/\\s*//`
else
  openssl_init_bin_last_path=$openssl_init_bin_tmp_path
fi 
echo openssl init bin path is $openssl_init_bin_last_path

if [ "$openssl_init_bin_last_path" == "/usr/bin/openssl" ]; then
   openssl_prefix_path=/usr
   echo openssl prefix path is $openssl_prefix_path
else
   openssl_prefix_path=`echo $openssl_init_bin_last_path | awk -v sslbinpath='' -F/ '{for(i=2;$i!="bin";i++){sslbinpath=sslbinpath"/"$i}{print sslbinpath}}'`
   echo openssl prefix path is $openssl_prefix_path
fi
#ssh path
openssh_init_bin_tmp_path=`which ssh`
if [ -L $openssh_init_bin_tmp_path ] ; then
  openssh_init_bin_last_path=`ls -l $openssh_init_bin_tmp_path | awk -F'->' '{print $2}' | sed s/\\s*//`
else
  openssh_init_bin_last_path=$openssh_init_bin_tmp_path
fi 
echo openssh init bin path is $openssh_init_bin_last_path
if [ "$openssh_init_bin_last_path" == "/usr/bin/openssh" ]; then
   openssh_prefix_path=/usr
   echo openssh prefix path is $openssh_prefix_path
else
   openssh_prefix_path=`echo $openssh_init_bin_last_path | awk -v sshbinpath='' -F/ '{for(i=2;$i!="bin";i++){sshbinpath=sshbinpath"/"$i}{print sshbinpath}}'`
   echo openssh prefix path is $openssh_prefix_path
fi


if [ -L /etc/ssh/sshd_config ]
 ; then
  openssh_sshd_config_file=`ls -l /etc/ssh/sshd_config | awk -F'->' '{print $2}' | sed s/\\s*//`
else
  openssh_sshd_config_file="/etc/ssh/sshd_config"
fi
echo openssh sshd config file path is $openssh_sshd_config_file
if [ -L /etc/ssh/ssh_config ]
 ; then
  openssh_ssh_config_file=`ls -l /etc/ssh/ssh_config | awk -F'->' '{print $2}' | sed s/\\s*//`
else
  openssh_ssh_config_file="/etc/ssh/ssh_config"
fi
echo openssh ssh config file path is $openssh_ssh_config_file

openssh_sysconfig_path=`echo $openssh_sshd_config_file | awk -v sshconfigpath='' -F/ '{for(i=2;$i!="sshd_config";i++){sshconfigpath=sshconfigpath"/"$i}{print sshconfigpath}}'`
echo openssh sysconfig dir path is  $openssh_sysconfig_path










################################################################################

#                          source code update                                  #

################################################################################


ssl_version='openssl-1.1.1c'

ssh_version='openssh-8.0p1'


cd /tmp


#download ssl tar file

#wget ftp://ftp.openssl.org/source/$ssl_version.tar.gz 
#wget ftp://ftp.openssl.org/source/$ssl_version.tar.gz.sha256
#wget ftp://ftp.openssl.org/source/$ssl_version.tar.gz.asc
sha256sum openssl-1.1.1c.tar.gz | awk '{print $1}' | cmp - openssl-1.1.1c.tar.gz.sha256
tmp_sha256_check_ssl=$?
if [ $tmp_sha256_check_ssl -eq 0 ]; then
  echo sha256 check all rigth
else
  echo sha256 check fail
  exit 
fi

#which gpg
#tmp_gnupg_install_state=$?
#if [ $tmp_gnupg_install_state -ne 0 ]; then

#  gnupg2_yum_state=`yum list | grep -c gnupg2`
#  if [ $gnupg2_yum_state -eq 0 ]; then
#    echo now instll gnupg
#    yum install -y gnupg
#  else
#    echo now install gnupg2
#    yum install -y gnupg2
#  fi
#fi


#gpg --verify $ssl_version.tar.gz.asc
#ssl_gpg_check_state=$?
#if [ $ssl_gpg_check_state -ne 0 ]; then
#  gpg --verify $ssl_version.tar.gz.asc 2> ssl_gpg_check_err.txt
#  ssl_key_string=`cat ssl_gpg_check_err.txt | grep RSA | awk '{print $NF}'`
#  gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys $ssl_key_string
#  ssl_gpg_key_download=$?
#  if [ $ssl_gpg_key_download -ne 0 ]; then
#    echo ssl gpg key download fail
#    exit
#  fi
#  gpg --verify $ssl_version.tar.gz.asc
#  ssl_gpg_check_again_state=$?
#  if [ $ssl_gpg_check_again_state -ne 0 ]; then
#    echo ssl tar file gpg check fail
#    exit
#  fi
#fi



#download ssh tar file

#wget http://ftp.jaist.ac.jp/pub/OpenBSD/OpenSSH/portable/$ssh_version.tar.gz
#wget http://ftp.jaist.ac.jp/pub/OpenBSD/OpenSSH/portable/$ssh_version.tar.gz.asc
which gpg
tmp_gnupg_install_state=$?
if [ $tmp_gnupg_install_state -ne 0 ]; then

  gnupg2_yum_state=`yum list | grep -c gnupg2`
  if [ $gnupg2_yum_state -eq 0 ]; then
    echo now instll gnupg
    yum install -y gnupg
  else
    echo now install gnupg2
    yum install -y gnupg2
  fi
fi


#gpg --verify $ssh_version.tar.gz.asc
#ssh_gpg_check_state=$?
#if [ $ssh_gpg_check_state -ne 0 ]; then
#  gpg --verify $ssh_version.tar.gz.asc 2> ssh_gpg_check_err.txt
#  ssh_key_string=`cat ssh_gpg_check_err.txt | grep RSA | awk '{print $NF}'`
#  gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys $ssh_key_string
#  ssh_gpg_key_download=$?
#  if [ $ssh_gpg_key_download -ne 0 ]; then
#    echo ssh gpg key download fail
#    exit
#  fi
#  gpg --verify $ssh_version.tar.gz.asc
#  ssh_gpg_check_again_state=$?
#  if [ $ssh_gpg_check_again_state -ne 0 ]; then
#    echo ssh tar file gpg check fail
#    exit
#  fi
#fi

#gcc need to  be installed

which gcc

tmp_gcc_install_state=$?

if [ $tmp_gcc_install_state -ne 0 ]; then

  echo now instll gcc
  yum install -y gcc
fi



#make need to be installed
make_install_state=`rpm -qa | grep -c make-[[:digit:]][[:digit:]]*`
if [ $make_install_state -eq 0 ]; then

  echo now install make
 /. yum install -y make
fi

#perl need to be installed
perl_install_state=`rpm -qa | grep -c perl-[[:digit:]][[:digit:]]*`
if [ $perl_install_state -eq 0 ]; then

  echo now install perl
  yum install -y perl
fi

#zlib and zlib-devel need to be install

zlib_install_state=`rpm -qa | egrep -c "zlib-[[:digit:]][[:digit:]]*"`

zlib_devel_install_state=`rpm -qa | egrep -c "zlib-devel"`
if [ $zlib_install_state -eq 0 ]; then

  echo now install zlib
  yum install -y zlib
fi
if [ $zlib_devel_install_state -eq 0 ]; then
  echo now install zlib-devel

  yum install -y zlib-devel
fi



#openssl-lib or openssl-devel need to be install

rpm -qa | grep openssl-devel
tmp_openssl_devel=$?

if [ $tmp_openssl_devel -ne 0 ]; then

  echo now install openssl-devel 
  yum install -y openssl-devel
fi

if [ $os_version_num -gt 6 ]; then

  rpm -qa | grep openssl-libs
 
 tmp_openssl_libs=$?

  if [ $tmp_openssl_libs -ne 0 ]; then

       echo now install openssl-libs
       yum install -y  
openssl-libs	
  fi
fi




#backup openssl
mv $openssl_prefix_path/bin/openssl  $openssl_prefix_path/bin/openssl.$date_time_now.bak

mv $openssl_prefix_path/include/openssl  $openssl_prefix_path/include/openssl.$date_time_now.old

mkdir -p $openssl_prefix_path/include/openssl
mv $openssl_init_dir_path  $openssl_init_dir_path.$date_time_now.old
mkdir -p $openssl_init_dir_path 


#install openssl

cd /tmp
tar -zxf $ssl_version.tar.gz

cd $ssl_version

./config  shared
  --prefix=$openssl_prefix_path  --openssldir=$openssl_init_dir_path  > /tmp/openssl_install.log
tmp_ssl_1=$?

if [ $tmp_ssl_1 -ne 0 ]; then

  echo configure ssl execute fail
  
  exit

fi

#make depend


make  >> /tmp/openssl_install.log
tmp_ssl_2=$?

if [ $tmp_ssl_2 -ne 0 ]; then

  echo make ssl execute fail
  
  exit

fi 

#make test

make install  >> /tmp/openssl_install.log

tmp_ssl_3=$?

if [ $tmp_ssl_3 -ne 0 ]; then

  echo make install ssl  execute fail
  
  exit

fi



#after install

#mv /usr/bin/openssl  /usr/bin/openssl.$date_time_now.bak

#mv /usr/include/openssl  /usr/include/openssl.$date_time_now.old

#ln -s /usr/local/ssl/bin/openssl  /usr/bin/openssl

#ln -s /usr/local/ssl/include/openssl  /usr/include/openssl

#echo "export PATH=/usr/local/ssl/bin:$PATH" >> /etc/profile

#echo /usr/local/ssl/lib  >>  /etc/ld.so.conf

#ldconfig

#source /etc/profile




#option packet
pam_devel_install_state=`rpm -qa | grep -c pam-devel `
if [ $pam_devel_install_state -eq 0 ]; then
  echo now install pam-devel
  yum install -y pam-devel
fi
krb5_devel_install_state=`rpm -qa | grep -c krb5-devel` 
if [ $krb5_devel_install_state -eq 0 ]; then
  echo now install krb5-devel
  yum install -y krb5-devel
fi

#restore config file 
mv  $openssl_init_dir_path/openssl.cnf $openssl_init_dir_path/openssl.cnf.$date_time_now.bak
cp -a $openssl_init_dir_path.$date_time_now.old/openssl.cnf $openssl_init_dir_path

#backup ssh
mv $openssh_sysconfig_path   $openssh_sysconfig_path.$date_time_now.old
mkdir -p $openssh_sysconfig_path



#install openssh
cd /tmp

tar -zxf $ssh_version.tar.gz

cd $ssh_version

ssh_option_function_string="--with-kerberos5 --with-md5-passwords"
if [ -f /etc/pam.d/sshd ]; then
  ssh_option_function_string="--with-pam "$ssh_option_function_string
else
  ssh_option_function_string="--without-pam "$ssh_option_function_string
fi

if [ $server_long_bit -eq 64 ]; then
./configure  --prefix=$openssh_prefix_path --sysconfdir=$openssh_sysconfig_path --with-ssl-dir=$openssl_prefix_path/lib64
 $ssh_option_function_string  > /tmp/openssh_install.log
else
./configure  --prefix=$openssh_prefix_path --sysconfdir=$openssh_sysconfig_path --with-ssl-dir=$openssl_prefix_path/lib
 $ssh_option_function_string  > /tmp/openssh_install.log
fi

tmp_ssh_1=$?

if [ $tmp_ssh_1 -ne 0 ]; then

  echo configure ssh execute fail

  exit

fi

make  >> /tmp/openssh_install.log  

tmp_ssh_2=$?

if [ $tmp_ssh_2 -ne 0 ]; then

  echo make ssh execute fail

  exit

fi 

#make test

make install  >> /tmp/openssh_install.log 

tmp_ssh_3=$?

if [ $tmp_ssh_3 -ne 0 ]; then

  echo make install ssh  execute fail
  
exit

fi


#restore telnet state
if [ $xinetd_install_state -eq 0 ]; then
  if  [ $os_version_num -lt 7 ]
; then
    service xinetd stop
    chkconfig xinetd off
  else
    systemctl stop telnet.socket
    systemctl disable telnet.socket
    systemctl stop xinetd.service
    systemctl disable  xinetd.service 
  fi

else
  if  [ $os_version_num -lt 7 ]
; then
    if [ $xinetd_service_runtime_state -eq 3 ]; then
      service xinetd stop
#     chkconfig xinetd off
    elif [ $xinetd_service_runtime_state -eq 0 ] && [ $telnet_init_state -ne 0 ] ;then
      if [ "$telnet_service_boot_state" == "yes" ]; then
          sed -i s/disable[[:space:]]*=[[:space:]]no/disable[[:space:]]*=[[:space:]]yes/ /etc/xinetd.d/telnet
          service xinetd restart
      fi
    else
       echo telnet is on at all
    fi
  else
    if [ "$xinetd_runtime_state" == "inactive" ]; then
      systemctl stop xinetd.service
#     systemctl disable  xinetd.service
    elif [ "$xinetd_runtime_state" == "active" ] && [ $telnet_init_state -ne 0 ] ;then
      systemctl stop telnet.socket
    else
       echo telnet is on at all
    fi

  fi
fi

#restore ssh config file
mv $openssh_sshd_config_file $openssh_sshd_config_file.$date_time_now.bak
mv $openssh_ssh_config_file $openssh_ssh_config_file.$date_time_now.bak
cp -a $openssh_sysconfig_path.$date_time_now.old/sshd_config $openssh_sysconfig_path/sshd_config
cp -a $openssh_sysconfig_path.$date_time_now.old/ssh_config $openssh_sysconfig_path/ssh_config
mv $openssh_sysconfig_path/ssh_host_rsa_key  $openssh_sysconfig_path/ssh_host_rsa_key.$date_time_now.bak
cp -a $openssh_sysconfig_path.$date_time_now.old/ssh_host_rsa_key  $openssh_sysconfig_path/ssh_host_rsa_key

#restart sshd service and show ssl and ssh version
#ldconfig

if  [ $os_version_num -lt 7 ]
; then
  cp -a $openssh_sysconfig_path.$date_time_now.old/ssh_host_key* $openssh_sysconfig_path/
  service sshd restart
  chkconfig sshd on
else
  chmod 0600 $openssh_sysconfig_path/ssh_host_rsa_key
  chmod 0600 $openssh_sysconfig_path/ssh_host_ecdsa_key
  systemctl restart sshd.service
  systemctl enable  sshd.service 
fi

if [ "$init_selinux_state" == "Enforcing" ]; then

  setenforce 1
fi

openssl version -a
ssh -V

