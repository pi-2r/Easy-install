#!/bin/bash

cluster_name="Zen"
node_name="Node_1"
host="['127.0.0.1']"
ssh_port="22"
your_email="your_mail"

java_url="http://download.oracle.com/otn-pub/java/jdk/8u25-b17/jdk-8u25-linux-x64.tar.gz"
es_url="https://download.elasticsearch.org/elasticsearch/elasticsearch/elasticsearch-1.5.0.deb" 


if [[ $EUID -ne 0 ]]; then
	echo -e "\033[31m[-] This script must be run as root. \033[0m"
	exit 1
fi

#----------- Vérification de parametre --------------
if [ -z $1 ]
then
	echo -e "\033[31m [-] Error:  you must specify an argument.  \033[0m"
	echo -e "\033[31m launch ./full_launcher.sh showme in order to more information \033[0m"
	exit 1
fi
#------------- fin Vérification ---------------------

#------------- Help ---------------------------------
if [ $1 == "showme" ]
then
    echo -e "\033[1;36m[+] How to run the script: ./setup.sh arg \033[0m"
    echo -e "\033[1;36m :arg web : web option (install Apache, PHP, and all the dependencies) \033[0m"
    echo -e "\033[1;36m :arg bdd : BDD option (install mysql, phpmyamdin, and all the dependencies) \033[0m"
    echo -e "\033[1;36m :arg scrapy : scrapy option (install python, scrapy, and all the dependencies) \033[0m"
    echo -e "\033[1;36m :arg es : ES option (install java, ElasticSearch, and all the dependencies) \033[0m"
    echo -e "\033[1;36m :arg s3cmd : s3cmd option (install the latest version of s3cmd tool) 033[0m"
    echo -e "\033[1;36m :arg sec : security option (install the latest version of s3cmd tool) 033[0m"
    echo -e "\033[1;36m \nexample: sudo ./setup.sh web \033[0m"
    exit 1
fi
#--------------End Help -----------------------------

        
echo -e "\033[32m Which OS ?\033[0m"
if [ -d /var/lib/gconf/debian.defaults ]
then
    echo -e "\033[1;36m [+] Ubuntu/Debian \033[0m"
else
   echo -e "\033[31m [-] Error: OS is not Ubuntu/Debian  \033[0m"
   exit 1
fi
#------------------------  Appel du fichier de config serveur  --------------------

function sedeasy {
sed -i "s/$(echo $1 | sed -e 's/\([[\/.*]\|\]\)/\\&/g')/$(echo $2 | sed -e 's/[\/&]/\\&/g')/g" $3
}

apt-get update
#apt-get upgrade -y

#----------------------Install PHP + APACHE2 ------------------------------------------------
if [ $1 = "web" ]
then
	echo -e "\033[32m[+] Install Apache2 \033[0m"
	apt-get -y install apache2 apache2-utils

	echo -e "\033[32m[+] Install and Configure PHP5 \033[0m"
	apt-get -y install libapache2-mod-auth-mysql php5-mcrypt php5-imagick php5-gd php5-cli php5-sqlite php5-curl php5-imap
	echo -e "\033[32m[+]Change chmod on html \033[0m"
	find /var/www/html \( -type f -execdir chmod 644 {} \; \) -o \( -type d -execdir chmod 755 {} \; \)
	echo -e "\033[32m[+] PHP hardening \033[0m"
	sedeasy "disable_functions = pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority," "disable_functions = pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,exec, system, shell_exec,passthru," /etc/php5/apache2/php.ini 
	sedeasy "expose_php = On" "expose_php = Off" /etc/php5/apache2/php.ini
	sedeasy "display_errors = On" "display_errors = Off" /etc/php5/apache2/php.ini
	sedeasy "track_errors = On" "track_errors = Off" /etc/php5/apache2/php.ini
	sedeasy "html_errors = On" "html_errors = Off" /etc/php5/apache2/php.ini

	echo -e "\033[32m[+] Apache hardening \033[0m"
	sedeasy "ServerTokens OS" "ServerTokens Prod" /etc/apache2/conf-enabled/security.conf
	sedeasy "ServerSignature On" "ServerSignature Off" /etc/apache2/conf-enabled/security.conf
	sedeasy "TraceEnable On" "TraceEnable Off" /etc/apache2/conf-enabled/security.conf
	echo "Header unset ETag" >> /etc/apache2/conf-enabled/security.conf
	echo "FileETag None" >> /etc/apache2/conf-enabled/security.conf

	ln -s /etc/apache2/mods-available/headers.load /etc/apache2/mods-enabled/headers.load

	echo -e "\033[32m[+]Restart Apache2 \033[0m"
	service apache2 restart

	echo -e "\033[32m[+]Install and configure ModSecurity \033[0m"
	apt-get install -y libapache2-mod-security2
	mv /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
	sedeasy "SecRuleEngine DetectionOnly" "SecRuleEngine On" /etc/modsecurity/modsecurity.conf

	echo -e "\033[32m[+] Open Web Application Security Project Core Rule  \033[0m"
	cd /tmp
	wget https://github.com/SpiderLabs/owasp-modsecurity-crs/archive/master.zip
	apt-get install -y zip
	unzip master.zip
	cp -r owasp-modsecurity-crs-master/* /etc/modsecurity/
	mv /etc/modsecurity/modsecurity_crs_10_setup.conf.example /etc/modsecurity/modsecurity_crs_10_setup.conf
	ls /etc/modsecurity/base_rules | xargs -I {} ln -s /etc/modsecurity/base_rules/{} /etc/modsecurity/activated_rules/{}
	ls /etc/modsecurity/optional_rules | xargs -I {} ln -s /etc/modsecurity/optional_rules/{} /etc/modsecurity/activated_rules/{}
	rm master.zip

	#sedeasy "</IfModule>" '</IfModule> Include "/etc/modsecurity/activated_rules/*.conf"' /etc/apache2/mods-available/security2.conf

	echo -e "\033[32m[+]  Install and configure mod_evasive \033[0m"
	apt-get install -y libapache2-mod-evasive
	sedeasy "#DOSHashTableSize" "#DOSHashTableSize" /etc/apache2/mods-available/evasive.conf
	sedeasy "#DOSPageCount" "DOSPageCount" /etc/apache2/mods-available/evasive.conf
	sedeasy "#DOSSiteCount" "DOSSiteCount" /etc/apache2/mods-available/evasive.conf
	sedeasy "#DOSPageInterval" "DOSPageInterval" /etc/apache2/mods-available/evasive.conf
	sedeasy "#DOSSiteInterval" "DOSSiteInterval" /etc/apache2/mods-available/evasive.conf
	sedeasy "#DOSBlockingPeriod" "DOSBlockingPeriod" /etc/apache2/mods-available/evasive.conf
	sedeasy "#DOSEmailNotify" "DOSEmailNotify" /etc/apache2/mods-available/evasive.conf
	sedeasy "you@yourdomain.com" $email /etc/apache2/mods-available/evasive.conf
	sedeasy "#DOSLogDir" "DOSLogDir" /etc/apache2/mods-available/evasive.conf

	ln -s /etc/apache2/mods-available/evasive.conf /etc/apache2/mods-enabled/evasive.conf
	service apache2 restart

	echo -e "\033[32m[+]  Install HTTPS \033[0m"
	apt-get install -y openssl
	a2enmod ssl
	service apache2 restart
	mkdir /etc/apache2/ssl
	openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/apache2/ssl/apache.key -out /etc/apache2/ssl/apache.crt
	chmod o-rw /etc/apache2/ssl
	cp /etc/apache2/sites-available/default-ssl.conf /etc/apache2/sites-available/save_default-ssl.conf
	rm /etc/apache2/sites-available/default-ssl.conf
	echo '<IfModule mod_ssl.c>
    <VirtualHost _default_:443>
        ServerAdmin admin@example.com
        ServerName your_domain.com
        ServerAlias www.your_domain.com
        DocumentRoot /var/www/html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
        SSLEngine on
        SSLCertificateFile /etc/apache2/ssl/apache.crt
        SSLCertificateKeyFile /etc/apache2/ssl/apache.key
        <FilesMatch "\.(cgi|shtml|phtml|php)$">
                        SSLOptions +StdEnvVars
        </FilesMatch>
        <Directory /usr/lib/cgi-bin>
                        SSLOptions +StdEnvVars
        </Directory>
        BrowserMatch "MSIE [2-6]" \
                        nokeepalive ssl-unclean-shutdown \
                        downgrade-1.0 force-response-1.0
        BrowserMatch "MSIE [17-9]" ssl-unclean-shutdown
    </VirtualHost>
</IfModule>' >> /etc/apache2/sites-available/default-ssl.conf
service apache2 restart
fi
#----------------------Ending PHP + APACHE2 -------------------------------------------------


#----------------------Install MYSQL --------------------------------------------------------
if [ $1 = "bdd" ]
then
	echo -e "\033[32m[+] Install and Configure MySQL Server \033[0m"
	apt-get -y install mysql-server libapache2-mod-auth-mysql php5-mysql apache2-utils apache2 mysql-client

	echo -e "\033[32m[+] mysql_secure_installation \033[0m"
	mysql_secure_installation


	echo -e "\033[32m[+] Install Phpmyadmin \033[0m"
	apt-get -y install phpmyadmin
	ln -s /usr/share/phpmyadmin /var/www/html/
fi
#----------------------Ending Mysql ---------------------------------------------------------


#----------------------Install Python & Scrapy -------------------------------------------------
if [ $1 = "scrapy" ]
then
	echo -e "\033[32m[+] Install Python \033[0m"
	apt-get install -y python2.7 python-pip python-dev build-essential libreadline-gplv2-dev libncursesw5-dev libssl-dev libsqlite3-dev tk-dev libgdbm-dev libc6-dev libbz2-dev libffi-dev libxslt-dev libxml2-dev

	echo -e "\033[32m[+] Install Scrapy \033[0m"
	apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 627220E7
	echo 'deb http://archive.scrapy.org/ubuntu scrapy main' | tee /etc/apt/sources.list.d/scrapy.list
	apt-get update && apt-get install -y scrapy-0.24

	echo -e "\033[32m[+] Install elasticsearch, simplejson, requests \033[0m"
	pip install lxml
	pip install elasticsearch
	pip install simplejson
	pip install requests
fi
#----------------------Ending Python & Scrapy -------------------------------------------------

#----------------------Install ElasticSearch  -------------------------------------------------
if [ $1 = "es" ]
then
echo -e "\033[32m[+] Install Java \033[0m"
echo -e "\033[32m[+] Downloading of JDK \033[0m"
COOKIE="gpw_e24=x; oraclelicense=accept-securebackup-cookie"
wget --header="Cookie: $COOKIE" $java_url
echo -e "\033[32m[+] Looking for JDK archive...\033[0m"
VERSION=`ls jdk-*-linux-*.tar.gz 2>/dev/null | awk -F '-' '{print $2}' | awk -F 'u' '{print $1}' | sort -n | tail -1`
UPDATE=`ls jdk-$VERSION*-linux-*.tar.gz 2>/dev/null | awk -F '-' '{print $2}' | awk -F 'u' '{print $2}' | sort -n | tail -1`
[ ! -z $UPDATE ] && UPDATE_SUFFIX="u$UPDATE"
LATEST_JDK_ARCHIVE=`ls jdk-$VERSION$UPDATE_SUFFIX-linux-*.tar.gz 2>/dev/null | sort | tail -1`
if [ -z "$LATEST_JDK_ARCHIVE" ] || [ -z "$VERSION" ]; then
echo -e "\033[31m[-]Archive with JDK wasn't found. It should be in the current directory.\033[0m"
exit 1
fi
echo -e "\033[32m[+] Found archive: $LATEST_JDK_ARCHIVE \033[0m"
echo -e "\033[32m[+] Version: $VERSION \033[0m"
[ ! -z $UPDATE ] && echo "Update: $UPDATE"
INSTALL_DIR=/usr/lib/jvm
JDK_DIR=$INSTALL_DIR/java-$VERSION-oracle
echo -e "\033[32m[+] Extracting archive... \033[0m"
tar -xzf $LATEST_JDK_ARCHIVE
if [ $? -ne 0 ]; then
echo -e "\033[31m[-] Error while extraction archive.\033[0m"
exit 1
fi
ARCHIVE_DIR="jdk1.$VERSION.0"
if [ ! -z $UPDATE ]; then
ARCHIVE_DIR=$ARCHIVE_DIR"_"`printf "%02d" $UPDATE`
fi
if [ ! -d $ARCHIVE_DIR ]; then
echo -e "\033[31m[-] Unexpected archive content (No $ARCHIVE_DIR directory).\033[0m"
exit 1
fi
echo -e "\033[32m[+] Moving content to installation directory...\033[0m"
[ ! -e $INSTALL_DIR ] && mkdir -p $INSTALL_DIR
[ -e $INSTALL_DIR/$ARCHIVE_DIR ] && rm -r $INSTALL_DIR/$ARCHIVE_DIR/
[ -e $JDK_DIR ] && rm $JDK_DIR
mv $ARCHIVE_DIR/ $INSTALL_DIR
ln -sf $INSTALL_DIR/$ARCHIVE_DIR/ $JDK_DIR
ln -sf $INSTALL_DIR/$ARCHIVE_DIR/ $INSTALL_DIR/default-java
echo -e "\033[32m[+] Updating alternatives...\033[0m"
gzip -9 $JDK_DIR/man/man1/*.1 >/dev/null 2>&1 &
LATEST=$((`update-alternatives --query java|grep Priority:|awk '{print $2}'|sort -n|tail -1`+1));
if [ -d "$JDK_DIR/man/man1" ];then
for f in $JDK_DIR/man/man1/*; do
name=`basename $f .1.gz`;
#some files, like jvisualvm might not be links. Further assume this for corresponding man page
if [ ! -f "/usr/bin/$name" -o -L "/usr/bin/$name" ]; then
if [ ! -f "$JDK_DIR/man/man1/$name.1.gz" ]; then
name=`basename $f .1`; #handle any legacy uncompressed pages
fi
update-alternatives --install /usr/bin/$name $name $JDK_DIR/bin/$name $LATEST \
--slave /usr/share/man/man1/$name.1.gz $name.1.gz $JDK_DIR/man/man1/$name.1.gz
fi
done
#File links without man pages
[ -f $JDK_DIR/bin/java_vm ] && update-alternatives --install /usr/bin/java_vm \
java_vm $JDK_DIR/jre/bin/java_vm $LATEST
[ -f $JDK_DIR/bin/jcontrol ] && update-alternatives --install /usr/bin/jcontrol \
jcontrol $JDK_DIR/bin/jcontrol $LATEST
else #no man pages available
for f in $JDK_DIR/bin/*; do
name=`basename $f`;
#some files, like jvisualvm might not be links
if [ ! -f "/usr/bin/$name" -o -L "/usr/bin/$name" ]; then
update-alternatives --install /usr/bin/$name $name $JDK_DIR/bin/$name $LATEST
fi
done
fi
echo -e "\033[32m[+] Setting up Mozilla plugin...\033[0m"
#File links that apt-get misses
[ -f $JDK_DIR/bin/libnpjp2.so ] && update-alternatives --install \
/usr/lib/mozilla/plugins/libnpjp2.so libnpjp2.so $JDK_DIR/jre/lib/i386/libnpjp2.so $LATEST
echo -e "\033[32m[+] Setting up env. variable JAVA_HOME... \033[0m"
cat > /etc/profile.d/java-home.sh << "EOF"
export JAVA_HOME="${JDK_DIR}"
export PATH="$JAVA_HOME/bin:$PATH"
EOF
sed -i -e 's,${JDK_DIR},'$JDK_DIR',g' /etc/profile.d/java-home.sh
echo -e "\033[32m[+] Checking version... \033[0m"
java -version
echo -e "\033[32m[+] Done. \033[0m"
echo -e "\033[32m[+] Cleaning ...\033[0m"
rm jdk-8u25-linux-x64.tar.gz > /dev/null

	######################################################
	#                                                    #
	# Install ElasticSearch                              #
	#                                                    #
	######################################################
	echo -e "\033[32m[+] Downloading ElasticSearch \033[0m"
	wget $es_url
	dpkg -i elasticsearch-1.5.0.deb
	update-rc.d elasticsearch defaults 95 10

	echo -e "\033[32m[+] Configuration of your ElasticSearch Cluster \033[0m"

	sedeasy '#cluster.name: elasticsearch' 'cluster.name: '$cluster_name'' /etc/elasticsearch/elasticsearch.yml
	sedeasy '#node.name: "Franz Kafka"' 'node.name: '$node_name'' /etc/elasticsearch/elasticsearch.yml
	sedeasy '#index.number_of_shards: 5' "index.number_of_shards: 1" /etc/elasticsearch/elasticsearch.yml
	sedeasy '#index.number_of_replicas: 1' "index.number_of_replicas: 1" /etc/elasticsearch/elasticsearch.yml
	sedeasy '#discovery.zen.ping.multicast.enabled: false' 'discovery.zen.ping.multicast.enabled: false' /etc/elasticsearch/elasticsearch.yml
	sedeasy '#discovery.zen.ping.unicast.hosts: ["host1", "host2:port"]' "discovery.zen.ping.unicast.hosts: $host" /etc/elasticsearch/elasticsearch.yml

	echo -e "\033[32m[+] Marvel - Turn off logging \033[0m"
	echo "marvel.agent.enabled: false" >> /etc/elasticsearch/elasticsearch.yml

	echo -e "\033[32m[+] Starting ElasticSearch \033[0m"
	/etc/init.d/elasticsearch start > /dev/null
	echo -e "\033[32m[+] Done. \033[0m"

	echo -e "\033[32m[+] Cleaning ...\033[0m"
	rm elasticsearch-1.5.0.deb > /dev/null
	apt-get autoclean > /dev/null

	echo -e "\033[32m[+] Install all plugin of ElasticSearch \033[0m"
	cd /usr/share/elasticsearch/bin
	./plugin --install elasticsearch/marvel/latest > /dev/null
	./plugin --install mobz/elasticsearch-head > /dev/null
	./plugin --install lmenezes/elasticsearch-kopf/1.5.0 > /dev/null
	./plugin --install royrusso/elasticsearch-HQ > /dev/null
fi
#----------------------Ending ElasticSearch  -------------------------------------------------

#-----------------------------------Security  ------------------------------------------------
if [ $1 = "sec" ]
then
	echo -e "\033[32m[+] Installation of the following packages: iptables, libpam-cracklib, fail2ban, portsentry, openssh-server \033[0m"
	apt-get install -y iptables libpam-cracklib fail2ban portsentry openssh-server

	echo -e "\033[32m[+] Prohibition compile or install a paquet for a simple user. \033[0m"
	chmod o-x /usr/bin/gcc-*
	chmod o-x /usr/bin/make*
	chmod o-x /usr/bin/apt-get
	chmod o-x /usr/bin/dpkg

	echo -e "\033[32m[+] No Core Dump. \033[0m"
	echo "* hard core 0" >> /etc/security/limits.conf
	echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
	echo 'ulimit -S -c 0 > /dev/null 2>&1' >> /etc/profile

	echo -e "\033[32m[+] Forbiden to read passwd et shadow \033[0m"
	cd /etc/
	chown root:root passwd shadow group gshadow
	chmod 644 passwd group
	chmod 400 shadow gshadow

	echo -e "\033[32m[+] Enable logging of su activity . \033[0m"
	sedeasy 'SYSLOG_SU_ENAB no' 'SYSLOG_SU_ENAB yes' /etc/login.defs
	sedeasy 'SYSLOG_SG_ENAB no' 'SYSLOG_SG_ENAB yes' /etc/login.defs

	echo -e "\033[32m[+] Backup of sshd_config \033[0m"
	cp /etc/ssh/sshd_config /etc/ssh/sshd_config_backup

	echo -e "\033[32m[+] Change the default SSH port\033[0m"
	sedeasy '#   Port 22' '   Port $ssh_port' /etc/ssh/ssh_config
	echo -e "\033[32m[+] Disable SSH login for the root user\033[0m"
	sedeasy 'PermitRootLogin' 'PermitRootLogin no' /etc/ssh/ssh_config


	echo -e "\033[32m[+] Update iptables \033[0m"
	iptables -A INPUT -p tcp -m tcp --dport $ssh_port -j ACCEPT

	echo -e "\033[32m[+] Change configuration of Portsentry \033[0m"
	sedeasy 'BLOCK_UDP="0"' 'BLOCK_UDP="1"' /etc/portsentry/portsentry.conf
	sedeasy 'BLOCK_TCP="0"' 'BLOCK_TCP="1"' /etc/portsentry/portsentry.conf
	sedeasy 'KILL_ROUTE="/sbin/route add -host $TARGET$ reject"' 'KILL_ROUTE="/sbin/iptables -I INPUT -s $TARGET$ -j DROP"' /etc/portsentry/portsentry.conf
	sedeasy 'RESOLVE_HOST = "0"' 'RESOLVE_HOST = "1"' /etc/portsentry/portsentry.conf
	sedeasy 'TCP_MODE="tcp"' 'TCP_MODE="atcp"' /etc/default/portsentry
	sedeasy 'UDP_MODE="udp"' 'UDP_MODE="sudp"' /etc/default/portsentry

	echo -e "\033[32m[+] Restarting portsentry \033[0m"
	/etc/init.d/portsentry restart > /dev/null

	echo -e "\033[32m[+] Restarting sshd \033[0m"
	/etc/init.d/ssh restart

	echo -e "\033[32m[+] Change configuration of Fail2Ban \033[0m"
	sedeasy '/maxretry = 6' 'maxretry = 3' /etc/fail2ban/jail.conf
	/etc/init.d/fail2ban restart > /dev/null

	echo -e "\033[32m[+] Install and configure rootkit checkers \033[0m"
	apt-get install -y rkhunter chkrootkit
	sedeasy 'RUN_DAILY="false"' 'RUN_DAILY="true"' /etc/chkrootkit.conf
	sedeasy 'RUN_DAILY_OPTS="-q"' 'RUN_DAILY_OPTS=""' /etc/chkrootkit.conf
	sedeasy 'CRON_DAILY_RUN=""' 'CRON_DAILY_RUN="true"' /etc/default/rkhunter
	sedeasy 'CRON_DB_UPDATE=""' 'CRON_DB_UPDATE="true"' /etc/default/rkhunter
	mv /etc/cron.weekly/rkhunter /etc/cron.weekly/rkhunter_update
	mv /etc/cron.daily/rkhunter /etc/cron.weekly/rkhunter_run
	mv /etc/cron.daily/chkrootkit /etc/cron.weekly/
fi
#----------------------------------Ending Security  ------------------------------------------

#-----------------------------------S3cmd  ---------------------------------------------------
if [ $1 = "s3cmd" ]
then
	echo -e "\033[32m[+] Install S3cmd \033[0m"
	apt-get install unzip python-pip
	wget https://github.com/s3tools/s3cmd/archive/master.zip
	unzip master.zip
	cd s3cmd-master/
	python setup.py install
	pip install python-dateutil
	echo -e "\033[32m[+] Check the installed version of s3cmd tool: \033[0m"
	s3cmd --version
	echo -e "\033[32m[+] configure of s3cmd tools with your AMAZON ACCESS KEY and SECRET KEY: \033[0m"
	s3cmd --configure
	cd ..
	rm master.zip
	rm -rf s3cmd-master
fi
#-----------------------------------Ending S3cmd  ----------------------------------------------