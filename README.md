# Easy-install

Simple script in order to install: PHP, Apache, Git, Scrapy, Java, ElasticSearch, fail2ban on Ubuntu Server.
More, this script configure Apache, PHP, ElasticSearch, rkhunter, chkrootkit, fail2ban

 How to:
-----------

Step1:
In the setup.sh, you need to change the default configuration.
You need to change this variables:

 		cluster_name="Zen"
 		node_name="Node_1"
 		host="['127.0.0.1']"
 		ssh_port="4246"
 		your_email="your_mail"

by your own parameters.

 Step2: 
 Change the chmod of this script, in order to make it executable (chmod +x setup.sh)
 
 Step3: 
 Run the scrip: sudo ./setup.sh
