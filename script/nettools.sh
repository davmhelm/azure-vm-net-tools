# This script has been tested on Ubuntu
# Update repository
apt update -y && sudo apt upgrade -y 

# Net-tools
apt-get install net-tools -y

#Traceroute
apt-get install traceroute -y

# TCP traceroute
apt-get install tcptraceroute -y

# Nmap
apt-get install nmap -y

# Hping3
apt-get install hping3 -y

# iPerf
apt-get install iperf3 -y

# Nginx and adds machine name & OS on main page
apt-get install nginx -y 
hostname > /var/www/html/index.html
lsb_release -ds >> /var/www/html/index.html

# Speedtest
apt-get install speedtest-cli -y
