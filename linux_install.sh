#!/bin/bash

echo "Made By SleepTheGod"

# Whois Lookup
echo "Installing Whois..."
sudo apt-get update
sudo apt-get install -y whois

# Website IP
echo "Installing ping..."
sudo apt-get install -y iputils-ping

# Asset Discovery
echo "Installing curl and jq..."
sudo apt-get install -y curl jq

# Subdomain Enumeration / Vertical domain correlation
echo "Installing Go..."

# Install Go (if not installed)
if ! command -v go &> /dev/null; then
    wget https://golang.org/dl/go1.15.6.linux-amd64.tar.gz
    sudo tar -C /usr/local -xzf go1.15.6.linux-amd64.tar.gz
    echo "export PATH=$PATH:/usr/local/go/bin" >> ~/.profile
    source ~/.profile
fi

echo "Installing assetfinder..."
go get -u github.com/tomnomnom/assetfinder

echo "Installing findomain..."
wget https://github.com/Findomain/Findomain/releases/download/5.0.0/findomain-linux
chmod +x findomain-linux
sudo mv findomain-linux /usr/local/bin/findomain

echo "Installing subfinder..."
wget https://github.com/projectdiscovery/subfinder/releases/download/v2.4.8/subfinder-linux-amd64
chmod +x subfinder-linux-amd64
sudo mv subfinder-linux-amd64 /usr/local/bin/subfinder

# Active Enumeration
echo "Installing nmap..."
sudo apt-get install -y nmap

echo "Installing massdns..."
git clone https://github.com/blechschmidt/massdns.git
cd massdns
make
sudo cp bin/massdns /usr/local/bin/
cd ..

echo "Installing goaltdns..."
go get github.com/subfinder/goaltdns

echo "Installing shuffledns..."
go get -v github.com/projectdiscovery/shuffledns/cmd/shuffledns

echo "Installing puredns..."
go get -v github.com/d3mondev/puredns

# HTTP/HTTPS Probing
echo "Installing httprobe and httpx..."
go get -u github.com/tomnomnom/httprobe
go get -v github.com/projectdiscovery/httpx/cmd/httpx

# ASN Lookup
echo "Installing python3 and requests library..."
sudo apt-get install -y python3 python3-pip
pip3 install requests

# Target Visualize/Web-Screenshot
echo "Installing gowitness..."
go get -u github.com/sensepost/gowitness

echo "Installing EyeWitness..."
git clone https://github.com/FortyNorthSecurity/EyeWitness.git
cd EyeWitness/Python/setup
sudo ./setup.sh
cd ../..

echo "Installing webscreenshot..."
pip3 install webscreenshot

# Scanning for directory with possible sensitive information
echo "Installing dirsearch..."
git clone https://github.com/maurosoria/dirsearch.git

echo "Installing wfuzz..."
sudo apt-get install -y wfuzz

# Parameter discovery
echo "Installing arjun..."
pip3 install arjun

echo "Installing ParamSpider..."
git clone https://github.com/devanshbatham/ParamSpider.git
cd ParamSpider
pip3 install -r requirements.txt
cd ..

# Subdomain Cname extraction
echo "Installing dig..."
sudo apt-get install -y dnsutils

# Crawling & Collecting Pagelinks
echo "Installing waybackurls..."
go get github.com/tomnomnom/waybackurls

echo "Installing gau..."
go get github.com/lc/gau

echo "Installing gospider..."
go get -u github.com/jaeles-project/gospider

# Javascript Files Crawling & find sensitive information from jsfile
echo "Installing getJS..."
git clone https://github.com/003random/getJS.git

echo "Installing JSFinder..."
git clone https://github.com/Threezh1/JSFinder.git

# Domain/Subdomain Version and technology detection
echo "Installing wappalyzer..."
npm install -g wappalyzer

echo "Installing whatweb..."
sudo apt-get install -y whatweb

echo "Installing wad..."
pip3 install wad

echo "Installing nuclei..."
go get -u github.com/projectdiscovery/nuclei/v2/cmd/nuclei

echo "Installation completed."
