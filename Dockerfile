#--------------------------------------------------------------------------------------------------
# - h4ckb0x - A simple hacking environment -
#--------------------------------------------------------------------------------------------------

FROM docker.io/ubuntu:20.04
LABEL Description="h4ckb0x: A simple hacking environment as docker image."

#--------------------------------------------------------------------------------------------------

# basic system tools we need
RUN apt update && apt upgrade -y && \
    export DEBIAN_FRONTEND=noninteractive && \
    apt install iputils-ping unzip vim netcat socat nmap curl wget git net-tools -y && \ 
    apt install jq -y && \
    apt install dnsutils -y && \
    apt install libgbm1 -y && \
    apt install libxkbcommon-x11-0 -y && \
    apt install ftp nfs-common -y && \
    apt install sudo -y 

#Home directory
ADD data /root
WORKDIR /root

#bashrc
RUN echo "set -o vi" >> /root/.bashrc &&  \
    echo "PATH=\$PATH:/root/opt/bin:/opt/node-v20.12.0-linux-x64/bin/" >> /root/.bashrc &&  \
    echo "export RECONAUT_TEMPLATES=/root/reconaut-templates/" >> /root/.bashrc &&  \
    echo "PS1='\[\033[0;31m\]\u \e[31m$(parse_if_root)\[\033[0;37m\]at \[\033[0;31m\]h4ckb0x \[\033[0;37m\]in \[\033[0;31m\]\w \[\033[1;35m\]$(parse_git_branch)\n\[\033[1;35m\]⤷ \[\033[0m\]'" >> /root/.bashrc && \
    echo "PATH=\$PATH:/usr/local/go/bin" >> /root/.bashrc && \
    echo "cat /root/etc/motd" >> /root/.bashrc && \
    echo "alias p='ping -c 1'" >> /root/.bashrc && \ 
    echo "alias nmapq='nmap -n -sC -sV'" >> /root/.bashrc && \
    echo "alias eslintsec='eslint -c ~/eslint-security-scanner-configs/eslintrc-light.js *.js'" >> /root/.bashrc && \
    echo "alias ffufu='ffuf -H \"User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0\"'" >> /root/.bashrc  && \
    echo "alias smuggler='/root/opt/smuggler/smuggler.py'" >> /root/.bashrc

#--------------------------------------------------------------------------------------------------
## programming languages

# Python
RUN apt install python python3 pip -y && \
    pip3 install requests

# Go
RUN wget -P /tmp https://go.dev/dl/go1.23.1.linux-amd64.tar.gz && \ 
    tar -C /usr/local -xzf /tmp/go1.23.1.linux-amd64.tar.gz   && \
    rm /tmp/go1.23.1.linux-amd64.tar.gz

# Java
RUN apt install openjdk-17-jdk openjdk-17-jre -y

#--------------------------------------------------------------------------------------------------
#Wordlists
# Some basic wordlists
RUN tar xzf opt/wordlists/rockyou.txt.tgz -C opt/wordlists/ && rm opt/wordlists/rockyou.txt.tgz
RUN git clone --depth 1 https://github.com/danielmiessler/SecLists.git /root/opt/wordlists/SecLists

# custom wordlists generator
RUN sudo apt install cewl -y

#--------------------------------------------------------------------------------------------------
# Host Enumeration

# amass
# OWASP enumeration tool
RUN wget -P /tmp https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_Linux_amd64.zip && \
    unzip -d /tmp /tmp/amass_Linux_amd64.zip && \
    mv /tmp/amass_Linux_amd64/amass /root/opt/bin && \
    rm -rf /tmp/amass_Linux_amd64 && rm /tmp/amass_Linux_amd64.zip
# nameservers usefull for using with amass
RUN wget https://public-dns.info/nameservers.txt && \
    sort -R nameservers.txt | tail -n 30 > mynameservers.txt && \
    mv nameservers.txt /root/etc/ && \
    mv mynameservers.txt /root/etc

# sublist3r 
# enumeration tool
RUN git clone --depth 1 https://github.com/huntergregal/Sublist3r.git /root/opt/sublist3r && \
    pip install -r /root/opt/sublist3r/requirements.txt

# findomain
# enumeration tool
RUN curl -LO https://github.com/findomain/findomain/releases/latest/download/findomain-linux-i386.zip && \
    unzip findomain-linux-i386.zip && \
    chmod +x findomain && \
    mv findomain /root/opt/bin/ && \
    rm findomain-linux-i386.zip

#--------------------------------------------------------------------------------------------------
# URL/File Enumeration

# katana
# Spider and Crawler
RUN /usr/local/go/bin/go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    mv go/bin/katana opt/bin/ && \
    rm -rf /root/go

# gau
# getallurls - OSINT url discovery
RUN /usr/local/go/bin/go  install github.com/lc/gau/v2/cmd/gau@latest && \
    mv go/bin/gau opt/bin/ && \
    rm -rf /root/go

# httpx
# HTTP Probe tool
RUN /usr/local/go/bin/go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    mv go/bin/httpx opt/bin/ && \
    rm -rf /root/go

# jsluice
# Static code analysis of js files in order to find API endpoints, secrets and other stuff
RUN /usr/local/go/bin/go install -v github.com/BishopFox/jsluice/cmd/jsluice@latest && \
  mv go/bin/jsluice opt/bin/ && \
  rm -rf /root/go
  
#--------------------------------------------------------------------------------------------------
# fuzzer

# ffuf
# fast fuzzer
RUN wget -P /tmp https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz && \
    tar -C /root/opt/bin/ -xf /tmp/ffuf_2.1.0_linux_amd64.tar.gz && \
    rm /root/opt/bin/CHANGELOG.md /root/opt/bin/LICENSE /root/opt/bin/README.md /tmp/ffuf_2.1.0_linux_amd64.tar.gz

# gobuster
RUN /usr/local/go/bin/go install -v github.com/OJ/gobuster/v3@latest && \
  mv go/bin/gobuster opt/bin/ && \
  rm -rf /root/go

# kiterunner
# API fuzzer
RUN wget -P /tmp/ https://github.com/assetnote/kiterunner/releases/download/v1.0.2/kiterunner_1.0.2_linux_amd64.tar.gz && \
    tar -C /root/opt/bin -xf /tmp/kiterunner_1.0.2_linux_amd64.tar.gz && \
    rm /tmp/kiterunner_1.0.2_linux_amd64.tar.gz

# arjun
# Parameter fuzzer
RUN pip3 install arjun

# crlffuzz
# CRLF injection fuzzer
RUN curl -sSfL https://git.io/crlfuzz | sh -s -- -b /root/opt/bin

#--------------------------------------------------------------------------------------------------
# Scanners 

# nuclei
# Vul scanner
RUN wget -P /tmp https://github.com/projectdiscovery/nuclei/releases/download/v2.9.15/nuclei_2.9.15_linux_amd64.zip && \
    unzip -d /root/opt/bin /tmp/nuclei_2.9.15_linux_amd64.zip && \
    rm /tmp/nuclei_2.9.15_linux_amd64.zip && \
    # run once to install the templates
    /root/opt/bin/nuclei

#nikto
RUN apt install nikto -y

# sqlamp
# SQLi scanner
RUN apt install sqlmap -y

# xssstrike
# XSS scanner
RUN wget -P /tmp "https://github.com/s0md3v/XSStrike/archive/refs/tags/3.1.5.tar.gz" && \
    tar -C /root/opt -xvzf /tmp/3.1.5.tar.gz && \
    chmod u+x /root/opt/XSStrike-3.1.5/xsstrike.py && \
    ln -s /root/opt/XSStrike-3.1.5/xsstrike.py /root/opt/bin/xssstrike && \
    rm /tmp/3.1.5.tar.gz

#--------------------------------------------------------------------------------------------------
# tomnomnom tools

# anew
# like tee, but no duplicates
RUN /usr/local/go/bin/go install -v github.com/tomnomnom/anew@latest && \
    mv go/bin/anew opt/bin/ && \
    rm -rf /root/go

# fff
# fairly fast fetcher: a fast content downloader
RUN git clone --depth 1 https://github.com/tomnomnom/fff.git /tmp/fff && \
    cd /tmp/fff && \
    /usr/local/go/bin/go build && \
    cp /tmp/fff/fff /root/opt/bin && \
    rm -rf /tmp/fff && \
    cd -

# gf
# A nice grep wrapper looking for interesting stuff
RUN git clone --depth 1 https://github.com/tomnomnom/gf.git /tmp/gf && \
    cd /tmp/gf && \
    /usr/local/go/bin/go mod init gf && \
    /usr/local/go/bin/go mod tidy  && \
    /usr/local/go/bin/go build && \
    cp /tmp/gf/gf /root/opt/bin && \
    mkdir /root/.gf && \
    cp -R /tmp/gf/examples/* /root/.gf/ && \
    rm -rf /tmp/gf && \
    cd -

# unfurl
# url remover 
RUN wget https://github.com/tomnomnom/unfurl/releases/download/v0.4.3/unfurl-linux-amd64-0.4.3.tgz -O /tmp/unfurl.tgz && \
   tar -C /root/opt/bin -xf /tmp/unfurl.tgz && \
   rm -rf /tmp/unfurl.tgz

# wayback url
# wayback client
RUN /usr/local/go/bin/go install github.com/tomnomnom/waybackurls@latest && \
    mv go/bin/waybackurls opt/bin/ && \
    rm -rf /root/go


#--------------------------------------------------------------------------------------------------
# Crackers

# hydra
# genaral cracker
#hdydra requires debconf which comes with an interactive q&a installation by default. 
#we don't want this so we set DEBIAN_FRONTEND to "noninteractive"
RUN apt update && DEBIAN_FRONTEND=noninteractive apt install -y hydra

# hashcat
# hash cracker
RUN apt install hashcat -y

# john
RUN apt -y install libssl-dev && \
  git clone --depth 1 https://github.com/openwall/john.git /tmp/john && \
  cd /tmp/john/src && ./configure && make -sj4 && mkdir -p /root/opt/john &&  \
  cp -R /tmp/john/run/* /root/opt/john && \
  rm -rf /tmp/john

#--------------------------------------------------------------------------------------------------
# Exploits 

# searchsploit
RUN git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb && \
  ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit

# metasploit
# explit framework
RUN curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall && \
  apt update && \
  chmod 755 /tmp/msfinstall && \
  /tmp/msfinstall && \
  rm /tmp/msfinstall

#--------------------------------------------------------------------------------------------------
# Mobile

# apk tooling
# Leak scanner
RUN pip3 install apkleaks && \
    wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool -O /root/opt/bin/apktool && \
    chmod u+x /root/opt/bin/apktool && \
    wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.8.1.jar -O /root/opt/bin/apktool.jar

#--------------------------------------------------------------------------------------------------
# AWS

# aws cli
RUN curl -P /tmp "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "/tmp/awscliv2.zip" && \
  cd /tmp && \
  unzip awscliv2.zip && \ 
  /tmp//aws/install && \
  rm -rf /tmp/aws*

#--------------------------------------------------------------------------------------------------
# bl155x0

# jsloot
RUN pip install jsbeautifier && \
  /usr/local/go/bin/go install github.com/bl155x0/jsloot@latest && \
  mv go/bin/jsloot opt/bin/ && \
  rm -rf /root/go

#--------------------------------------------------------------------------------------------------
# JavaScript

# node, npm and eslint
RUN cd /tmp && wget https://nodejs.org/dist/v20.12.0/node-v20.12.0-linux-x64.tar.xz && \
  tar xf node-v20.12.0-linux-x64.tar.xz -C /opt && \
  export PATH=$PATH:/opt/node-v20.12.0-linux-x64/bin/ && \
  npm install -g --save-dev eslint eslint-plugin-security && \
  cd /root &&  git clone https://github.com/Greenwolf/eslint-security-scanner-configs && \
  cd /root/eslint-security-scanner-configs && npm install eslint-plugin-standard eslint-plugin-import eslint-plugin-node eslint-plugin-promise eslint-config-standard eslint-config-semistandard eslint-plugin-scanjs-rules eslint-plugin-no-unsanitized eslint-plugin-prototype-pollution-security-rules eslint-plugin-angularjs-security-rules eslint-plugin-react eslint-plugin-no-wildcard-postmessage eslint-plugin-html@latest --save-dev

#--------------------------------------------------------------------------------------------------
# smuggler
RUN cd /root/opt && git clone --depth 1 https://github.com/defparam/smuggler.git

#--------------------------------------------------------------------------------------------------
#smb/cifs stuff
RUN apt install -y smbclient && \
    wget https://raw.githubusercontent.com/CiscoCXSecurity/enum4linux/master/enum4linux.pl -O /root/opt/bin/enum4linux && \
    chmod u+x /root/opt/bin/enum4linux

#--------------------------------------------------------------------------------------------------
# /var/www - stuff to serve 
RUN mkdir /var/www && \
   wget -P /var/www https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh && \
   wget -P /var/www https://raw.githubusercontent.com/peass-ng/PEASS-ng/master/winPEAS/winPEASps1/winPEAS.ps1 && \
   wget -P /var/www https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASany_ofs.exe && \
   wget -P /var/www https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64 && \
   wget -P /var/www https://github.com/int0x33/nc.exe/raw/master/nc.exe && \
   wget -P /var/www https://github.com/int0x33/nc.exe/raw/master/nc64.exe && \
   cp /usr/bin/socat /var/www/socat


#--------------------------------------------------------------------------------------------------
# sql tools
RUN apt install mysql-client -y

#--------------------------------------------------------------------------------------------------
# impacket - network libraries and offensive toolings
RUN git clone --depth 1 https://github.com/fortra/impacket /root/opt/impacket && \
  cd /root/opt/impacket/ && python3 ./setup.py install && \
  pip3 install -r requirements.txt && \
  cd -

#--------------------------------------------------------------------------------------------------
# Responder - Poisoner - https://github.com/lgandx/Responder
RUN git clone --depth 1 https://github.com/lgandx/Responder.git /root/opt/responder && \
  cd /root/opt/responder && pip3 install -r requirements.txt && \
  cd -

  
