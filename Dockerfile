#--------------------------------------------------------------------------------------------------
# - h4ckb0x - A simple hacking environment -
#--------------------------------------------------------------------------------------------------

FROM docker.io/ubuntu:20.04
LABEL Description="h4ckb0x: A simple hacking environment as docker image."

#--------------------------------------------------------------------------------------------------

# basic system tools we need
RUN apt update && apt upgrade -y
RUN export DEBIAN_FRONTEND=noninteractive && \
    #tools
    apt install iputils-ping unzip vim netcat nmap curl wget git -y && \ 
    #python
    apt install python python3 pip -y && \
    #go
    wget -P /tmp https://go.dev/dl/go1.21.1.linux-amd64.tar.gz && \ 
    tar -C /usr/local -xzf /tmp/go1.21.1.linux-amd64.tar.gz   && \
    rm /tmp/go1.21.1.linux-amd64.tar.gz  && \
    #java
    apt install openjdk-17-jdk openjdk-17-jre -y && \
    #jq for processing JSON inputs
    apt install jq -y && \
    # dnsutils like nslookup and dig
    apt install dnsutils -y
    
#Home directory
ADD data /root
WORKDIR /root

#python
RUN pip3 install requests

#bashrc
RUN echo "set -o vi" >> /root/.bashrc &&  \
    echo "PATH=\$PATH:/root/opt/bin" >> /root/.bashrc &&  \
    echo "export RECONAUT_TEMPLATES=/root/reconaut-templates/" >> /root/.bashrc &&  \
    echo "PS1='\[\033[0;31m\]\u \e[31m$(parse_if_root)\[\033[0;37m\]at \[\033[0;31m\]h4ckb0x \[\033[0;37m\]in \[\033[0;31m\]\w \[\033[1;35m\]$(parse_git_branch)\n\[\033[1;35m\]⤷ \[\033[0m\]'" >> /root/.bashrc && \
    echo "PATH=\$PATH:/usr/local/go/bin" >> /root/.bashrc && \
    echo "cat /root/etc/motd" >> /root/.bashrc  && \
    echo "alias nmapq='nmap -n -sC -sV'" >> /root/.bashrc

#--------------------------------------------------------------------------------------------------
#Wordlists
# Some basic wordlists
RUN tar xzf opt/wordlists/rockyou.txt.tgz -C opt/wordlists/ && rm opt/wordlists/rockyou.txt.tgz
RUN git clone --depth 1 https://github.com/danielmiessler/SecLists.git /root/opt/wordlists/SecLists

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
RUN export DEBIAN_FRONTEND=noninteractive && apt install hydra -y

# hashcat
# hash cracker
RUN apt install hashcat -y

#--------------------------------------------------------------------------------------------------
# Exploits 

# metasploit
# explit framework
RUN curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall && \
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
