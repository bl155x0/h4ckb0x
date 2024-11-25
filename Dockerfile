#--------------------------------------------------------------------------------------------------
# - h4ckb0x - A simple hacking environment -
#--------------------------------------------------------------------------------------------------

FROM docker.io/ubuntu:20.04
LABEL Description="h4ckb0x: A simple hacking environment as docker image."

#--------------------------------------------------------------------------------------------------

# basic system tools we need
RUN apt update && apt upgrade -y && \
    export DEBIAN_FRONTEND=noninteractive && \
    apt install iputils-ping unzip vim netcat socat curl wget git net-tools -y && \ 
    apt install jq -y && \
    apt install dnsutils -y && \
    apt install libgbm1 -y && \
    apt install rsync -y && \
    apt install libxkbcommon-x11-0 -y && \
    apt install ftp nfs-common -y && \
    apt install mlocate -y && \
    apt install sudo -y && \
    apt install alien -y

#Home directory
ADD data /root
WORKDIR /root

#bashrc
RUN echo "PATH=\$PATH:/root/opt/bin:/opt/node-v20.12.0-linux-x64/bin/" >> /root/.bashrc &&  \
    echo "export RECONAUT_TEMPLATES=/root/reconaut-templates/" >> /root/.bashrc &&  \
    echo "PS1='\[\033[0;31m\]\u \e[31m$(parse_if_root)\[\033[0;37m\]at \[\033[0;31m\]h4ckb0x \[\033[0;37m\]in \[\033[0;31m\]\w \[\033[1;35m\]$(parse_git_branch)\n\[\033[1;35m\] \[\033[0m\]'" >> /root/.bashrc && \
    echo "PATH=\$PATH:/usr/local/go/bin" >> /root/.bashrc && \
    echo "cat /root/etc/motd" >> /root/.bashrc && \
    echo "alias p='ping -c 1'" >> /root/.bashrc && \ 
    echo "alias nmapq='nmap -n -sC -sV'" >> /root/.bashrc && \
    echo "alias eslintsec='eslint -c ~/eslint-security-scanner-configs/eslintrc-light.js *.js'" >> /root/.bashrc && \
    echo "alias ffufu='ffuf -H \"User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0\"'" >> /root/.bashrc  && \
    echo "alias smuggler='/root/opt/smuggler/smuggler.py'" >> /root/.bashrc

#--------------------------------------------------------------------------------------------------
## programming languages
RUN apt update && \
    # Python
    apt install -y python python3 python3-pip && pip3 install requests && \

    # Go
    wget -P /tmp https://go.dev/dl/go1.23.1.linux-amd64.tar.gz && \ 
    tar -C /usr/local -xzf /tmp/go1.23.1.linux-amd64.tar.gz   && \
    rm /tmp/go1.23.1.linux-amd64.tar.gz && \

    # Java
    apt install openjdk-17-jdk openjdk-17-jre -y

#--------------------------------------------------------------------------------------------------
#Wordlists

RUN apt update && \

    # rockyou
    tar xzf opt/wordlists/rockyou.txt.tgz -C opt/wordlists/ && rm opt/wordlists/rockyou.txt.tgz && \

    # SecLists
    git clone --depth 1 https://github.com/danielmiessler/SecLists.git /root/opt/wordlists/SecLists && \

    # n0kovo subdomain
    git clone --depth 1  https://github.com/n0kovo/n0kovo_subdomains /root/opt/wordlists/n0kovo && \

    # custom wordlists generator
    apt install cewl -y

#--------------------------------------------------------------------------------------------------
# Host Enumeration

    # amass - OWASP enumeration tool
RUN wget -P /tmp https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_Linux_amd64.zip && \
    unzip -d /tmp /tmp/amass_Linux_amd64.zip && \
    mv /tmp/amass_Linux_amd64/amass /root/opt/bin && \
    rm -rf /tmp/amass_Linux_amd64 && rm /tmp/amass_Linux_amd64.zip && \

    # nameservers usefull for using with amass
    wget https://public-dns.info/nameservers.txt && \
    sort -R nameservers.txt | tail -n 30 > mynameservers.txt && \
    mv nameservers.txt /root/etc/ && \
    mv mynameservers.txt /root/etc && \

    # sublist3r - enumeration tool
    git clone --depth 1 https://github.com/huntergregal/Sublist3r.git /root/opt/sublist3r && \
    pip install -r /root/opt/sublist3r/requirements.txt && \

    # findomain - enumeration tool
    curl -LO https://github.com/findomain/findomain/releases/latest/download/findomain-linux-i386.zip && \
    unzip findomain-linux-i386.zip && \
    chmod +x findomain && \
    mv findomain /root/opt/bin/ && \
    rm findomain-linux-i386.zip && \

    # dns enum
    git clone --depth 1 https://github.com/fwaeytens/dnsenum /tmp/dnsenum && \
    apt install -y cpanminus && \
    cpanm String::Random Net::IP Net::DNS Net::Netmask XML::Writer && \
    mv /tmp/dnsenum/dnsenum.pl /root/opt/bin/dnsenum && chmod u+x /root/opt/bin/dnsenum && \
    rm -rf /tmp/dnsenum

#--------------------------------------------------------------------------------------------------
# URL/File Enumeration

     # katana - Spider and Crawler
RUN /usr/local/go/bin/go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    mv go/bin/katana opt/bin/ && \
    rm -rf /root/go && \

    # gau - getallurls - OSINT url discovery
    /usr/local/go/bin/go  install github.com/lc/gau/v2/cmd/gau@latest && \
    mv go/bin/gau opt/bin/ && \
    rm -rf /root/go && \

    # httpx - HTTP Probe tool
    /usr/local/go/bin/go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    mv go/bin/httpx opt/bin/ && \
    rm -rf /root/go && \

    # jsluice  -Static code analysis of js files in order to find API endpoints, secrets and other stuff
    /usr/local/go/bin/go install -v github.com/BishopFox/jsluice/cmd/jsluice@latest && \
    mv go/bin/jsluice opt/bin/ && \
    rm -rf /root/go
  
#--------------------------------------------------------------------------------------------------
# fuzzer

RUN apt update && \ 

    # ffuf - fast fuzzer
    wget -P /tmp https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz && \
    tar -C /root/opt/bin/ -xf /tmp/ffuf_2.1.0_linux_amd64.tar.gz && \
    rm /root/opt/bin/CHANGELOG.md /root/opt/bin/LICENSE /root/opt/bin/README.md /tmp/ffuf_2.1.0_linux_amd64.tar.gz && \

    # gobuster
    /usr/local/go/bin/go install -v github.com/OJ/gobuster/v3@latest && \
    mv go/bin/gobuster opt/bin/ && \
    rm -rf /root/go && \

    # kiterunner API fuzzer 
    wget -P /tmp/ https://github.com/assetnote/kiterunner/releases/download/v1.0.2/kiterunner_1.0.2_linux_amd64.tar.gz && \
    tar -C /root/opt/bin -xf /tmp/kiterunner_1.0.2_linux_amd64.tar.gz && \
    rm /tmp/kiterunner_1.0.2_linux_amd64.tar.gz && \

    # arjun Parameter fuzzer
    pip3 install arjun && \

    # crlffuzz - CRLF injection fuzzer
    curl -sSfL https://git.io/crlfuzz | sh -s -- -b /root/opt/bin && \

    # whatweb
    apt install -y whatweb && \

    # eye witness
    git clone --depth 1 https://github.com/RedSiege/EyeWitness.git /root/opt/eyewitness/ && \
    /root/opt/eyewitness/Python/setup/setup.sh 

#--------------------------------------------------------------------------------------------------
# Scanners 

RUN apt update && \ 

    # famous nmap - recent version
    wget -P /tmp https://nmap.org/dist/nmap-7.95-3.x86_64.rpm && \
    cd /tmp/ && alien -k nmap-7.95-3.x86_64.rpm && \
    dpkg -i ./nmap_7.95-3_amd64.deb && \
    cd - && rm -rf /tmp/* && \

    # nuclei Vul scanner
    wget -P /tmp https://github.com/projectdiscovery/nuclei/releases/download/v2.9.15/nuclei_2.9.15_linux_amd64.zip && \
    unzip -d /root/opt/bin /tmp/nuclei_2.9.15_linux_amd64.zip && \
    rm /tmp/nuclei_2.9.15_linux_amd64.zip && \
    # run once to install the templates
    /root/opt/bin/nuclei && \

    #nikto
    apt install nikto -y && \

    # sqlamp SQLi scanner
    apt install sqlmap -y && \

    # xssstrike XSS scanner
    wget -P /tmp "https://github.com/s0md3v/XSStrike/archive/refs/tags/3.1.5.tar.gz" && \
    tar -C /root/opt -xvzf /tmp/3.1.5.tar.gz && \
    chmod u+x /root/opt/XSStrike-3.1.5/xsstrike.py && \
    ln -s /root/opt/XSStrike-3.1.5/xsstrike.py /root/opt/bin/xssstrike && \
    rm /tmp/3.1.5.tar.gz

#--------------------------------------------------------------------------------------------------
# tomnomnom tools

    # anew - like tee, but no duplicates
RUN /usr/local/go/bin/go install -v github.com/tomnomnom/anew@latest && \
    mv go/bin/anew opt/bin/ && \
    rm -rf /root/go && \

    # fff
    # fairly fast fetcher: a fast content downloader
    git clone --depth 1 https://github.com/tomnomnom/fff.git /tmp/fff && \
    cd /tmp/fff && \
    /usr/local/go/bin/go build && \
    cp /tmp/fff/fff /root/opt/bin && \
    rm -rf /tmp/fff && \
    cd - && \

    # gf
    # A nice grep wrapper looking for interesting stuff
    git clone --depth 1 https://github.com/tomnomnom/gf.git /tmp/gf && \
    cd /tmp/gf && \
    /usr/local/go/bin/go mod init gf && \
    /usr/local/go/bin/go mod tidy  && \
    /usr/local/go/bin/go build && \
    cp /tmp/gf/gf /root/opt/bin && \
    mkdir /root/.gf && \
    cp -R /tmp/gf/examples/* /root/.gf/ && \
    rm -rf /tmp/gf && \
    cd - && \

    # unfurl url remover 
    wget https://github.com/tomnomnom/unfurl/releases/download/v0.4.3/unfurl-linux-amd64-0.4.3.tgz -O /tmp/unfurl.tgz && \
    tar -C /root/opt/bin -xf /tmp/unfurl.tgz && \
    rm -rf /tmp/unfurl.tgz && \

    # wayback url wayback client
    /usr/local/go/bin/go install github.com/tomnomnom/waybackurls@latest && \
    mv go/bin/waybackurls opt/bin/ && \
    rm -rf /root/go

#--------------------------------------------------------------------------------------------------
# Crackers

RUN apt update && \ 

    # hydra
    # genaral cracker
    #hdydra requires debconf which comes with an interactive q&a installation by default. 
    #we don't want this so we set DEBIAN_FRONTEND to "noninteractive"
    DEBIAN_FRONTEND=noninteractive apt install -y hydra && \

    # hashcat hash cracker
    apt install hashcat -y && \

    # john
    apt -y install libssl-dev && \
    git clone --depth 1 https://github.com/openwall/john.git /tmp/john && \
    cd /tmp/john/src && ./configure && make -sj4 && mkdir -p /root/opt/john &&  \
    cp -R /tmp/john/run/* /root/opt/john && \
    rm -rf /tmp/john

#--------------------------------------------------------------------------------------------------
# Exploits 

RUN apt update && \

    # searchsploit
    git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb && \
    ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit && \

    # metasploit - exploit framwework
    curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall && \
    chmod 755 /tmp/msfinstall && \
    /tmp/msfinstall && \
    rm /tmp/msfinstall

#--------------------------------------------------------------------------------------------------
# Mobile

    # apk tooling Leak scanner
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
    rm -rf /root/go && \

   # findwordlist
   git clone --depth 1 https://github.com/bl155x0/findwordlist.git /tmp/findwordlist && \
   cd /tmp/findwordlist && /usr/local/go/bin/go build && \
   chmod u+x findwordlist && mv findwordlist /root/opt/bin/findwordlist && \
   rm -rf /tmp/findwordlist && cd - && \

   # godork
   git clone --depth 1 https://github.com/bl155x0/godork.git /tmp/godork && \
   cd /tmp/godork && /usr/local/go/bin/go build && \
   chmod u+x godork && mv godork /root/opt/bin && \
   mv dorks.txt /root/opt/wordlists && \
   echo -n 'export GODORK_DORKFILE="/root/opt/wordlists/dorks.txt"' >> /root/.bashrc && \
   rm -rf /tmp/godork && cd -

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
# /var/www - stuff to serve 
RUN mkdir /var/www && \
   wget -P /var/www https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh && \
   wget -P /var/www https://raw.githubusercontent.com/peass-ng/PEASS-ng/master/winPEAS/winPEASps1/winPEAS.ps1 && \
   wget -P /var/www https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASany_ofs.exe && \
   wget -P /var/www https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64 && \
   wget -P /var/www https://github.com/int0x33/nc.exe/raw/master/nc.exe && \
   wget -P /var/www https://github.com/int0x33/nc.exe/raw/master/nc64.exe && \
   wget -P /var/www https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat && \
   wget -P /var/www https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/ncat

#--------------------------------------------------------------------------------------------------
# Database - SQL 
RUN apt update && \ 

    #mysql client
    apt install mysql-client -y && \

    # oracle - sql plus
    apt install libaio1 -y && \
    wget -P /tmp/ https://download.oracle.com/otn_software/linux/instantclient/214000/instantclient-basic-linux.x64-21.4.0.0.0dbru.zip && \
    wget -P /tmp/ https://download.oracle.com/otn_software/linux/instantclient/214000/instantclient-sqlplus-linux.x64-21.4.0.0.0dbru.zip && \
    cd /tmp && unzip instantclient-basic-linux.x64-21.4.0.0.0dbru.zip && unzip instantclient-sqlplus-linux.x64-21.4.0.0.0dbru.zip && \
    mv instantclient_21_4 /root/opt/sqlplus && cd - && \
    echo "/root/opt/sqlplus" > /etc/ld.so.conf.d/oracle-instantclient.conf && ldconfig && \
    ln -s /root/opt/sqlplus/sqlplus /root/opt/bin/sqlplus && \
    rm -rf /tmp/* && \


    # ODAT - Oracle Database Attacking Tool  
    wget -P /tmp/ "https://github.com/quentinhardy/odat/releases/download/5.1.1/odat-linux-libc2.17-x86_64.tar.gz" && \
    tar -C /root/opt/ -xvf /tmp/odat-linux-libc2.17-x86_64.tar.gz && \
    ln -s /root/opt/odat-libc2.17-x86_64/odat-libc2.17-x86_64 /root/opt/bin/odat && \
    rm -rf /tmp/odat*

#--------------------------------------------------------------------------------------------------
# Windows offensive

     # impacket - network libraries and offensive toolings
 RUN git clone --depth 1 https://github.com/fortra/impacket /root/opt/impacket && \
     cd /root/opt/impacket/ && pip install . && \

    # Responder - Poisoner - https://github.com/lgandx/Responder
    git clone --depth 1 https://github.com/lgandx/Responder.git /root/opt/responder && \
    cd /root/opt/responder && pip3 install -r requirements.txt && \
    cd -

#--------------------------------------------------------------------------------------------------
#smb/cifs stuff

RUN apt update && \

    # smbclient including rpcclient
    apt install -y smbclient && \

    #enum4linux-ng
    apt install -y python3-ldap3 python3-yaml && \
    wget https://github.com/cddmp/enum4linux-ng/archive/refs/tags/v1.3.4.zip -O /tmp/enum4linux.zip && \
    unzip /tmp/enum4linux -d /tmp && \
    cp /tmp/enum4linux-ng-1.3.4/enum4linux-ng.py /root/opt/bin && \
    chmod u+x /root/opt/bin/enum4linux-ng.py && \

    #smbmap
   pip3 install smbmap

#--------------------------------------------------------------------------------------------------
#SMTP
    #Perl based smtp-user-enum
RUN wget https://raw.githubusercontent.com/pentestmonkey/smtp-user-enum/refs/heads/master/smtp-user-enum.pl -P /root/opt/bin/ && \
    chmod u+x /root/opt/bin/smtp-user-enum.pl && \

    #Python based smtp-user-enum
    pip install smtp-user-enum

#--------------------------------------------------------------------------------------------------
#SNMP
RUN apt update && \

    # snmp - snmpwalk: snmp query tool
    apt install -y snmp && \

    # onesixtyone  - snmp scanner
    apt install -y onesixtyone && \

    # braa - a mass snmp scanner
    apt install -y braa

#--------------------------------------------------------------------------------------------------
#ssh
RUN pip3 install ssh-audit

#--------------------------------------------------------------------------------------------------
#IPMI 
RUN apt update && \

    # ipmitool - snmpwalk: snmp query tool
    apt install -y ipmitool

#--------------------------------------------------------------------------------------------------
# EOF
