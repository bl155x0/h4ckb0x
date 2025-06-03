#--------------------------------------------------------------------------------------------------
# - h4ckb0x - A simple hacking environment -
#--------------------------------------------------------------------------------------------------

FROM docker.io/ubuntu:22.04
LABEL Description="h4ckb0x: A simple hacking environment as docker image."

#--------------------------------------------------------------------------------------------------

# basic system tools we need
RUN apt update && apt upgrade -y && \
    export DEBIAN_FRONTEND=noninteractive && \
    apt install iputils-ping fping unzip vim tree netcat ncat socat curl wget git net-tools whois swaks telnet faketime -y && \ 
    apt install jq -y && \
    apt install 7zip -y && \
    apt install dnsutils -y && \
    apt install libgbm1 -y && \
    apt install rsync -y && \
    apt install libxkbcommon-x11-0 -y && \
    apt install ftp nfs-common -y && \
    apt install mlocate -y && \
    apt install sudo -y && \
    apt install alien -y && \
    apt install ldap-utils -y && \
    apt install -y openssh-server && mkdir -p /run/sshd && chmod 0755 /run/sshd

#Home directory
ADD data /root
WORKDIR /root

#prepare useful directories
RUN mkdir /root/.ssh

#bashrc
RUN echo "PATH=\$PATH:/root/opt/bin:/opt/node-v20.12.0-linux-x64/bin/" >> /root/.bashrc &&  \
    echo "export RECONAUT_TEMPLATES=/root/reconaut-templates/" >> /root/.bashrc &&  \
    echo "PS1='\[\033[0;31m\]\u \e[31m$(parse_if_root)\[\033[0;37m\]at \[\033[0;31m\]h4ckb0x \[\033[0;37m\]in \[\033[0;31m\]\w \[\033[1;35m\]$(parse_git_branch)\n\[\033[1;35m\] \[\033[0m\]'" >> /root/.bashrc && \
    echo "PATH=\$PATH:/root/.local/bin" >> /root/.bashrc && \
    echo "cat /root/etc/motd" >> /root/.bashrc && \
    echo "alias p='ping -c 1'" >> /root/.bashrc && \ 
    echo "alias nmapq='nmap -n -sC -sV'" >> /root/.bashrc && \
    echo "alias eslintsec='eslint -c ~/eslint-security-scanner-configs/eslintrc-light.js *.js'" >> /root/.bashrc && \
    echo "alias ffufu='ffuf -H \"User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0\"'" >> /root/.bashrc  && \
    echo "alias smuggler='/root/opt/smuggler/smuggler.py'" >> /root/.bashrc && \
    echo "alias reconspider='python3 /root/opt/bin/ReconSpider.py'" >> /root/.bashrc && \
    echo "alias msfconsole='msfconsole -x \"db_connect msfuser:\$POSTGRES_MSFDB_PASS@127.0.0.1:5432/msfdb; db_status\"'" >> /root/.bashrc && \
    echo "alias nocolor='sed -E \"s/\x1B\[[0-9;]*m//g\"'" >> /root/.bashrc

#--------------------------------------------------------------------------------------------------
## Other Shells
RUN apt update && \

  # PowerShell
  wget -P /tmp https://github.com/PowerShell/PowerShell/releases/download/v7.4.7/powershell_7.4.7-1.deb_amd64.deb -O /tmp/ps.deb && \
  dpkg -i /tmp/ps.deb

#--------------------------------------------------------------------------------------------------
## programming languages
RUN apt update && \
    # Python
    apt install -y python3 python3-pip && pip3 install requests && \

    # Python2
    apt install -y python2.7 && \

    # Go
    wget -P /tmp https://go.dev/dl/go1.23.1.linux-amd64.tar.gz && \ 
    tar -C /usr/local -xzf /tmp/go1.23.1.linux-amd64.tar.gz   && \
    rm /tmp/go1.23.1.linux-amd64.tar.gz && \
    ln -s /usr/local/go/bin/go /usr/bin/go && \

    # Java
    apt install openjdk-17-jdk openjdk-17-jre -y && \

    # Ruby
    apt install ruby-dev -y && \
    gem install bundler && \

    # php 
    export DEBIAN_FRONTEND=noninteractive && \
    apt install php -y  && \

    # gdb and PEDA gdb utils 
    apt install gdb -y && \
    git clone --depth 1 https://github.com/longld/peda.git ~/opt/peda && \
    echo "source ~/opt/peda/peda.py" >> ~/.gdbinit

#--------------------------------------------------------------------------------------------------
#Wordlists

RUN apt update && \

    # rockyou
    tar xzf opt/wordlists/rockyou.txt.tgz -C opt/wordlists/ && rm opt/wordlists/rockyou.txt.tgz && \

    # SecLists
    git clone --depth 1 https://github.com/danielmiessler/SecLists.git /root/opt/wordlists/SecLists && \

    # n0kovo subdomain
    git clone --depth 1  https://github.com/n0kovo/n0kovo_subdomains /root/opt/wordlists/n0kovo && \

    # insidetrust's user-name SecLists
    git clone --depth 1 https://github.com/insidetrust/statistically-likely-usernames.git /root/opt/wordlists/statistically-likely-usernames && \

    # creds: Default password database / tool
    pip3 install defaultcreds-cheat-sheet && \

    # custom wordlists generator
    apt install cewl -y && \

    # cupp - comon user password profiler
    apt install cupp -y 

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

    # subbrute
    git clone --depth 1 https://github.com/TheRook/subbrute.git /root/opt/subbrute && \

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
    rm -rf /tmp/dnsenum && \

    # fierce DNS recon tool
    pip install fierce && \

    # adidnsdump- Windows AD DNS enumeration
    git clone --depth 1 https://github.com/dirkjanm/adidnsdump.git /tmp/adidnsdump && \
    cp /tmp/adidnsdump/adidnsdump/dnsdump.py /root/opt/bin/adidnsdump && \
    chmod u+x /root/opt/bin/adidnsdump

#--------------------------------------------------------------------------------------------------
# URL/File Enumeration

     # katana - Spider and Crawler
RUN /usr/local/go/bin/go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    mv go/bin/katana opt/bin/ && \
    rm -rf /root/go && \

    # Recon Spider
    pip3 install scrapy && \
    cd /tmp && wget -O ReconSpider.zip https://academy.hackthebox.com/storage/modules/144/ReconSpider.v1.2.zip && \
    unzip ReconSpider.zip && mv ./ReconSpider.py /root/opt/bin/ && \
    cd - && rm -rf /tmp/* && \

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
    /root/opt/eyewitness/Python/setup/setup.sh  &&\

    # shortscan - IIS 8.3 enumeration
    /usr/local/go/bin/go install github.com/bitquark/shortscan/cmd/shortscan@latest && \
    /usr/local/go/bin/go install github.com/bitquark/shortscan/cmd/shortutil@latest && \
    mv go/bin/shortscan opt/bin/ && \
    mv go/bin/shortutil opt/bin/ && \
    rm -rf /root/go

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

    # WAF detection scanner
    pip install git+https://github.com/EnableSecurity/wafw00f.git && \

    # sqlamp SQLi scanner
    apt install sqlmap -y && \

    # sql map ws support
    pip install websocket-client && \

    # xssstrike XSS scanner
    wget -P /tmp "https://github.com/s0md3v/XSStrike/archive/refs/tags/3.1.5.tar.gz" && \
    tar -C /root/opt -xvzf /tmp/3.1.5.tar.gz && \
    chmod u+x /root/opt/XSStrike-3.1.5/xsstrike.py && \
    ln -s /root/opt/XSStrike-3.1.5/xsstrike.py /root/opt/bin/xssstrike && \
    rm /tmp/3.1.5.tar.gz && \

    # Droopescan - CMS plugin scanner
    pip install droopescan && \

    # Joomlascan
    # pip2 install requests bs4 certifi urllib3 && \
    git clone --depth 1 https://github.com/drego85/JoomlaScan.git  /root/opt/Joomlascan && \

    # lynis - linux auditing tool 
    cd /tmp/ &&  git clone --depth 1 https://github.com/CISOfy/lynis.git && \
    mkdir -p /var/www/linux && tar cvzf lynis.tgz lynis/ && mv lynis.tgz /var/www/linux/lynis.tgz && \
    cd / && rm -rf /tmp/lynis

#--------------------------------------------------------------------------------------------------
# Auto Recon tools

RUN cd /tmp && \ 

  # final-recon
  git clone --depth 1 https://github.com/thewhiteh4t/FinalRecon.git && \
  cd FinalRecon && pip3 install -r requirements.txt && chmod +x ./finalrecon.py && \
  mv /tmp/FinalRecon /root/opt/ && ln -s /root/opt/FinalRecon/finalrecon.py ~/opt/bin/finalrecon

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
# Crackers and other password tools

RUN apt update && \ 

    # hydra
    # genaral cracker
    #hdydra requires debconf which comes with an interactive q&a installation by default. 
    #we don't want this so we set DEBIAN_FRONTEND to "noninteractive"
    DEBIAN_FRONTEND=noninteractive apt install -y hydra && \

    # medusa
    apt install medusa -y && \

    # hashcat hash cracker
    apt install hashcat -y && \

    # john
    apt -y install libssl-dev && \
    git clone --depth 1 https://github.com/openwall/john.git /tmp/john && \
    cd /tmp/john/src && ./configure && make -sj4 && mkdir -p /root/opt/john &&  \
    cp -R /tmp/john/run/* /root/opt/john && \
    rm -rf /tmp/john && \
    cd - && \

    # rulesets for mutating wordlists
    wget https://raw.githubusercontent.com/stealthsploit/OneRuleToRuleThemStill/refs/heads/main/OneRuleToRuleThemStill.rule -O /root/opt/rulesets/OneRuleToRuleThemStill.rule && \

    # username-anarchy - tool for creating username lists
    cd /tmp/ && wget https://github.com/urbanadventurer/username-anarchy/archive/refs/tags/v0.6.zip && \
    unzip v0.6.zip -d /root/opt && \
    ln -s /root/opt/username-anarchy-0.6/username-anarchy /root/opt/bin/username-anarchy && \
    rm v0.6.zip && cd - && \

    # pypycatzs - Mimikatz implementation in pure Python. 
    # Usefull for extracting secrets from memory dumps 
    pip3 install pypykatz && \

    # o365spray
    git clone --depth 1 https://github.com/0xZDH/o365spray.git /root/opt/o365spray && \
    chmod u+x /root/opt/o365spray/o365spray.py && \

    # kerbrute - Kerberos based bruteforce and enumeration tool
    git clone --depth 1 https://github.com/ropnop/kerbrute.git /tmp/kerbrute && \
    cd /tmp/kerbrute && make linux && \
    mv /tmp/kerbrute/dist/kerbrute_linux_amd64 /root/opt/bin/kerbrute && \
    ## download windows binaries as well
    mkdir -p /var/www/windows && cd /var/www/windows \
    wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_windows_386.exe && \
    wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_windows_amd64.exe  && \
    cd -

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
    rm /tmp/msfinstall && \
    cp /opt/metasploit-framework/embedded/framework/data/wordlists/http_default_pass.txt /root/opt/wordlists/ && \

    # Exploits
    mkdir -p /root/opt/exploits && \
    # noPac - Windows DC exploitation 
    git clone --depth 1 https://github.com/Ridter/noPac /root/opt/exploits/noPac && \
    # PrintNightmare
    git clone --depth 1 https://github.com/cube0x0/CVE-2021-1675.git /root/opt/exploits/printNightmare && \
    # Petit Potam
    git clone --depth 1 https://github.com/topotam/PetitPotam.git /root/opt/exploits/petitPotam && \
    mkdir -p /var/www/windows && cp /root/opt/exploits/petitPotam/PetitPotam.exe /var/www/windows  && \
    # Potato exploits
    mkdir -p /root/opt/exploits/JuicyPotato && cd /root/opt/exploits/JuicyPotato && \
    wget https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe && \
    cp /root/opt/exploits/JuicyPotato/JuicyPotato.exe /var/www/windows/ && \
    # Print Spoofer
    mkdir -p /root/opt/exploits/PrintSpoofer && cd /root/opt/exploits/PrintSpoofer && \
    wget https://github.com/dievus/printspoofer/raw/refs/heads/master/PrintSpoofer.exe && \
    cp /root/opt/exploits/PrintSpoofer/PrintSpoofer.exe /var/www/windows

#--------------------------------------------------------------------------------------------------
# Web Shells
Run mkdir -p /root/opt/web-shells/ && git clone --depth 1 https://github.com/jbarcia/Web-Shells /tmp/Web-Shells && \
  
  # laudanum
  mv /tmp/Web-Shells/laudanum /root/opt/web-shells/laudanum && \
  rm -rf /tmp/Web-Shells && \

  # wwwolf-php-webshell
  git clone --depth 1 https://github.com/WhiteWinterWolf/wwwolf-php-webshell /root/opt/web-shells/wwwolf-php-webshell && \

  # phpbash
  git clone --depth 1 https://github.com/Arrexel/phpbash.git /root/opt/web-shells/phpbash

#--------------------------------------------------------------------------------------------------
# Other Remote Shells 

Run mkdir -p /root/opt/reverse-shells && \

  # splunk reverse shell
  git clone --depth 1 https://github.com/0xjpuff/reverse_shell_splunk.git /root/opt/reverse-shells/reverse_shell_splunk

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
   apt install -y fzf && \
   git clone --depth 1 https://github.com/bl155x0/findwordlist.git /tmp/findwordlist && \
   cd /tmp/findwordlist && /usr/local/go/bin/go build && \
   chmod u+x findwordlist && mv findwordlist /root/opt/bin/findwordlist && \
   mv findwl /root/opt/bin/findwl && \
   echo "#findwl" >> /root/.bashrc && \
   echo "source /root/opt/bin/findwl" >> /root/.bashrc && \
   rm -rf /tmp/findwordlist && cd - && \

   # godork
   git clone --depth 1 https://github.com/bl155x0/godork.git /tmp/godork && \
   cd /tmp/godork && /usr/local/go/bin/go build && \
   chmod u+x godork && mv godork /root/opt/bin && \
   mv dorks.txt /root/opt/wordlists && \
   echo -n 'export GODORK_DORKFILE="/root/opt/wordlists/dorks.txt"' >> /root/.bashrc && \
   rm -rf /tmp/godork && cd - && \

  # gocrtsh
   git clone --depth 1 https://github.com/bl155x0/gocrtsh.git /tmp/gocrtsh && \
   cd /tmp/gocrtsh && /usr/local/go/bin/go build && \
   chmod u+x gocrtsh && mv gocrtsh /root/opt/bin && \
   rm -rf /tmp/gocrtsh && cd -

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
RUN mkdir -p /var/www/linux && mkdir -p /var/www/windows/ && \
   # linux
   wget -P /var/www/linux/ https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh && \
   wget -P /var/www/linux/ https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64 && \
   wget -P /var/www/linux/ https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat && \
   wget -P /var/www/linux/ https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/ncat && \
   wget -P /var/www/linux/ https://raw.githubusercontent.com/AlessandroZ/LaZagne/refs/heads/master/Linux/laZagne.py && \
   wget -P /var/www/linux/ https://raw.githubusercontent.com/huntergregal/mimipenguin/refs/heads/master/mimipenguin.py && \
   wget -P /var/www/linux/ https://raw.githubusercontent.com/huntergregal/mimipenguin/refs/heads/master/mimipenguin.sh && \
   wget -P /var/www/linux/ https://raw.githubusercontent.com/CiscoCXSecurity/linikatz/master/linikatz.sh && \
   wget -P /var/www/linux/ https://master.dockerproject.org/linux/x86_64/docker && \

   # windows
   wget -P /var/www/windows/ https://raw.githubusercontent.com/peass-ng/PEASS-ng/master/winPEAS/winPEASps1/winPEAS.ps1 && \
   wget -P /var/www/windows/ https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASany_ofs.exe && \
   wget -P /var/www/windows/ https://github.com/int0x33/nc.exe/raw/master/nc.exe && \
   wget -P /var/www/windows/ https://github.com/int0x33/nc.exe/raw/master/nc64.exe && \
   wget -P /var/www/windows/ https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1 && \
   wget -P /var/www/windows/ https://raw.githubusercontent.com/bl155x0/PowerShellHacks/refs/heads/main/Invoke-AESEncryption.ps1 && \
   wget -P /var/www/windows/ https://raw.githubusercontent.com/bl155x0/PowerShellHacks/refs/heads/main/Invoke-PowerShellTcp.ps1 && \
   wget -P /var/www/windows/ https://github.com/AlessandroZ/LaZagne/releases/download/v2.4.6/LaZagne.exe && \
   wget -P /var/www/windows/ https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/refs/heads/master/Recon/PowerView.ps1 && \
   wget -P /var/www/windows/ https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/refs/heads/master/Exfiltration/Get-GPPPassword.ps1 && \
   wget -P /var/www/windows/ https://raw.githubusercontent.com/Kevin-Robertson/Invoke-TheHash/refs/heads/master/Invoke-TheHash.ps1 && \
   wget -P /var/www/windows/ https://raw.githubusercontent.com/Kevin-Robertson/Invoke-TheHash/refs/heads/master/Invoke-SMBExec.ps1 && \
   wget -P /var/www/windows/ https://raw.githubusercontent.com/Kevin-Robertson/Invoke-TheHash/refs/heads/master/Invoke-SMBEnum.ps1 && \
   wget -P /var/www/windows/ https://raw.githubusercontent.com/Kevin-Robertson/Invoke-TheHash/refs/heads/master/Invoke-SMBClient.ps1 && \
   wget -P /var/www/windows/ https://raw.githubusercontent.com/Kevin-Robertson/Invoke-TheHash/refs/heads/master/Invoke-WMIExec.ps1 && \
   wget -P /var/www/windows/ https://raw.githubusercontent.com/Kevin-Robertson/Invoke-TheHash/refs/heads/master/Invoke-TheHash.psd1 && \
   wget -P /var/www/windows/ https://raw.githubusercontent.com/Kevin-Robertson/Invoke-TheHash/refs/heads/master/Invoke-TheHash.psm1 && \
   wget -P /var/www/windows/ https://raw.githubusercontent.com/lukebaggett/dnscat2-powershell/refs/heads/master/dnscat2.ps1 && \
   wget -P /var/www/windows/ https://raw.githubusercontent.com/dafthack/DomainPasswordSpray/refs/heads/master/DomainPasswordSpray.ps1 && \
   wget -P /var/www/windows/ https://raw.githubusercontent.com/leoloobeek/LAPSToolkit/refs/heads/master/LAPSToolkit.ps1 && \
   wget -P /var/www/windows/ https://raw.githubusercontent.com/NetSPI/PowerUpSQL/refs/heads/master/PowerUpSQL.ps1 && \
   wget -P /var/www/windows/ https://www.proxifier.com/download/ProxifierPE.zip && \
   wget -P /var/www/windows/socksOverRdp/x86 https://github.com/nccgroup/SocksOverRDP/releases/download/v1.0/SocksOverRDP-x86.zip && unzip /var/www/windows/socksOverRdp/x86/SocksOverRDP-x86.zip -d /var/www/windows/socksOverRdp/x86 && \
   wget -P /var/www/windows/socksOverRdp/x64 https://github.com/nccgroup/SocksOverRDP/releases/download/v1.0/SocksOverRDP-x64.zip && unzip /var/www/windows/socksOverRdp/x64/SocksOverRDP-x64.zip -d /var/www/windows/socksOverRdp/x64 && \
   wget -P /var/www/windows/ https://github.com/SnaffCon/Snaffler/releases/download/1.0.184/Snaffler.exe && \
   wget -P /var/www/windows/ https://github.com/SpecterOps/BloodHound-Legacy/raw/refs/heads/master/Collectors/SharpHound.exe && \
   wget -P /var/www/windows/ https://gitlab.com/kalilinux/packages/mimikatz/-/raw/d72fc2cca1df23f60f81bc141095f65a131fd099/Win32/mimikatz.exe -O /var/www/windows/mimikatz.exe && \
   wget -P /var/www/windows/ https://gitlab.com/kalilinux/packages/mimikatz/-/raw/d72fc2cca1df23f60f81bc141095f65a131fd099/x64/mimikatz.exe -O /var/www/windows/mimikatz64.exe && \
   wget -P /var/www/windows/ https://github.com/Group3r/Group3r/releases/download/1.0.67/Group3r.exe && \
   wget -P /var/www/windows/ https://raw.githubusercontent.com/adrecon/ADRecon/refs/heads/master/ADRecon.ps1 && \
   wget -P /var/www/windows/ https://raw.githubusercontent.com/decoder-it/psgetsystem/refs/heads/master/psgetsys.ps1 && \
   wget -P /var/www/windows/ https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/refs/heads/master/EnableAllTokenPrivs.ps1 && \
   wget -P /var/www/windows/ https://download.sysinternals.com/files/PSTools.zip && \

  # socat windows
  git clone --depth 1 https://github.com/tech128/socat-1.7.3.0-windows.git /tmp/socat && \
  cd /tmp/ && zip -r socat.zip socat && rm -rf socat && \
  mv socat.zip /var/www/windows && \
  cd / && \

  # Combine all poweshell stuff for convenience 
  zip -r /var/www/windows/powershell.zip /var/www/windows -i "*.ps1" "*.psd1" "*.psm1" && \

  # also install an upload server to receive files via http
  pip3 install uploadserver && \

  # A WebDAV server for alternative file transfer via http
  pip3 install wsgidav cheroot

  # Add additional local stuff 
  COPY var/www/windows/* /var/www/windows/
#--------------------------------------------------------------------------------------------------
# Database - SQL 
RUN apt update && \ 

    #mysql client
    apt install mysql-client -y && \

    # sqsh for MS SQL and Sybase 
    apt install sqsh -y && \

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
    cd - && \
    ln -s /root/opt/responder/Responder.py /root/opt/bin/responder && \

    # make responder available as download if we need to transfer it to a linux jump host
    cd /root/opt/&& tar cvzf responder.tgz responder && mv responder.tgz /var/www/linux && cd - && \

    # Inveight 
    mkdir -p /tmp/inveight && wget https://github.com/Kevin-Robertson/Inveigh/releases/download/v2.0.11/Inveigh-net4.6.2-v2.0.11.zip -P /tmp/inveight && \
    cd /tmp/inveight && unzip Inveigh-net4.6.2-v2.0.11.zip && \
    mkdir -p /var/www/windows && mv /tmp/inveight/Inveigh.exe /var/www/windows/Inveight-net4.6.2.exe && \

    # RDP
    cpanm Encoding::BER && \
    git clone --depth 1 https://github.com/CiscoCXSecurity/rdp-sec-check.git /root/opt/rdp-sec-check && \
    ln -s /root/opt/rdp-sec-check/rdp-sec-check.pl /root/opt/bin/rdp-sec-check.pl && \

    # evil-winrm for a WinRM shell
    gem install evil-winrm && \

    # Nishang offensive Powershell scripts  inkl. "Antak" Web Shells
    git clone --depth 1 https://github.com/samratashok/nishang /root/opt/nishang && \
    ln -s /root/opt/nishang/Shells/ /root/opt/reverse-shells/nishang && \

    # netexec
    export DEBIAN_FRONTEND=noninteractive && \
    apt install -y pipx git && \
    pipx ensurepath && \
    pipx install git+https://github.com/Pennyw0rth/NetExec && \

    # bloodhound
    pip install bloodhound-ce && \

    # Certipy - offensive tool for enumerating and attacking AD CS (Active Directory certificate Service)
    pip3 install certipy-ad && \

    # pyGPOAbuse - A tool to abuse writable GPO
    git clone --depth 1 https://github.com/Hackndo/pyGPOAbuse.git /root/opt/pyGPOAbuse 

#--------------------------------------------------------------------------------------------------
# Kerberos
  
    # keytabextract is a tool for extracting usefull information from keyberos keytab files on linux
RUN wget https://raw.githubusercontent.com/sosdave/KeyTabExtract/refs/heads/master/keytabextract.py -P /root/opt/bin/ && \
    chmod u+x /root/opt/bin/keytabextract.py && \

    # Kerberos Authentication Package (klist and support for other tooling)
    export DEBIAN_FRONTEND=noninteractive && \
    apt install -y krb5-user && \

    # targetedKerberoast - a tool for adding fake SPN to an use account
    cd /tmp && git clone https://github.com/ShutdownRepo/targetedKerberoast.git && \
    cd /tmp/targetedKerberoast && pip install -r requirements.txt && \
    mv targetedKerberoast.py ~/opt/bin && cd - && rm -rf /tmp/targetedKerberoast && \

    # PKINITtools, like gettgtpkinit, for getting a TGT by presenting a certificate
    git clone --depth 1 https://github.com/dirkjanm/PKINITtools /root/opt/PKINITtools
  
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
    pip3 install smbmap && \

    # python based ftp server for file transfer
    pip3 install pyftpdlib

#--------------------------------------------------------------------------------------------------
# LDAP
RUN apt update && \

  apt install -y python3-ldap && \
  git clone --depth 1 https://github.com/ropnop/windapsearch.git  /root/opt/windapsearch && \
  ln -s /root/opt/windapsearch/windapsearch.py /root/opt/bin/windapsearch 

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
    #Tool  for auditing ssh servers
RUN pip3 install ssh-audit

#--------------------------------------------------------------------------------------------------
#IPMI 
RUN apt update && \

    # ipmitool - tool to interact with IPMI devices 
    apt install -y ipmitool

#--------------------------------------------------------------------------------------------------
# Network tooling
RUN apt update && \
    # proxychaings - socks proxy tooling
    apt install -y proxychains4 && \
    echo "strict_chain\nproxy_dns\nremote_dns_subnet 224\ntcp_read_time_out 15000\ntcp_connect_time_out 8000\n[ProxyList]\nsocks5  127.0.0.1 1080" > /etc/proxychains4.conf && \ 

    # chisel  - build it for: linux, linux staticly linked, windows x86, windows x64 
    wget -P /tmp/ https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_linux_amd64.deb && \
    dpkg -i /tmp/chisel_1.10.1_linux_amd64.deb && \
    # also clone it so that we can compile clients for various target platforms manually  
    git clone --depth 1 https://github.com/jpillora/chisel.git /root/opt/chisel && \
    cd /root/opt/chisel && \
    /usr/local/go/bin/go build && cp /root/opt/chisel/chisel /var/www/linux/ && \
    CGO_ENABLED=0  /usr/local/go/bin/go build -ldflags "-extldflags '-static'" -o chisel-static && cp /root/opt/chisel/chisel-static /var/www/linux && \
    GOOARCH="amd64" GOOS="windows" /usr/local/go/bin/go  build -o chisel-x64.exe && cp /root/opt/chisel/chisel-x64.exe /var/www/windows/ && \
    GOOARCH="386" GOOS="windows" /usr/local/go/bin/go build -o chisel-x86.exe && cp /root/opt/chisel/chisel-x86.exe /var/www/windows/ && \
    cd - && \

    # rpivot
    git clone --depth 1 https://github.com/klsecservices/rpivot.git /root/opt/rpivot && \

    # dnscat2 - tunneling and traffic hiding via DNS - build the dnsclient staticly linked
    git clone --depth 1 https://github.com/iagox86/dnscat2.git /root/opt/dnscat2 && \
    cd /root/opt/dnscat2/server && bundle install && \ 
    cd /root/opt/dnscat2/client && sed -i 's/^LDFLAGS=\(.*\)/LDFLAGS=\1 -static/' Makefile && make && \
    mkdir -p /var/www/linux/ && cp /root/opt/dnscat2/client/dnscat  /var/www/linux && \
    cd - && \

    # ptunnel-ng for ICMP tunneling - bulding from source as static linked binary!
    git clone --depth 1 https://github.com/utoni/ptunnel-ng.git /root/opt/ptunnel-ng && \
    cd /root/opt/ptunnel-ng && \
    sed -i '$s/.*/LDFLAGS=-static "${NEW_WD}\/configure" --enable-static $@ \&\& make clean \&\& make -j${BUILDJOBS:-4} all/' autogen.sh && \
    ./autogen.sh && \
    cp /root/opt/ptunnel-ng/src/ptunnel-ng /root/opt/bin && \
    mkdir -p /var/www/linux && cp /root/opt/bin/ptunnel-ng /var/www/linux && \
    cd - && \

    # ligolo-ng
    wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.7.5/ligolo-ng_proxy_0.7.5_linux_amd64.tar.gz -O /tmp/ligolo-ng.tar.gz && \
    cd /tmp/ && tar xvzf ligolo-ng.tar.gz && cp proxy /root/opt/bin/ligolo-proxy && cd - && \
    rm -rf /tmp/* && \
    wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.7.5/ligolo-ng_agent_0.7.5_linux_amd64.tar.gz -O /tmp/ligolo-agent.tar.gz && \
    cd /tmp/ && tar xf ligolo-agent.tar.gz && mv agent /var/www/linux/ligolo-agent && cd - && \
    rm -rf /tmp/* && \
    wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.7.5/ligolo-ng_agent_0.7.5_windows_amd64.zip -O /tmp/ligolo-agent.zip && \ 
    cd /tmp/ && unzip ligolo-agent.zip && mv agent.exe /var/www/windows/ligolo-agent.exe && cd - && \
    rm -rf /tmp/*

#--------------------------------------------------------------------------------------------------
# additional compression tools
RUN cd /tmp && \
  
  # rarlinux
  wget https://www.rarlab.com/rar/rarlinux-x64-612.tar.gz && \
  tar xvzf rarlinux-x64-612.tar.gz && \
  cp ./rar/rar /root/opt/bin &&  \
  cp ./rar/unrar /root/opt/bin && \
  rm -rf /tmp/rar && rm /tmp/rarlinux-x64-612.tar.gz && \

  # upx packer
  wget https://github.com/upx/upx/releases/download/v4.2.4/upx-4.2.4-amd64_linux.tar.xz && \
  tar xvf upx-4.2.4-amd64_linux.tar.xz && \
  mv /tmp/upx-4.2.4-amd64_linux/upx /root/opt/bin/ && \
  rm -rf /tmp/upx-4.2.4-amd64_linux

#--------------------------------------------------------------------------------------------------
# crypto tools
RUN cd && \
  # gpp-decrypt.rb - a simple tool to encrypt Group Policy Preferences passwords using MS default AES key  
  mkdir -p /root/opt/gpp-decrypt/ && cd /root/opt/gpp-decrypt && \
  wget 'https://gitlab.com/kalilinux/packages/gpp-decrypt/-/raw/kali/master/gpp-decrypt.rb' && \
  chmod u+x /root/opt/gpp-decrypt/gpp-decrypt.rb

#--------------------------------------------------------------------------------------------------
# Obfuscation tools
RUN cd /tmp && \ 

  # Bashfuscator
  git clone --depth=1 https://github.com/Bashfuscator/Bashfuscator /tmp/bf && \
  cd /tmp/bf && python3 setup.py install --user || true && \
  rm -rf /tmp/bf  && \

  # Invoke-DOSfuscation v1.0
  # requires Powershell
  cd /root/opt && \
  git clone --depth=1 https://github.com/danielbohannon/Invoke-DOSfuscation.git

#--------------------------------------------------------------------------------------------------
# XML and XEE injection tooling
RUN cd /tmp && \
  
  # XXEinjector
  git clone https://github.com/enjoiz/XXEinjector.git && \
  mv /tmp/XXEinjector/XXEinjector.rb /root/opt/bin/XXEinjector && \
  chmod u+x /root/opt/bin/XXEinjector && \
  rm -rf /tmp/XXEinjector

#--------------------------------------------------------------------------------------------------
# Docker an  Kubernetes related tooling
Run cd /tmp && \

  # kubeletctl
  curl -LO https://github.com/cyberark/kubeletctl/releases/download/v1.13/kubeletctl_linux_amd64 && \
  chmod u+x kubeletctl_linux_amd64 && \
  cp kubeletctl_linux_amd64 /root/opt/bin/kubeletctl && \
  mv kubeletctl_linux_amd64 /var/www/linux/kubeletctl

#--------------------------------------------------------------------------------------------------
# EOF
