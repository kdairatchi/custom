sudo apt install git -y
sudo apt install stacer -y
sudo apt install plank -y
sudo apt install terminator -y
sudo apt install nmap -y
sudo apt install copyq -y
sudo apt install vlc -y
sudo apt install flameshot -y
sudo apt install obs-studio -y
sudo apt install v4l2loopback-dkms -y
sudo apt install netcat -y
sudo apt install net-tools -y
sudo apt install filezilla -y
echo "FFUF Installing"
sudo wget https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz -O /opt/ffuf.tar.gz
sudo mkdir -p /opt/ffuf
sudo tar -xvzf /opt/ffuf.tar.gz --directory=/opt/ffuf/
sudo chmod +x /opt/ffuf/ffuf
sudo ln -sf /opt/ffuf/ffuf /usr/local/bin/ffuf
ffuf -h
echo "#################### Done ####################"

echo "Dirsearch Installing"
sudo apt install pip -y
sudo git clone https://github.com/maurosoria/dirsearch.git /opt/dirsearch
cd /opt/dirsearch/
sudo pip install -r requirements.txt
sudo python3 setup.py install
cd
sudo ln -sf /opt/dirsearch/dirsearch.py /usr/local/bin/dirsearch
dirsearch -h
echo "#################### Done ####################"

echo "wpscan Installing"
sudo apt install build-essential libcurl4-openssl-dev libxml2 libxml2-dev libxslt1-dev ruby-dev -y
sudo apt install ruby-full -y
sudo gem install wpscan
wpscan -h
echo "#################### Done ####################"

echo "nikto Installing"
sudo git clone https://github.com/sullo/nikto.git /opt/nikto
sudo ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto
nikto --help
echo "#################### Done ####################"

echo "nuclei Installing"
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest                                     ─╯
sudo mv go/bin/nuclei /opt/
sudo ln -sf /opt/nuclei /usr/local/bin/nuclei
nuclei -h
echo "#################### Done ####################"

echo "SQLmap"
sudo git clone https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap
sudo ln -sf /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap
sqlmap -h
# sudo nano /opt/sqlmap/sqlmap.py
# #!/usr/bin/env python3
echo "#################### Done ####################"

echo "searchsploit"
sudo git clone https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb
sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit
cd
searchsploit -h
echo "#################### Done ####################"


echo "hydra"
sudo git clone https://github.com/vanhauser-thc/thc-hydra.git /opt/hydra && cd /opt/hydra/
sudo ./configure
sudo DWITH_SSH1=On make
sudo make install
cd
sudo apt install libssl-dev libssh-dev libidn11-dev libpcre3-dev libgtk2.0-dev libmysqlclient-dev libpq-dev libsvn-dev firebird-dev libmemcached-dev libgpg-error-dev libgcrypt20-dev -y
hydra -h
echo "#################### Done ####################"


echo "dalfox"
go install github.com/hahwul/dalfox/v2@latest
sudo mv go/bin/dalfox /opt/
sudo ln -sf /opt/dalfox /usr/local/bin/dalfox
dalfox -h
echo "#################### Done ####################"


# go install github.com/tomnomnom/gf@latest
# sudo mv go/bin/gf /usr/local/bin/

echo "subfinder"
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
sudo mv go/bin/subfinder /opt/
sudo ln -sf /opt/subfinder /usr/local/bin/subfinder
subfinder -h
echo "#################### Done ####################"

go install github.com/gwen001/github-subdomains@latest
sudo mv go/bin/github-subdomains /opt/
sudo ln -sf /opt/github-subdomains /usr/local/bin/githubsubdomains
githubsubdomains -h


go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
sudo mv go/bin/dnsx /opt/
sudo ln -sf /opt/dnsx /usr/local/bin/dnsx
dnsx -h

go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
sudo mv go/bin/httpx /opt/
sudo ln -sf /opt/httpx /usr/local/bin/httpx
httpx -h

sudo git clone https://github.com/xnl-h4ck3r/waymore.git /opt/waymore
cd /opt/waymore
sudo pip install -r requirements.txt
sudo python3 ./setup.py install
cd
sudo ln -sf /opt/waymore/waymore.py /usr/local/bin/waymore

go install github.com/tomnomnom/waybackurls@latest
sudo mv go/bin/waybackurls /opt/
sudo ln -sf /opt/waybackurls /usr/local/bin/waybackurls
waybackurls -h

go install github.com/tomnomnom/qsreplace@latest
sudo mv go/bin/qsreplace /opt/
sudo ln -sf /opt/qsreplace /usr/local/bin/qsreplace
qsreplace -h

sudo git clone https://github.com/m4ll0k/SecretFinder.git /opt/secretfinder
cd /opt/secretfinder
sudo pip install -r requirements.txt
cd
sudo ln -sf /opt/secretfinder/SecretFinder.py /usr/local/bin/secretfinder
sudo chmod +x /opt/secretfinder/SecretFinder.py
secretfinder -h

go install github.com/haccer/subjack@latest
sudo mv go/bin/subjack /opt/
sudo ln -sf /opt/subjack /usr/local/bin/subjack
sudo mkdir -p /src/github.com/haccer/subjack
cd /src/github.com/haccer/subjack/
sudo wget https://raw.githubusercontent.com/haccer/subjack/master/fingerprints.json
cd
subjack -h

sudo git clone https://github.com/s0md3v/uro.git /opt/uro
cd /opt/uro
sudo python3 setup.py install
cd
uro -h



# echo "Default Credentials Cheat Sheet"
# sudo git clone https://github.com/ihebski/DefaultCreds-cheat-sheet /opt/DefaultCreds-cheat-sheet
# cd /opt/DefaultCreds-cheat-sheet
# pip3 install -r requirements.txt
# sudo python3 ./setup.py install
# cd
# creds -h
# echo "#################### Done ####################"

echo "JWT Tool Installaation"
sudo git clone https://github.com/ticarpi/jwt_tool.git /opt/jwttool
cd /opt/jwttool
pip3 install -r requirements.txt
sudo chmod +x jwt_tool.py
cd
sudo ln -sf /opt/jwttool/jwt_tool.py /usr/local/bin/jwttool
jwttool -h
echo "#################### Done ####################"

echo "OpenRedireX Tool Installaation"
sudo git clone https://github.com/devanshbatham/openredirex /opt/openredirectex
cd /opt/openredirectex
sudo chmod +x *
cd
openredirex -h
echo "#################### Done ####################"

echo "BXSS"
go install github.com/ethicalhackingplayground/bxss@latest
sudo mv go/bin/bxss /opt/
sudo ln -sf /opt/bxss /usr/local/bin/bxss
bxss -h
echo "#################### Done ####################"

# echo "URO"
# sudo git clone https://github.com/s0md3v/uro.git /opt/uro
# cd /opt/uro/
# udo chmod +x setup.py
# sudo python3 ./setup.py install

echo "Open Redirect"
sudo git clone https://github.com/devanshbatham/openredirex /opt/openredirex
cd /opt/openredirex
sudo chmod +x setup.sh
sudo ./setup.sh
cd
openredirex -h
echo "#################### Done ####################"

echo "Path Traversal / LFI"
sudo git clone https://github.com/hansmach1ne/LFImap.git /opt/lfimap
cd /opt/lfimap
pip3 install -r requirements.txt
cd
sudo ln -sf /opt/lfimap/lfimap.py /usr/local/bin/lfimap
lfimap -h
echo "#################### Done ####################"


<details>
    <summary>SQLi</summary>

    ## Ghauri

    ### Installation

    ```
    sudo mkdir -p /opt/sqli
    cd /opt/sqli
    sudo git clone https://github.com/r0oth3x49/ghauri.git
    cd ghauri
    pip3 install -r requirements.txt
    sudo python3 ./setup.py install
    cd
    ghauri -h
    ```

    ### Updating

    ```
    cd /opt/sqli/ghauri/
    sudo git pull
    cd
    ```
    
</details>
