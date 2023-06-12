# BSA
## Prvotní nastavení

```
  setxkbmap cz
  sudo apt install nano
  apt-get install --no-install-recommends
```
Přihlášení
```
  pkill - 9 - f apt-get 
```
Zrušení běžícího procesu
```
  ssh –i id_ecdsa spos@hrkalovh-lin-exam.spos.sgfl.xyz
 
```

## 1. úkol - nastavení klíčů
Přihlášení na server ssh ..
```
sudo su -
cd ~
mkdir .ssh
vim .ssh/authorized_keys
```
zkopírovat veřejný klíč sem, potom
Nastavit sshdconfig
```
vim /etc/ssh/sshd_config

echo "PermitRootLogin without-password
PasswordAuthentication no" >> /etc/ssh/sshd_config
```
Pak restartovat
```
systemctl restart ssh
systemctl restart sshd
```

## Fail2Ban
```
 apt-get install --no-install-recommends fail2ban
```

## Vytvoření skupiny a přidání klíče
Vytvoření skupiny, usera
```
addgroup admins
adduser pepa
usermod -a -G uzivatele pepa
```
Přidání souboru, nastavení bez hesla
```
vim /etc/sudoers.d/bsa

%admins ALL=(ALL:ALL) NOPASSWD:ALL

```
Nastavení klíčů pepovi
```
su - pepa
mkdir .ssh
chmod 700 .ssh
ssh-copy-id pepa@bsa

su - root
cp .ssh/authorized_keys ~pepa/.ssh/
chown pepa:pepa ~pepa/.ssh/authorized_keys

```

## LDAP
```
apt install libnss-ldap libpam-ldap 

apt install slapd ldap-utils ldapscripts 
```
Nastavit heslo na: Heslo123.
```
dpkg-reconfigure -plow slapd 
```
Vytvoříme soubor ou.ldif

Do toho dovnitř, dn musí být jen jednou, objectClass 
```
echo "dn: ou=users,dc=hrkalovh ,dc=bsa 
objectClass: organizationalUnit 
ou: users" >> ou.ldif 
```
Vytvořeni organizacni jednotky ve stromecku 
```
ldapadd -f ou.ldif -D cn=admin,dc=hrkalovh,dc=bsa -w Heslo123.
```
zadat Heslo

### Přidání usera
Vytvořim nový soubor user.ldif 

Do něj přidám tohle
```
echo "dn: uid=pepa,ou=users,dc=hrkalovh,dc=bsa 
uid: pepa 
cn: pepa 
objectClass: account 
objectClass: posixAccount 
objectClass: top 
objectClass: shadowAccount 
userPassword:: heslo123 
shadowLastChange: 14846 
shadowMax: 99999 
shadowWarning: 7 
loginShell: /bin/bash 
uidNumber: 10001 
gidNumber: 10001 
homeDirectory: /home/ldap/pepan" >> user.ldif 
```
Vytvoření uživatele:
```
ldapadd -f user.ldif -D cn=admin,dc=hrkalovh,dc=bsa -w Heslo123.
```
 Znovu vim user.ldif a jen prejmenuji tondu a zmenim id z 1001 na 1002, pak zase add  
 ### Vyhledání v seznamu
```
ldapsearch -D cn=admin,dc=hrkalovh,dc=bsa -w admin123 -b "dc=hrkalovh,dc=bsa" '(objectClass='account')' cn 
ldapsearch -D cn=admin,dc=hrkalovh,dc=bsa -w Heslo123. -b "dc=hrkalovh,dc=bsa" '(objectClass='account')' cn homedirectory 
```

### Nastavení autentizace
```
apt install libnss-ldap libpam-ldap
ldapi://localhost:389
```
dc=hrkalovh,dc=bsa
ldap3
admin jarda bsa
root yes db no
/usr/share/doc/libnss-ldap/examples/nsswitch.ldap
yes


V /etc/pam.d/
soubory common-auth, common-account   ldap required

/etc/init.d/nscd restart
```
su - pepa
curl https://gitlab.com/leheckaj.keys >> ~/.ssh/authorized_keys
ssh -i ~/.ssh/id_rsa tonda@192.168.20.244
```
## LVM - vytvoření logického svazku
```
apt install lvm2 cryptsetup 
#pripadne
pvdisplay
```
vdb je podle toho co je uvnitř slblk - pro všechny disky 
Mame fyzicke volume 
```
pvcreate /dev/sdb
vgcreate data /dev/sdb
lvcreate -L 1G -n encrypted data
```
muzeme delat resize, jde to i relativne 
```
lvresize -L -1G /dev/data/encrypted 
```
## LUKS - šifrování

```
cryptsetup -y -v luksFormat /dev/data/encrypted
cryptsetup luksOpen /dev/data/encrypted db
```
Vznikne novy device, který je rozsifrovan
Muzeme delat mkf
```
mkfs.ext4 /dev/mapper/db
```
pripojim db do mnt, ted se teprve dostanu k datum fyzicky
```
mount /dev/mapper/db /mnt 
```
Uvidim ten mount 
```
df -h 
```
tim to zahodi
```
umount /dev/mapper/db 
cryptsetup luksClose db 
```
Šifrování key filem
```
dd if=/dev/urandom of=db.key bs=1M count=1 
cryptsetup luksAddKey /dev/data/encrypted  db.key 
```
Zeptá se na heslo
Děšifrujeme pomocí key file
```
cryptsetup luksOpen /dev/data/<encrypted> <decrypted> --key-file dec.key
```

### Záloha luks
```
cryptsetup luksHeaderBackup /dev/data/database --header-backup-file /mnt/vgbsa_test.img 

cryptsetup luksHeaderRestore /dev/data/database --header-backup-file /mnt/vgbsa_test.img  
```

## CA
```
apt install easy-rsa
mkdir -p /etc/ca
cp -r /usr/share/easy-rsa/* /etc/ca/ 
```
vlezt do etc ca
```
cd /etc/ca
cp vars.example vars 
vim vars
```
Vložit tohle
```
echo "set_var EASYRSA_REQ_COUNTRY     "CZ" 
set_var EASYRSA_REQ_PROVINCE    "PLzen" 
set_var EASYRSA_REQ_CITY        "Plzen" 
set_var EASYRSA_REQ_ORG "Copyleft Certificate Co" 
set_var EASYRSA_REQ_EMAIL       "me@hrkalova.bsa" 
set_var EASYRSA_REQ_OU          "ZCU BSa"" >> vars
```
Odkomentovat expiraci EASYRSA_CA_EXPIRE EASYRSA_CERT_EXPIRE 

```
echo "set_var EASYRSA_CA_EXPIRE       3650 
# In how many days should certificates expire? 
set_var EASYRSA_CERT_EXPIRE     825" >> vars
```
vytvari certifikat 
```
./easyrsa init-pki 
./easyrsa build-ca 
```
zepta se na heslo - Heslo123.
zepta se na jmeno - BSA Ceritifcate Autohrity 
vytvornei serveru:
```
 ./easyrsa build-server-full private.hrkalovh.bsa
  ./easyrsa build-server-full public.hrkalovh.bsa
 
```
zepta se na heslo 3x 

Odheslovat klíče
```
mv key key.bak # Aby pak šel vytvořit správný název
openssl rsa -in /etc/ca/pki/private/ca.key -out /etc/ca/pki/private/ca.key.in

```
Kontrola certifikatu:
```
openssl x509 -in /etc/ca/pki/issued/private.hrkalovh.bsa.crt -text | less 
```
## NGINX - nastaveni + CA 
```
apt install nginx ca-certificates 
cd /etc/nginx 
openssl rsa -in /etc/ca/pki/private/private.hrkalovh.bsa.key -out /etc/ca/pki/private/private.hrkalovh.bsa.key 
openssl rsa -in /etc/ca/pki/private/public.hrkalovh.bsa.key -out /etc/ca/pki/private/public.hrkalovh.bsa.key 
```
site-avaliable říka co můžeme budeme používat 
```
cd sites-enabled
vim defaultssl
```

```
echo"listen 443 ssl;
listen [::]:443 ssl;
ssl_certificate /etc/ca/pki/issued/public.hrkalovh.bsa.crt;
ssl_certificate_key /etc/ca/pki/private/public.hrkalovh.bsa.key; 
server_name public.hrkalovh.bsa;" >> /etc/nginx/sites-enabled
```

```
listen 80;
listen [::]:80;
server_name private.hrkalovh.bsa;
```

```

cp defaultssl /etc/nginx/sites-enabled
openssl rsa -in server.key -out server.key

nginx -t
service nginx restart 
```

## Apache2 SSL
```
apt install apache2
a2enmod ssl
cd /etc/apache2/sites-enabled/
 
openssl rsa -in /etc/ca/pki/private/private.hrkalovh.bsa.key -out /etc/ca/pki/private/private.hrkalovh.bsa.key

echo "
	<VirtualHost _default_:8543>
		DocumentRoot /var/www/html
		ErrorLog /error.log
		CustomLog /access.log combined
		SSLEngine on

		SSLCertificateFile	/etc/ca/pki/issued/private.hrkalovh.bsa.crt
		SSLCertificateKeyFile /etc/ca/pki/private/private.hrkalovh.bsa.key

	</VirtualHost>" > /etc/apache2/sites-enabled/ssl.conf

echo "Listen 8543" >> /etc/apache/ports.conf

# zkontroluj tohle ještě
a2ensite ssl
service apache2 restart
```
## SSH TUNNEL
šlo by to použít jako vpnka 
stunnel v ssh 
```


Ssh -L 80:192.168.4.160:443 bsa 

Ssh -L 8443:192.168.4.160:443 bsa 

Curl https://localhost:8443 
```
## Stunnel 4

```
apt install stunnel4 
cp /usr/share/doc/stunnel4/examples/stunnel.conf-sample /etc/stunnel/stunnel.conf 
```
 SMAZAT ÚPLNĚ VŠE KOLEM gmailu V TOMTO SOUBORU AKORÁT PŘIDAT TOTO: 

 ```
echo "[https] 
accept=8443 
connect=80 
cert=/etc/ca/pki/issued/private.hrkalovh.bsa.crt 
key=/etc/ca/pki/private/private.hrkalovh.bsa.key" >> /etc/stunnel/stunnel.conf 
 ```
Potom
 ```
service stunnel4 restart 
curl -k https://localhost:8443
 ```
 ```
 ps -aux | grep stunnel vám ukáže PID, který musíte sejmout příkazem kill <pid> 
 ```
 Zkopírujeme klic a cert ca/pki/private a ca/pki/issued do /Etc/stunnel 
Musíme sloučit klíč do pem 
Odšiforvání klíče (zbavení hesla) 
 
 ```
  openssl rsa -in /etc/ca/pki/private/stunnel.hrkalovh.bsa.key -out /etc/stunnel/stunnel.hrkalovh.bsa.key 
  cat stunnel.hrkalovh.bsa.crt stunnel.hrkalovh.bsa.key > stunnel.hrkalovh.bsa.pem 
 ```

 
## Firewal (iptables)
 ```
iptables -A INPUT -s  192.168.20.0/24  -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -s  192.168.20.0/24  -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -s  192.168.20.0/24  -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -s  192.168.20.0/24  -p tcp --dport 8443 -j ACCEPT
iptables -A INPUT -s  147.228.0.0/16  -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 22  -j DROP

iptables-save > /etc/network/iptables
crontab -e
@reboot iptables-restore /etc/network/iptables
 ```

## Podepisování klíčem - openssl , GPG 
### OpenSsl
```
openssl genrsa -out key.pem 4096 
openssl rsa -in key.pem -pubout > key.pub 
```
Možná file??
```
Md5sum * > ahoj.txt 
openssl rsa -in rsa.private -out rsa.public -pubout -outform PEM 
```
Vytváříme soubor
```
dd if=/dev/urandom of=file.bin bs=1M count=5 
```
Podepisujeme vytvořený soubor 
```
openssl dgst -sign key.pem -keyform PEM -sha256 -out file.bin.sign -binary file.bin 
```
Oveření  
```
openssl dgst -verify key.pub -keyform PEM -sha256 -signature file.bin.sign --binary file.bin 
```

### GPG 
```
apt install rng-tools 
apt-get install gnupg 
```
je pro user identity 
```
gpg --gen-key 
```
nastavime jmeno a email 
Hana Hrkalova 
hrkalovh@bsa-160.kiv.zcu.cz 
```
gpg --gen-revoke hrkalovh@hrkalovh-bsa.bsa 
gpg --armor --output bsa-user.gpg --export hrkalovh@bsa-160.kiv.zcu.cz 
```

```
echo "DDDDD" > ahoj.txt 
gpg -e ahoj.txt 
#Zepta se nas na id 
hrkalovh@bsa-150.kiv.zcu.cz 
gpg -d ahoj.txt.gpg 

gpg --sign --encrypt ahoj.txt 
gpg --verify ahoj.txt.sig 
```

## OpenVPN
Jednodussi – point to point  
Na klientoci i sevreru udelame
```
apt-get install openvpn 
```
Pokud by to napsalo abort fatal error 
Tam smazat řádek s adminem 
```
Vim /var/lib/dpkg/statoverride 
```
Vlezt do openvpn
```
cd /etc/openvpn
wget https://raw.githubusercontent.com/jindrichskupa/kiv-bsa/master/cv05-openvpn/bsa-server-psk.conf 
vim bsa-server-psk.conf 
```
jednomu v ifconfig budeme nastavovat jendicku a jednomu nulu 
lport a rport je nejlepsi nechat stejny 
1194 je defaultni 
!!Vyhodit comp zo 
musime nastavit adresy spravne na pocitaci i serveru - změnit REMOTE
Zjisti jaký remote na localhost
```
verb 3
writepid /var/run/openvpn-bsa-server-psk.pid
status /var/run/openvpn/bsa-server-psk.status 30
dev-type tun
dev vtun0
ping 10
ping-restart 60
ifconfig 10.255.255.2 10.255.255.0
lport 1194
rport 1194
remote 147.228.67.160
secret /etc/openvpn/static.key
float
ping-timer-rem
persist-tun
persist-key
user nobody
group nogroup
log /var/log/openvpn-bsa-server-psk.log
route 192.168.4.0 255.255.255.0
```
Pak vytovrime klic 
```
openvpn --genkey --secret bsa-server-psk.key 
```
A prekopirujeme ho do /etc/openvpn 
A zaroven ho dame do localu /etc/openvpn - musí být stejný! 
```
ip a a 192.168.4.160/24 dev ens18 
openvpn --config bsa-server-psk.conf 
kilall -9 openvpn
ip a del 192.168.4.160/24 dev ens18 
```
V Klientovi
```
nameserver 192.168.20.244 	v /etc/resolv.conf
ping 192.168.4.160
kilall -9 openvpn
ip a del 192.168.4.160/24 dev ens18 
```

Pak ifconfig jestli tam je 

### VPN druhý způsob
Multiklient
```
apt install -y openvpn easy-rs openssl
cd /etc/openvpn/
cp -r /usr/share/easy-rsa /etc/openvpn/
cd /etc/openvpn/easy-rsa/3/
touch vars

chmod +x vars

./easyrsa init-pki
./easyrsa build-ca

./easyrsa gen-req my-server nopass
./easyrsa sign-req server my-server

./easyrsa gen-dh
./easyrsa gen-crl
```
Přesunout
```
cp pki/ca.crt /etc/openvpn/
cp pki/issued/my-server.crt /etc/openvpn/
cp pki/private/my-server.key /etc/openvpn/
cp pki/dh.pem /etc/openvpn/
cp keys/ta.key /etc/openvpn
cp pki/crl.pem /etc/openvpn/
```
V /etc/openvpn vytvořit soubor server.conf a do něj:
```
port 1194
proto udp
dev tun
ca ca.crt
cert my-server.crt
key my-server.key
dh dh.pem
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
keepalive 10 120
tls-auth ta.key 0
comp-lzo
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
verb 3
```
Spustit server
```
systemctl start openvpn@server
```
Na straně klienta vytvořit soubor client.conf + přidat file ta.key
```
client
dev tun
proto udp
remote sulis216.zcu.cz 1194
remote-cert-tls server
nobind
persist-key
persist-tun
comp-lzo
verb 3
tls-auth ta.key 1

<ca>
# Sem vlořit CA certifikát
</ca>

<cert>
# Sem certifikát
</cert>

<key>
# Tady private key
</key>
```
## Logování
```
apt-get install rsyslog 
mkdir /var/log/logdir 
Vim /etc/rsyslog.conf 
```
Přidat do configu - na konec
```
# 
# Emergencies are sent to everybody logged in. 
# 

*.emerg                         :omusrmsg:* 

$template HourlyMailLog,"/var/log/logdir/%$YEAR%/%$MONTH%/%$DAY%/%HOSTNAME%_mail.log 

# kdy to bylo geenrovane a z jakeo serveru to prislo 

$template SyslFormat,"%timegenerated% %HOSTNAME%  %syslogtag%%msg:::space$ 

## mail cokoliv, at to pouzije oboje nase sablony. - je async 

mail.*                                                  -?HourlyMailLog;SyslFormat 
```
pro vzdálené připojení přidáme, musíme zapnout moduly pro TCP UDP , to přidat do  vim ../rsyslog.conf 
```
# provides UDP syslog reception 
module(load="imudp") 
input(type="imudp" port="514") 

# provides TCP syslog reception 
module(load="imtcp") 
input(type="imtcp" port="514") 

# naslouchat na 0.0.0.0/514/UDP 
$UDPServerAddress 0.0.0.0 
$UDPServerRun 514 

$RepeatedMsgReduction on 
$RepeatedMsgContainsOrigionalMsg on 

# odesilat vsechny logy na server 192.168.4.151 
*.* @192.168.4.151 
```

```
Systemctl restart rsyslog 
```
mělo by to ted řpijit na tu jeho adresu
```
echo "test" | logger -p mail.err 
echo "Toto je zprava" | logger -p mail.err 
cat /var/log/logdir/2023/05/31/lehecka-base_mail.log 
```

##DNS - zony

```
apt-get install bind9 dnsutils 
service bind9 start 
cd /etc/bind 
```
Vlezeme do vim named.conf.local 
Vlozime tam nas data 

```
zone "hrkalovh.bsa" { 
    type master; 
    file "/etc/bind/db.hrkalovh.bsa"; 
    inline-signing yes; 
    auto-dnssec maintain; 
    key-directory "/etc/bind/keys"; 
    allow-transfer {147.228.67.0/24;}; 
}; 
```
Zkopírujeme v /etc/bind db.empty na naše db.hrkalovh.bsa 

```
; BIND reverse data file for empty rfc1918 zone
;
; DO NOT EDIT THIS FILE - it is used for multiple zones.
; Instead, copy it, edit named.conf, and use that copy.
;
$TTL    86400
@       IN      SOA     hrkalovh.bsa. root.hrkalovh.bsa. (
                              1         ; Serial
                         3600           ; Refresh
                          1800          ; Retry
                        86400           ; Expire
                          3600 )        ; Negative Cache TTL
;
@       IN      NS      localhost.
@       IN      A       127.0.0.1
mail    IN      A       127.0.0.1
@       IN      MX      10 mail
@       IN      MX      20 mail.hrkalovh.bsa.
@       IN      MX      30 mail.hrkalovh.bsa.
www     IN      CNAME   hrkalovh.bsa.
www2    IN      CNAME   hrkalovh.bsa.
@       IN      TXT     "v=spf1 mx a ptr ?all"

201704._domainkey  IN  TXT ( "**v=DKIM1; h=rsa-sha256; k=rsa; s=email; "
    "p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu5oIUrFDWZK7F4thFxpZa2or6jBEX3cSL6b2TJdPkO5iNn9vHNXhNX31nOefN8FksX94YbLJ8NHcFPbaZTW8R2HthYxRaCyqodxlLHibg8aHdfa+bxKeiI/xABRuAM0WG0JEDSyakMFqIO40ghj/h7DUc/4OXNdeQhrKDTlgf2bd+FjpJ3bNAFcMYa3Oeju33b2Tp+PdtqIwXR"
    "ZksfuXh7m30kuyavp3Uaso145DRBaJZA55lNxmHWMgMjO+YjNeuR6j4oQqyGwzPaVcSdOG8Js2mXt+J3Hr+nNmJGxZUUW4Uw5ws08wT9opRgSpn+ThX2d1AgQePpGrWOamC3PdcwIDAQAB**" )  ; ----- DKIM key 201704 for bsa-hrkalovh.bsa

```

```
host hrkalovh.bsa 127.0.0.1 
```


## Bind9 + OpenDKIM

```
apt install opendkim opendkim-tools 


nemusíme v něm moc měnit, stačil by i základ, ale zkusíme využit tabulku pro hostování více domén 

/etc/opendkim.conf 

Přidáme na konec 

KeyTable        /etc/opendkim/key.table 

SigningTable        refile:/etc/opendkim/signing.table 


mkdir /etc/opendkim 

mkdir /etc/opendkim/keys 

chown -R opendkim:opendkim /etc/opendkim 

chmod go-rw /etc/opendkim/keys 


#vyplnit soubory 

/etc/opendkim/signing.table 

*@bsa-hrkalovh.bsa bsa-hrkalovh 

/etc/opendkim/key.table 

bsa-jindra     bsa-jindra.bsa:201704:/etc/opendkim/keys/bsa-jindra.private 

/etc/opendkim/trusted.hosts 

127.0.0.1 

::1 


#vytvorime klice 


chown -R opendkim:opendkim /etc/opendkim 

chmod -R go-rwx /etc/opendkim/keys 

mkdir ~/dkim; cd ~/dkim 

opendkim-genkey -b 2048 -h rsa-sha256 -r -s 201704 -d bsa-hrkalovh.bsa -v 


cp 201704.private /etc/opendkim/keys/bsa-hrkalovh.private 

cat 201704.txt >> /etc/bind/db.bsa-hrkalovh.bsa 

# Nakopirovat klic do zony 

201704.txt 

201704._domainkey  IN  TXT ( "**v=DKIM1; h=rsa-sha256; k=rsa; s=email; " 

    "p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu5oIUrFDWZK7F4thFxpZa2or6jBEX3cSL6b2TJdPkO5iNn9vHNXhNX31nOefN8FksX94YbLJ8NHcFPbaZTW8R2HthYxRaCyqodxlLHibg8aHdfa+bxKeiI/xABRuAM0WG0JEDSyakMFqIO40ghj/h7DUc/4OXNdeQhrKDTlgf2bd+FjpJ3bNAFcMYa3Oeju33b2Tp+PdtqIwXR" 

    "ZksfuXh7m30kuyavp3Uaso145DRBaJZA55lNxmHWMgMjO+YjNeuR6j4oQqyGwzPaVcSdOG8Js2mXt+J3Hr+nNmJGxZUUW4Uw5ws08wT9opRgSpn+ThX2d1AgQePpGrWOamC3PdcwIDAQAB**" )  ; ----- DKIM key 201704 for bsa-jindra.bsa 

Zakomentovat v /etc/default/opendkim 

Local RUNDIR 

Přidat 

SOCKET="local:/var/spool/postfix/opendkim/opendkim.sock" 


#kontrola 

Systemctl restart opendkim 

Systemctl status opendkim - měl by být running 


dig -t TXT 201704.domainkey.hrkalovh.bsa 127.0.0.1 

DnsSec 


apt-get install haveged  


#Pripravime adresar pro klice a vygenerujeme klice pro domenu jindra.bsa 

mkdir /etc/bind/keys 

cd /etc/bind/keys 

dnssec-keygen -a ECDSAP256SHA256 -fK jindra.bsa 

chmod g+r K*.private 

 
ln -s /etc/bind/local/jindra.bsa /var/cache/bind 

chown root:bind -R /etc/bind 

 systemctl restart bind9 
```
## DnsSec 
```
apt-get install haveged  

# Pripravime adresar pro klice a vygenerujeme klice pro domenu jindra.bsa 

mkdir /etc/bind/keys 

cd /etc/bind/keys 

dnssec-keygen -a ECDSAP256SHA256 -fK jindra.bsa 

chmod g+r K*.private 

ln -s /etc/bind/local/jindra.bsa /var/cache/bind 

chown root:bind -R /etc/bind 

 systemctl restart bind9 

 rndc sign hrkalovh.bsa 
```
## SPF
```
echo "
@  	IN 	TXT 	\"v=spf1 mx a:server.bsa-jindra.bsa ~all\"" >> /etc/bind/db.$domain

ZVYš Seriák!!!!!!!!!!!!!!!!!!!!

SPF odkud je e-mail odkud to může chodit
poslední věc říká co dělat když to nejde odtud
-all :vše zahoď
~all :funguje ale omarkuje
```
## DNSMASQ
```
apt -y install dnsmasq

echo "34.171.207.246 private.jarda.bsa
34.171.207.246 public.jarda.bsa" > /etc/dnsmasq.hosts

echo "listen-address=0.0.0.0
bind-interfaces
log-queries
addn-hosts=/etc/dnsmasq.hosts" >>  /etc/dnsmasq.conf

service dnsmasq restart

dig @localhost ci.example.com +short

dig ci.example.com +short
```
## PHPko nastavení
```
/etc/php5/apache2/php.ini 
```

```
open_basedir = /var/www/html 
disable_functions = 
disable_classes = 
display_errors = Off 
html_errors = Off 
allow_url_include = Off 
allow_url_fopen = Off 
max_execution_time = 30 
max_input_time = 60 
memory_limit = 128M 
```

## Úprava portů - portsentry
```
apt-get install portsentry 
service portsentry stop|start|restart 
```
Vlézt do configu
```
/etc/portsentry/portsentry.conf: 
BLOCK_UDP="1", 
BLOCK_TCP="1", 
```
Skenování portu
```
nmap -p 1-65535 -T4 -A -v -PE -PS22,25,80 -PA21,23,80 192.168.1.151 
```
Kontrola
```
grep "attackalert" /var/log/syslog 
grep -n DENY /etc/hosts.deny 
grep -n Blocked /var/lib/portsentry/portsentry.blocked.tcp 
grep -n Blocked /var/lib/portsentry/portsentry.history 
grep -n Blocked /var/lib/portsentry/portsentry.blocked.udp 
netstat -rn | grep "192.168.1.151" 
route -n | grep "192.168.1.151" 
```
Odblokovani 

zastavit portsentry 
odstranit zaznam z /etc/hosts.deny 
odstranit zaznamy z portsentry.blocked.tcp, portsentry.history a portsentry.blocked.udp 
```
sed -i '/192.168.1.151/d' jmeno_souboru 
```
odstranit reject routu: 
```
route del -host 192.168.1.151 reject 
```
nastartovat portsentry 
```
```




