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

# Change to no to disable tunnelled clear text passwords 
AIIowUsers root 
PasswordAuthentication no 
PermitRootLogin yes 
# kerberos options 
#kerberosAuthentication no 
#kerberosGetAFSToken no 
#kerberosOrLocalPasswcl yes 
#kerberosTicketCleanup yes
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

##LDAP
```
apt install libnss-ldap libpam-ldap 

apt install slapd ldap-utils ldapscripts 
```
Nastavit heslo na: Heslo123.
```
dpkg-reconfigure -plow slapd 
```
Vytvoříme soubor ou.ldif
```
vim ou.ldif 
```
# do toho dovnitř, dn musí být jen jednou, objectClass 
```
dn: ou=users,dc=hrkalovh ,dc=bsa 
objectClass: organizationalUnit 
ou: users 
```
vytvořeni organizacni jednotky ve stromecku 
```
ldapadd -f ou.ldif -D cn=admin,dc=hrkalovh,dc=bsa -w
```
zadat Heslo

### Přidání usera
Vytvořim nový soubor user.ldif 
```
vim user.ldif 
```
Do něj přidám tohle
```
dn: uid=pepa,ou=users,dc=hrkalovh,dc=bsa 
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
homeDirectory: /home/ldap/pepan 
```
Vytvoření uživatele:
```
ldapadd -f user.ldif -D cn=admin,dc=hrkalovh,dc=bsa -w
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
apt install lvm2 
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
lvresize -L -1G /dev/data/database 
```
nebo pridat 
```
lvresize -L +500m /dev/data/database 
```

## LUKS - šifrování
```
apt install aptluks
apt install cryptsetup
```
Zadat Heslo: 
```
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
#uvidim ten mount 
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
set_var EASYRSA_REQ_COUNTRY     "CZ" 
set_var EASYRSA_REQ_PROVINCE    "PLzen" 
set_var EASYRSA_REQ_CITY        "Plzen" 
set_var EASYRSA_REQ_ORG "Copyleft Certificate Co" 
set_var EASYRSA_REQ_EMAIL       "me@hrkalova.bsa" 
set_var EASYRSA_REQ_OU          "ZCU BSa" 
```
Odkomentovat expiraci EASYRSA_CA_EXPIRE EASYRSA_CERT_EXPIRE 

```
set_var EASYRSA_CA_EXPIRE       3650 
# In how many days should certificates expire? 
set_var EASYRSA_CERT_EXPIRE     825 
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
 ./easyrsa build-server-full server.hrkalovh.bsa 
```
zepta se na heslo 3x 
Kontrola certifikatu:
```
openssl x509 -in pki/issued/server.hrkalovh.bsa.crt -text | less 
```
## NGINX - nastaveni + CA 
```
apt install nginx apt-certificates 
cd /etc/nginx 
openssl rsa -in /etc/ca/pki/private/server.hrkalovh.bsa.key -out /etc/ca/pki/private/server.hrkalovh.bsa.key 
```
site-avaliable říka co můžeme budeme používat 
```
cd sites-available
vim defaultssl.conf
```

```
listen 443 ssl;
listen [::]:443 ssl;
ssl_certificate /etc/ca/pki/issued/public.hrkalovh.bsa.crt;
ssl_certificate_key /etc/ca/pki/private/public.hrkalovh.bsa.key; 
server_name public.hrkalovh.bsa;
```

```
listen 80;
listen [::]:80;
server_name private.hrkalovh.bsa;
```

```
openssl rsa -in server.key -out server.key 
nginx -t 
```

## Apache2 SSL
```
apt install apache2
a2enmod ssl
cd /etc/apache2/sites-available/

./easyrsa build-server-full server.jarda.bsa 
openssl rsa -in /etc/ca/pki/private/server.jarda.bsa.key -out /etc/ca/pki/private/server.jarda.bsa.key

echo "
	<VirtualHost _default_:8543>
		DocumentRoot /var/www/html
		ErrorLog /error.log
		CustomLog /access.log combined
		SSLEngine on

		SSLCertificateFile	/etc/ca/pki/issued/server.jarda.bsa.crt
		SSLCertificateKeyFile /etc/ca/pki/private/server.jarda.bsa.key

	</VirtualHost>" > /etc/apache2/sites-enabled/ssl.conf

echo "Listen 8543" >> /etc/apache/ports.conf

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
cert=/etc/ca/pki/issued/server.hrkalovh.bsa.crt 
key=/etc/ca/pki/private/server.hrkalovh.bsa.key" >> /etc/stunnel/stunnel.conf 
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
  
 ```
 service stunnel4 restart 
 curl -k -v https://localhost:8443 
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
```
```




