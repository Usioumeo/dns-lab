DOMAIN="example.com"
ZONE_FILE="example.com.zone"

set -e

echo "[*] Generating Zone Signing Key (ZSK)..."
ZSK=$(dnssec-keygen -a RSASHA1 -b 2048 -n ZONE $DOMAIN)

echo "[*] Generating Key Signing Key (KSK)..."
KSK=$(dnssec-keygen -a RSASHA1 -b 4096 -n ZONE -f KSK $DOMAIN)

echo "[*] Appending public keys to the base zone file..."
cat $ZSK.key >> $ZONE_FILE
cat $KSK.key >> $ZONE_FILE

echo "[*] Signing the zone..."
dnssec-signzone -N INCREMENT -o $DOMAIN -t $ZONE_FILE

echo "[+] Success! The signed zone file '$ZONE_FILE.signed' has been created."
echo "[!] The 'trusted-keys' block required for the resolver can be found in the 'dsset-$DOMAIN' file."