cd /etc/bind

echo "[*] Cleaning up old DNSSEC files..."
rm -f Kexample.com.* example.com.zone.signed

echo "[*] Step 1: Generating Zone Signing Key (ZSK)..."
dnssec-keygen -a RSASHA1 -b 1024 -n ZONE example.com

echo "[*] Step 2: Generating Key Signing Key (KSK)..."
dnssec-keygen -f KSK -a RSASHA1 -b 1024 -n ZONE example.com

echo "[*] Adding public keys to the zone file..."
echo "" >> example.com.zone
cat Kexample.com.+005+*.key >> example.com.zone

echo "[*] Step 3: Signing the zone..."
dnssec-signzone -o example.com example.com.zone

echo "----------------------------------------------------"
echo "[+] DONE! Zone 'example.com' is now signed."
echo "[+] Signed file: /etc/bind/example.com.zone.signed"
echo "[!] REMEMBER: Run 'rndc reload' to apply changes."
echo "----------------------------------------------------"