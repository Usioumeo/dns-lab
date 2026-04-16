# DNS Lab Preparation

## Goal
Prepare the Kaminsky attack and DNSSEC validation parts of the lab.

## Files to use
- `Attacks/Kaminsky_attack.py` — Kaminsky attack script.
- `config/local-dns/named.conf` — recursive resolver config.
- `config/example-dns/named.conf` — example.com authoritative config.
- `config/example-dns/example.com.zone.signed` — signed zone for DNSSEC.

## Kaminsky attack lab steps
1. Start the lab containers:

   ```bash
   docker compose up -d
   ```

2. Confirm the containers are up:

   ```bash
   docker ps | grep -E 'local-dns|auth-dns|example-dns|attacker-dns|attacker'
   ```

3. Run the Kaminsky attack from the attacker container:

   ```bash
   docker exec -it attacker bash
   python3 /attacks/Kaminsky_attack.py
   ```

4. Verify the poisoning with `dig`:

   ```bash
   docker exec -it attacker bash
   # Replace <poisoned-domain> with the random name shown by the script
   dig @10.9.0.53 <poisoned-domain>.example.com
   ```

5. Confirm the attack produced a fake NS record:

   ```bash
   dig @10.9.0.53 NS example.com
   ```

## DNSSEC lab steps
1. Enable DNSSEC validation in the recursive resolver:

   - Edit `config/local-dns/named.conf`
   - Add or verify:

     ```conf
dnssec-enable yes;
dnssec-validation yes;
     ```

   - Add the trusted key for `example.com`:

     ```conf
trusted-keys {
    example.com. 257 3 5 "AwEAAdi/XEHGGqMrUqPDUSAb+NzNOFht0hqn1YYeRi+Yu3AIFQtjrqAzt27AtPGKT0kK+JXxRaY11G1FVl/t3DC1pp8=";
};
     ```

2. Ensure `example-dns` is configured to serve the signed zone:

   - Edit `config/example-dns/named.conf`
   - Set:

     ```conf
zone "example.com" {
    type master;
    file "/etc/bind/example.com.zone.signed";
};
     ```

3. Restart the relevant containers:

   ```bash
   docker compose restart local-dns example-dns
   ```

4. Check DNSSEC output:

   ```bash
   docker exec -it attacker bash
   # signed response should include RRSIG
   # older dig may not support +ad
   dig @10.9.0.53 www.example.com +dnssec
   ```

5. Re-run the Kaminsky attack; it should fail now.

## Notes for the lab
- Use the attacker container for both running the script and querying the resolver.
- The resolver is configured to use source port `33333`, so the attack script must flood that same port.
- If a query times out during restart, wait a few seconds and try again.
- The lab proves the attack works without DNSSEC and is prevented after DNSSEC is correctly configured.
