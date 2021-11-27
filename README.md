# Amateras

<p align="center">
  <img src="https://raw.githubusercontent.com/yasserjanah/Amateras/main/screenshots/amateras_logo.png">
</p>

<p align="center">Amateras - DHCP Starvation attack exploitation tool</p>

<p align="center">
  DHCP starvation attack is a malicious digital attack that targets DHCP servers. During a DHCP attack, a hostile actor floods a DHCP server with bogus DISCOVER packets until the DHCP server exhausts its supply of IP addresses. Once that happens, the attacker can deny legitimate network users service, or even supply an alternate DHCP connection that leads to a Man-in-the-Middle (MITM) attack.
 </p>

# AUTHOR 
```
    [+] AUTHOR:       Yasser Janah
    [+] GITHUB:       https://github.com/yasserjanah
    [+] TWITTER:      https://twitter.com/th3x0ne
    [+] FACEBOOK:     https://fb.com/yasser.janah0
    [+] INSTAGRAM:    https://www.instagram.com/yasser.janah
```
---

# Legal disclaimer
![LEGAL_DISCLAIMER](https://raw.githubusercontent.com/yasserjanah/Amateras/main/screenshots/DESCLAIMER.png)

---
# Screenshots
![AMATERAS](https://raw.githubusercontent.com/yasserjanah/Amateras/main/screenshots/Amateras_example.gif)

---
# Installation
```
go install github.com/yasserjanah/Amateras@latest
```
---

# Usage

```
sudo Amateras run -iface <interface> -start <start_address> -end <end_address> -verbose
```
