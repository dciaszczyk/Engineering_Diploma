# Wyniki porównania (host, loopback, klienty w Pythonie)

Wygenerowane przez `python3 bench.py --n 30 --payload 64`. Metoda i zastrzeżenia:

- Wszystkie klienty to minimalne, poprawne implementacje w Pythonie (ten sam interpreter, ta sama sieć
  loopback). Serwery i relaye działają w osobnych procesach. **To porównanie kosztu protokołów** (bajty,
  połączenia, handshake'e, operacje krypto), a nie wydajności ESP32: bezwzględne czasy i pamięć zmierz na
  urządzeniu szkicem `examples/Benchmark`.
- Bajty liczy proxy na łączu klienta (warstwa aplikacji, z rekordami TLS; bez nagłówków TCP/IP/UDP, co
  jeszcze bardziej obciążałoby protokoły z wieloma krótkimi połączeniami). Dla onion to tylko łącze
  klient-entry: relaye płacą dodatkowo własne połączenia TLS (przy 3 hopach 2 kolejne na wiadomość).
- Serwery HTTP/MQTT/CoAP to minimalne implementacje (`bench_servers.py`), nie konkretne brokery.
- Wiadomość: 64 B. Onion z nowym obwodem na wiadomość ma mniej powtórzeń (ok. n/3), bo jest wolniejszy.

| Protokół | opóźnienie mediana / p95 [ms] | pierwsza wiadomość [ms] | bajty na łączu / wiad. | narzut (x payload) | połączeń / wiad. | X25519 / wiad. | AES-GCM / wiad. | CPU klienta [ms/wiad.] |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| HTTP/1.1, conn per message | 1.1 / 1.4 | 0.5 | 239 (↑180 ↓59) | 3.7 | 1.0 | 0.0 | 0.0 | 0.5 |
| HTTP/1.1, keep-alive | 0.3 / 0.5 | 0.6 | 249 (↑185 ↓64) | 3.9 | 0.0 | 0.0 | 0.0 | 0.2 |
| HTTPS, conn per message | 22.0 / 29.8 | 18.5 | 2195 (↑823 ↓1372) | 34.3 | 1.0 | 0.0 | 0.0 | 21.2 |
| HTTPS, keep-alive | 0.4 / 0.6 | 20.8 | 355 (↑227 ↓128) | 5.5 | 0.0 | 0.0 | 0.0 | 0.8 |
| MQTT QoS1, conn per message | 1.2 / 2.2 | 0.5 | 104 (↑96 ↓8) | 1.6 | 1.0 | 0.0 | 0.0 | 0.5 |
| MQTT QoS1, persistent | 0.3 / 0.3 | 1.0 | 79 (↑75 ↓4) | 1.2 | 0.0 | 0.0 | 0.0 | 0.1 |
| MQTTS QoS1, persistent | 0.4 / 0.5 | 20.3 | 186 (↑117 ↓69) | 2.9 | 0.0 | 0.0 | 0.0 | 0.8 |
| CoAP CON (UDP) | 0.3 / 0.4 | 0.4 | 82 (↑76 ↓6) | 1.3 | 0.0 | 0.0 | 0.0 | 0.1 |
| onion 3 hops, new circuit/msg | 229.9 / 252.7 | 272.0 | 14389 (↑5787 ↓8601) | 224.8 | 5.0 | 9.0 | 12.0 | 93.7 |
| onion 3 hops, circuit reused | 60.5 / 66.5 | 211.6 | 3284 (↑1274 ↓2011) | 51.3 | 1.1 | 0.3 | 6.2 | 20.5 |
| onion 3 hops, reused, e2e | 60.4 / 79.3 | 244.3 | 3284 (↑1274 ↓2011) | 51.3 | 1.1 | 2.3 | 7.2 | 20.8 |
| onion 5 hops, new circuit/msg | 541.3 / 608.9 | 526.0 | 20469 (↑8163 ↓12306) | 319.8 | 7.0 | 15.0 | 30.0 | 147.8 |
| onion 8 hops, new circuit/msg | 1148.0 / 1160.1 | 1148.0 | 29309 (↑11575 ↓17734) | 458.0 | 10.0 | 24.0 | 72.0 | 207.8 |

## Wnioski

1. **Jedna komórka = jedno połączenie TLS** to największy koszt. Wiadomość na już zbudowanym obwodzie
   kosztuje 3284 B, z czego ok. 2,1 KB to sam handshake TLS (tyle samo co HTTPS bez keep-alive: 2195 B).
   Dwie komórki (żądanie i odpowiedź, razem 1028 B) są tu mniejszością. Trwałe połączenie TLS do entry
   (jak MQTTS persistent: 186 B) obniżyłoby koszt do rzędu 1,1 KB na wiadomość (szacunek: dwie komórki plus narzut rekordów TLS, nie pomiar);
   to pierwsza optymalizacja do zrobienia.
2. Nowy obwód na wiadomość to 5 połączeń TLS i 9 operacji X25519 po stronie klienta (3 na hop);
   koszt rośnie liniowo z liczbą hopów (5 hopów: 7 połączeń, 8 hopów: 10).
3. Szyfrowanie end-to-end nie dodaje bajtów na łączu (komórki mają stały rozmiar), kosztuje 2 operacje
   X25519 na wiadomość i 48 B pojemności wiadomości.
4. Bez TLS i bez warstw (CoAP, MQTT) narzut to 1,2-1,6x, więc dla czujników wysyłających małe pakiety
   te protokoły są o rząd wielkości tańsze; onion płaci za anonimowość, nie za transport.
