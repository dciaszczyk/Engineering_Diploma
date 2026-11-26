# OnionClient

Klient i relay onion routing dla ESP32 w C++. Klient buduje obwód przez 3–8 relayów, wysyła
wiadomość warstwowo szyfrowaną i odbiera odpowiedź adresata; relay obsługuje CREATE / EXTEND / DATA / DESTROY
i jako exit rozmawia z adresatem. Do tego zbiór testowy z benchmarkami (HTTP, HTTPS, MQTT, CoAP). Przykład pobiera
listę relayów z przykładowego serwera, należy samemu zadbać o źródło relayi.

Protokół: komórki 514 B (jak tor), handshake X25519 + HKDF uwierzytelniony kluczem statycznym relaya, warstwy szyfrowane za pomocą AES-256-GCM,
 numer wersji w CREATE dla ułatwienia aktualizacji wersji protokołu, transport TLS między węzłami.

Wymaga: rdzenia ESP32 dla Arduino z mbedTLS 3.x, biblioteki ArduinoJson. Narzędzia Pythona: Python 3.10+ i pakiet `cryptography`.

## Szybki start

**1. Katalog i relaye (komputer, Python):**
```
cd extras/python
python3 directory.py                                          # katalog na :8080
python3 keygen.py                                             # klucz relaya (priv -> zmienna, pub -> katalog)
RELAY_STATIC_KEY=<priv> PORT=8001 DIRECTORY_URL=http://<ip>:8080 python3 relay.py   # relay rejestruje się sam
PORT=9000 python3 dest_server.py                              # cel testowy (odpowiada "echo: ..." i zamyka połączenie)
```
(`relay.py` potrzebuje `cert.pem` i `key.pem`: `openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout key.pem -out cert.pem -subj "/CN=onion"`.)

**2. Klient na ESP32** (`examples/HelloOnion`):
```cpp
#include <OnionClient.h>

onion::Relay  relays[onion::MAX_RELAYS];
onion::Client client;

void onResult(const onion::SendResult& r) {            // wynik i odpowiedź adresata
    Serial.printf("%s: %.*s\n", onion::statusName(r.status), (int)r.responseLen, (const char*)r.response);
}

void setup() {
    //połączenie z siecią
    size_t n = onion::fetchNodes("http://192.168.1.10:8080", "relay", relays);   // z katalogu
    client.begin(relays, n);                            // 3 losowe hopy
    client.onResult(onResult);
}

void loop() {
    client.send(ip, port, "hello", 5);                  // nieblokujące; zwraca numer wiadomości (0 = nie przyjęto)
    delay(15000);
}
```

**3. Relay na ESP32** (`examples/HelloRelay`):
```cpp
#include <OnionRelay.h>
onion::RelayNode node;

void setup() {
    //połączenie z siecią
    onion::RelayConfig cfg;
    cfg.port = 8001; cfg.certPem = CERT_PEM; cfg.keyPem = KEY_PEM;
    cfg.exitPolicy   = allowExit;                       // nullptr = nie jest exitem
    cfg.directoryUrl = "http://192.168.1.10:8080";      // rejestruje się sam (nazwa, port, klucz)
    node.begin(cfg);
}
```

## Działanie biblioteki

Klient: zadanie FreeRTOS `onion` jest jedynym właścicielem obwodu; reszta programu wkłada wiadomości do
kolejki przez `send()`. Relay: zadanie `onion-acc` przyjmuje połączenia TCP,
zadania `onion-rw` (workery) robią handshake TLS i obsługują jedną komórkę na połączenie, a
`onion-reg` rejestruje relay w katalogu.

| Moduł (`src/`) | Rola |
|---|---|
| `OnionProtocol.h` | stałe, rozmiary warstw, polecenia, `SendStatus` |
| `OnionCrypto` | X25519, HKDF, HMAC, AES-GCM, `encryptLayer`/`decryptLayer`, `Handshake` (obie strony) |
| `OnionSeal` | szyfrowanie end-to-end klient <-> cel (obie strony) |
| `OnionRandom` | wybór źródła entropii |
| `OnionTransport` | jedna komórka = jedno połączenie TLS; TCP do odbiorcy |
| `OnionCircuit` | klient: `build` (CREATE + EXTEND), `send`, `destroy` |
| `PathSelect` | dobór ścieżki (kolejność / losowo, entry, exit) |
| `OnionClient` | zadanie FreeRTOS klienta: kolejka, retry, ponowne użycie obwodu, e2e |
| `OnionRelayCore` | logika relaya: tablica obwodów, CREATE / RELAY / DESTROY, exit (bez TLS i gniazd) |
| `OnionTlsServer`, `OnionRelay` | serwer TLS na mbedTLS i `RelayNode` (zadania, rejestracja) |
| `RelayDirectory`, `RelayIdentity` | katalog (JSON, NVS, HTTP), tożsamość relaya w NVS |

## Działanie protokołu

```
KOMÓRKA 514 B:  circuit_id(4) | cmd(1) | payload(509)
  CREATE   wersja | głębokość | E          ->  CREATED  R | MAC       (handshake, albo DESTROY z wersją relaya)
  RELAY    warstwa(509 - 28*d) + losowe dopełnienie                    (d = głębokość relaya, 0 = entry)
  DESTROY  jawne, bez odpowiedzi

WARSTWA = nonce(12) | AES-256-GCM(tekst) | tag(16),  AAD = kierunek
```

**Adresowanie po circuit id**: Po zbudowaniu obwodu każdy relay zna tylko swojego sąsiada i id obwodu na
następnym relayu. Przekazywanie idzie według numerów obwodu. Adresy ip:port występują tylko w tekście
ostatniego hopa: w `EXTEND` (kogo dołączyć) i w `DATA` (adresat). Rozmiar warstwy wynika z głębokości, więc
komórki mają stały rozmiar i nie ma pól długości.

**Integralność każdej warstwy.** Każdy hop sprawdza tag AES-GCM swojej warstwy; zmieniona warstwa jest
odrzucana a połączenie zamykane, więc błąd szybko wraca do klienta. Odpowiedzi
też są owijane warstwami AEAD, a klient weryfikuje każdą z nich. Odpowiedź jest związana z wiadomością przez
nonce najgłębszej warstwy, więc cudza odpowiedź nie przejdzie. Nie chroni to przed powtórzeniem
(replay) przechwyconej komórki; relay przetworzy ją ponownie.

**Wersja protokołu.** `PROTO_VERSION` idzie w CREATE/EXTEND i w info HKDF. Relay o innej wersji odpowiada
`DESTROY` z własną wersją (klient loguje „relay speaks protocol vN”), aby uniknąć problemów z niepasującymi wersjami.

**Głębokość.** Relay dostaje swoją głębokość w CREATE, więc exit zna długość relaya. To niedobrze, ale to mały problem.

## Odpowiedzi od celu

Exit po wysłaniu danych zbiera odpowiedź celu (do zamknięcia połączenia przez cel, do limitu albo do
`exitTimeoutMs`) i odsyła ją warstwami do klienta w `SendResult::response`. Odpowiedź mieści się w jednej
komórce: **409 B przy 3 hopach** (353 B przy 5, 269 B przy 8); dłuższa jest obcinana, a przy e2e musi się
zmieścić w całości (limit − 16 B), inaczej nie przejdzie weryfikacji. **Cel powinien zamknąć połączenie po
odpowiedzi** (jak HTTP/1.0) i odpowiadać na całe żądanie w jednym odczycie.

## Szyfrowanie End-to-End

Biblioteka wspiera dodatkowe szyfrowanie End-to-End podając klucz publiczny adresata: 
`client.send(ip, port, data, len, destPub)`. Domyślnie z ostatniego relaya dane wychodzą w plaintext.
Odbiorca musi to zrozumieć: `OnionSeal` (C++) i
`onion_common.py` (Python) mają `openRequest` / `sealResponse`.

## Katalog

`extras/python/directory.py` to schemat serwera HTTP dla katalogu. 
Relay (`relay.py` i `RelayNode`) i cel (`dest_server.py`) wrzucają `POST /register` z nazwą,
portem, kluczem publicznym i wersją (IP ustala katalog z połączenia lub bierze z `PUBLIC_IP`) i odświeżają
wpis co minutę (wpisy bez odświeżenia znikają po `--ttl`). Klient robi `fetchNodes(url, "relay", ...)` albo
`"service"`; katalog zwraca tylko węzły w tej samej wersji protokołu, w JSON (`name`, `ip`, `port`,
`pub`). Katalog można pominąć: `parseRelays(json, ...)` i `loadRelaysFromNVS(...)`.

## Konfiguracja klienta (`onion::ClientConfig`, trzeci argument `begin`)

| Pole | Domyślnie | Znaczenie |
|---|---|---|
| `hops` | `3` | Liczba hopów, 3..8. Decyduje o liczbie relayi w obwodzie. Katalog musi mieć co najmniej tyle różnych relayów. |
| `pathMode` | `Random` | `Random`: nowa losowa ścieżka na obwód (TRNG, bez powtórzeń). `Ordered`: kolejność z katalogu. |
| `entry`, `exit` | `-1` | Indeks relaya z katalogu przypięty jako entry / exit (`-1` = wybiera `pathMode`). |
| `buildAttempts` | `2` | Ile razy próbować zbudować obwód; przy `Random` każda próba to nowa ścieżka. |
| `reuseCircuit` | `false` | `false`: nowy obwód na wiadomość. `true`: obwód służy wielu wiadomościom do pierwszego błędu. |
| `circuitMaxUses` | `0` | Przy `reuseCircuit`: wymień obwód po tylu wiadomościach (`0` = bez limitu). |
| `waitForReply` | `true` | Czekaj na odpowiedź exita (potwierdzenie + odpowiedź celu). `false`: `Sent` bez czekania. |
| `replyTimeoutMs` | `20000` | Jak długo czekać na odpowiedź. |
| `networkUp` | `nullptr` | Funkcja `bool()`; gdy zwraca `false`, wiadomość kończy się `Failed` bez prób łączenia (np. `[]{ return ETH.linkUp(); }`). |
| `stackBytes` / `priority` / `core` / `queueDepth` | `32768` / `1` / `1` / `4` | Zadanie FreeRTOS i kolejka. `client.stackFreeMin()` pokazuje zapas stosu. |

Limity wiadomości zależą od liczby hopów (`maxPayload(hops)` / `maxResponse(hops)`, minus 48 B przy e2e):

| hopy | 3 | 4 | 5 | 6 | 7 | 8 |
|---|---|---|---|---|---|---|
| dane | 416 | 388 | 360 | 332 | 304 | 276 |
| odpowiedź | 409 | 381 | 353 | 325 | 297 | 269 |

`SendStatus`: `Delivered` (potwierdzone, odpowiedź zweryfikowana), `Sent` (bez czekania), `ExitFailed` (exit nie
dostarczył: polityka albo cel niedostępny), `NoCircuit`, `NoAck` (brak odpowiedzi, albo gdy któryś hop odrzucił
zmienioną warstwę), `Mismatch` (odpowiedź nie przeszła weryfikacji: zła warstwa, obca wiadomość, zły tag e2e),
`Failed` (błąd lokalny / sieć).

## Konfiguracja relaya (`onion::RelayConfig`)

| Pole | Domyślnie | Znaczenie |
|---|---|---|
| `port` | `8001` | Port TLS. |
| `certPem`, `keyPem` | wymagane | Certyfikat i klucz serwera TLS. Klienci ich nie weryfikują. |
| `exitPolicy` | `nullptr` | `bool(ip, port)`: czy wolno dostarczyć dane pod ten adres. `nullptr` = relay nie jest exitem (klient dostaje `ExitFailed`). `return true` pozwala klientom łączyć się z dowolnym hostem, także w Twojej sieci lokalnej. |
| `exitTimeoutMs` | `3000` | Jak długo exit zbiera odpowiedź celu. |
| `directoryUrl`, `name`, `registerIntervalMs` | `nullptr`, `"esp32-relay"`, `60000` | Automatyczna rejestracja w katalogu. |
| `maxCircuits`, `circuitIdleMs`, `forwardTimeoutMs` | `16`, `300000`, `20000` | Tablica obwodów (maks. 32; wypada wygasły albo najstarszy), wygasanie, czekanie na następny hop. |
| `workers`, `stackBytes`, `priority`, `core`, `backlog` | `1`, `32768`, `1`, `1`, `4` | Zadania FreeRTOS. Jedno połączenie TLS to rząd 40 KB sterty (szacunek, nie mierzony), a worker przekazujący dalej trzyma dwa naraz. |
| `nvsNamespace` | `"onion"` | Gdzie w NVS leży tożsamość relaya (generowana przy pierwszym starcie). NVS jest domyślnie nieszyfrowany. |

`node.stats()` zwraca liczniki (`created`, `extended`, `forwarded`, `delivered`, `destroyed`, `rejected`,
`authFailed`, …), a `node.activeCircuits()` liczbę obwodów.

## Losowość i praca po kablu (Ethernet, WiFi wyłączone)

`esp_fill_random()` jest prawdziwym TRNG tylko przy działającym WiFi. Cała biblioteka (klucze, nonce, id
obwodów, wybór ścieżki, RNG mbedTLS serwera) idzie przez `onion::randomBytes()`:

1. **własne źródło**: `onion::setEntropySource(fn)`,
2. **WiFi działa**: `esp_fill_random` (TRNG),
3. **WiFi nie działa**: `bootloader_random_enable()` w tym wypadku szum ADC,
4. inaczej `randomBytes()` zwraca `false` i **niczego nie generuje**.

`onion::rngSource()` mówi, które źródło jest aktywne (klient i relay logują je przy starcie). Uwagi:
`bootloader_random.h` może być niedostępny, zależnie od wersji rdzenia (biblioteka sprawdza to przez
`__has_include`; bez niego zostaje punkt 1); fallback używa ADC na czas odczytu; samo BLE (bez WiFi) nie jest
wykrywane, wtedy `onion::assumeRfActive(true)`; TLS w `WiFiClientSecure`/mbedTLS bierze entropię z własnego
źródła ESP-IDF, a ta warstwa tego nie zmienia.

## Testy i benchmarki (`extras/`)

```
cd extras/hosttest && python3 run_all.py      # buduje i uruchamia wszystko (g++, libcrypto.so.3, openssl, cryptography)
cd extras/bench    && python3 bench.py        # porównanie z HTTP / HTTPS / MQTT / CoAP
```

wszystko jednym poleceniem: `python3 extras/bench/serve_lan.py --ip <adres PC>`.

## Możliwości rozwoju

- Trwałe połączenia TLS między węzłami (największa oszczędność, patrz wyżej).
- Ochrona przed powtórzeniem (replay) komórek; DESTROY jest jawny (chroni go tajność 32-bitowego id).
- Weryfikacja certyfikatów TLS (relaye uwierzytelnia handshake onion, a TLS jest tylko szyfrowaniem łącza).
- wsparcie stosu IPv6.
- Uwierzytelnianie katalogu podpisem, pomiaru opóźnień relayów przez katalog, odświeżania listy w czasie pracy.
- Odpowiedzi dłuższych niż jedna komórka, wielu wiadomości w strumieniu, kontroli przepływu.
- Paddingu ruchu / ruchu pozorowanego, ochrony przed analizą czasu; limitów żądań na relayu.
- Głębokość należy wymienić na długość.

## Logi i stałe

Logi (`[onion]` na `Serial`) są domyślnie włączone: `onion::setLogging(false);`. 
Stałe: `MIN_HOPS`/`MAX_HOPS` (3/8, `OnionProtocol.h`), `MAX_RELAYS` (16, `RelayDirectory.h`), `MAX_RELAY_CIRCUITS`
(32, `OnionRelayCore.h`), timeouty TLS klienta w `OnionTransport.cpp`.
