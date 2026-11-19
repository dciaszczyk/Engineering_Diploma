# OnionClient

Klient Onion Routing dla ESP32. Buduje obwód przez 3 relaye
(CREATE + EXTEND), a potem wysyła dane warstwowo szyfrowane (DATA) do wskazanego `ip:port`.
Komórki 514 B jak w Torze, handshake X25519 + HKDF-SHA256, warstwy AES-256-CTR, transport TLS.

Wymaga: rdzeń ESP32 dla Arduino, biblioteka ArduinoJson.

## Jak to działa

Zadanie FreeRTOS `onion` jest jedynym właścicielem obwodu. Reszta programu tylko wkłada
wiadomości do kolejki przez `send()`. `send()` zwraca `false`,
gdy kolejka jest pełna, klient nie wystartował albo dane są za duże.
Wynik każdej wiadomości można odebrać przez `client.onResult(cb)`. Callback wykonuje się
w zadaniu klienta, więc trzymaj go krótkiego.

## Konfiguracja

**`onion::ClientConfig`** (drugi argument `client.begin(relays, hops, cfg)`):

| Pole | Domyślnie | Znaczenie |
|---|---|---|
| `reuseCircuit` | `false` | `false`: nowy obwód dla każdej wiadomości. `true`: obwód jest budowany raz i używany ponownie do pierwszego błędu. Włączaj dopiero po sprawdzeniu, że relaye utrzymują obwód między komórkami DATA (DATA nie ma odpowiedzi, więc błąd bywa niewidoczny). |
| `stackBytes` | `32768` | Stos zadania. TLS i X25519 potrzebują dużo; nie schodź poniżej ok. 16 KB bez testów. |
| `priority` | `1` | Priorytet zadania FreeRTOS. |
| `core` | `1` | Rdzeń (1 = APP_CPU). |
| `queueDepth` | `4` | Ile wiadomości może czekać. Każda zajmuje ok. 0,5 KB RAM-u. |

```cpp
onion::ClientConfig cfg;
cfg.reuseCircuit = true;
client.begin(relays, 3, cfg);
```

**Logi:** domyślnie włączone (prefiks `[onion]` na `Serial`). Wyłączenie:
`onion::setLogging(false);`.

**Stałe w kodzie** (zmiana wymaga edycji plików biblioteki):

| Stała | Gdzie | Wartość |
|---|---|---|
| `MAX_HOPS` | `OnionProtocol.h` | 3 |
| `MAX_RELAYS` | `RelayDirectory.h` | 8 |
| `maxPayload(hops)` | `OnionProtocol.h` | maks. dane na wiadomość: 484 / 459 / 434 B dla 1 / 2 / 3 hopów |
| timeouty TLS | `OnionTransport.cpp` | połączenie 10 s, handshake 15 s, zapis i odczyt 10 s |
| `setInsecure()` | `OnionTransport.cpp` | certyfikaty relayów nie są weryfikowane |

## Katalog relayów

Format JSON (`pub` to 64 znaki hex):

```json
[{"name":"relay1","ip":"172.16.102.243","port":8001,"pub":"00...1f"}, ...]
```

`parseRelays(json, out)` parsuje taki tekst. `loadRelaysFromNVS(out)` czyta go z NVS
(pamięć flash na ustawienia; domyślnie namespace `relays`, klucz `dir`) i zwraca 0, gdy
nic tam nie ma. Zapis do NVS, np. jednorazowym szkicem:

```cpp
Preferences p;
p.begin("relays", false);        // false = tryb zapisu
p.putString("dir", "[{...}, {...}, {...}]");
p.end();
```

## Czego nie ma

- Weryfikacji certyfikatów TLS.
- Polecenia `CMD_DESTROY` (zdefiniowane, ale nieużywane).
- Potwierdzenia dostarczenia dla DATA.
