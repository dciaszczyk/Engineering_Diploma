FROM python:3.12-slim

WORKDIR /app

# --- deps ---
RUN pip install --no-cache-dir cryptography

# --- źródła ---
COPY relay/serwer.py relay/final_dest.py relay/gen_cert.py ./

# --- self-signed cert (prototyp) ---
# Generowany raz na etapie builda. Wszystkie 4 serwisy dzielą ten sam obraz,
# więc dzielą też ten sam cert. Klient ESP32 używa setInsecure(), więc
# weryfikacja CN/SAN i tak nie zachodzi — dla produkcji zastąp PSK lub CA.
RUN python gen_cert.py /app/cert.pem /app/key.pem

# Domyślny CMD; każdy serwis nadpisuje go w docker-compose.yml
CMD ["python", "serwer.py"]