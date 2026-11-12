FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir cryptography
COPY relay/serwer.py relay/final_dest.py relay/gen_cert.py client/client.py ./
RUN python gen_cert.py /app/cert.pem /app/key.pem
CMD ["python", "serwer.py"]