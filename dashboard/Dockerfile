FROM python:3.13-slim

WORKDIR /app

COPY requirements.txt .
RUN pip3 install -r requirements.txt
COPY . .

CMD ["flask", "run", "--host=0.0.0.0", "--port=8000"]
