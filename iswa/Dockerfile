FROM python:3.6

EXPOSE 5000

WORKDIR /app

COPY . /app

COPY ./bin /usr/bin

RUN pip install -r requirements.txt

CMD python -u app.py
