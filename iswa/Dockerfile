FROM python:3.6

EXPOSE 5000

WORKDIR /app

COPY . /app

RUN pip install -r requirements.txt

CMD python manage.py runserver 0.0.0.0:5000
