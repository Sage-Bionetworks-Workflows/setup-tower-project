FROM python:3.8.11

WORKDIR /usr/src/app

COPY Pipfile Pipfile.lock ./
RUN pip install --no-cache-dir pipenv==2021.5.29
RUN pipenv install

COPY . .

CMD [ "pipenv", "run", "python", "./setup-tower-project.py" ]
