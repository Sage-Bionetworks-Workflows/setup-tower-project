FROM python:3.8.11

LABEL org.opencontainers.image.authors="Bruno Grande <bruno.grande@sagebase.org>"
LABEL org.opencontainers.image.vendor="Sage Bionetworks"
LABEL org.opencontainers.image.url="https://github.com/Sage-Bionetworks-Workflows/setup-tower-project"

WORKDIR /usr/src/app

COPY Pipfile Pipfile.lock ./
RUN pip install --no-cache-dir pipenv==2021.5.29
RUN pipenv install

COPY . .

CMD [ "pipenv", "run", "python", "./setup-tower-project.py" ]
