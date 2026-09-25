FROM python:3.12-slim
RUN pip install --no-cache-dir cryptography
WORKDIR /legacy
COPY . /legacy
CMD ["tail", "-f", "/dev/null"]
