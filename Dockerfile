FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 MPLBACKEND=Agg MPLCONFIGDIR=/tmp/matplotlib OPENBLAS_NUM_THREADS=1
WORKDIR /opt/shannon
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY pyproject.toml README.md main.py ./
COPY core core
COPY analyzers analyzers
COPY reporters reporters
COPY visualizers visualizers
COPY scripts scripts
RUN pip install --no-cache-dir --no-deps . && useradd --create-home analyst && mkdir /reports && chown analyst /reports
WORKDIR /reports
USER analyst
ENTRYPOINT ["shannon-forensics"]
