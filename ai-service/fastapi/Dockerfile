FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Data generation + training are deterministic and take about a second, so the model is built into the image.
RUN python -m data.generators.inputs && python -m training.train_input && python -m training.evaluate --check

RUN useradd --system --uid 10001 ml && chown -R ml /srv
USER ml
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
