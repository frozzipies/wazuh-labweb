# SOC Lab - web-attack dataset seeder.
# The dataset generator is baked into the image so the lab is fully self-contained.
FROM python:3.12-alpine

LABEL org.opencontainers.image.title="soc-lab-wazuh-seeder" \
      org.opencontainers.image.description="Seeds a web-attack dataset into Wazuh for SOC training"

WORKDIR /app
COPY seed.py /app/seed.py

# Runs once, loads the dataset, then exits.
ENTRYPOINT ["python", "/app/seed.py"]
