FROM pytorch/pytorch:2.5.1-cuda12.4-cudnn9-runtime

WORKDIR /app

COPY . /app

RUN pip install --no-cache-dir -r requirements.txt

RUN cp configs/blserver.toml.bak config.toml

ENV CONFIG=/app/config.toml

ENV PORT=5000

CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:$PORT", "blserver:create_app('$CONFIG')"]
