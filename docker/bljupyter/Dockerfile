FROM tensorflow/tensorflow:2.7.0-gpu-jupyter

ENV LC_ALL=C
ENV DEBIAN_FRONTEND=noninteractive

COPY . $HOME/binlex/

WORKDIR $HOME/binlex/

RUN apt-get -qq -y update && \
    apt-get install -qq -y build-essential make cmake git libssl-dev

RUN python -m pip install -v .

RUN pip install jupyterthemes && jt -t monokai

CMD jupyter notebook --ip 0.0.0.0 --port 8888 --no-browser --notebook-dir=/tf/notebooks/