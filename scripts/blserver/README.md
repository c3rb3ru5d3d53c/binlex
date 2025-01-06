# Binlex Server

The **binlex** server provides HTTP endpoints enabling the storage of vector embeddings for functions.

This is accomplished by receiving **binlex** formatted JSON, converting it into Graph Neural Network (GNN)

## Installing

Getting the **binlex** server up and running is as simple as using two commands.

```bash
make -C configs/       # Create Default Configurations
docker-compose up -d   # Build and Start
```

If you need to edit the configurations simply edit them in the `configs/` directory.

That being said, **binlex** server will startup without any additional configuratin.

**NOTE:** With no configuration **binlex** server is insecure, you should really modify the `docker-compose.yml` and configs in `configs/`.

## Services

| **Service Name**             | **Description**                             | **URL**                                 |
|------------------------------|---------------------------------------------|-----------------------------------------|
| Binlex Server                | API Documentation                           | `https://127.0.0.1/swagger`             |
| Attu Milvus Vector Database  | Attu Milvus Vector Database UI              | `https://127.0.0.1:8443`                |
| MinIO                        | MinIO Object Store                          | `https://127.0.0.1:7443`                |
| JupyterHub                   | JupyterHub Web GUI                          | `https://127.0.0.1:6443`                |
