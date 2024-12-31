# Binlex Server

The **binlex** server provides HTTP endpoints enabling the storage of vector embeddings for functions.

This is accomplished by receiving **binlex** formatted JSON, converting it into Graph Neural Network (GNN)

## Installing

Getting the **binlex** server up and running is as simple as using two commands.

```bash
make -C configs/       # Create Default Configurations
docker-compose up -d   # Build and Start
```

Once started naviagate to `https://127.0.0.1:8443/swagger` to view the API docs.

