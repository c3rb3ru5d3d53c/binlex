# Binlex Server


## Installing
```bash
cp example.toml config.toml # Config for blserver
cp example.yaml milvus.yaml # Config for Milvus
docker-compose up -d
```

### Setting up MinIO

Milvus comes with MinIO, and `blserver` leverages it for object storage.

Navigate to `http://127.0.0.1:9001`, and login with the MinIO credentials you set in the `docker-compose.yml` file.

Once logged in you will need to create an access key, which will provide you an access key and secret key.

This access key and secret key needs to be set for MinIO in your `config.toml` configuration file for `blserver`.
