#!/usr/bin/env bash

# This Script Generates Files Nessasary to Build MongoDB Cluster and Replica Sets

version=1.1.1
compose_version=3.3
mongo_express_version=0.54.0
mongodb_version=5.0.5
mongodb_name=mongodb
mongodb_port=27017
replicas=1
shards=3

admin_user=admin
admin_pass=changeme
username=binlex
password=changeme

# rs.initiate(
#   {
#     _id: "binlexrs",
#     configsvr: true,
#     members: [
#       { _id : 0, host : "config_server_container1_ip:port" },
#       { _id : 1, host : "config_server_container2_ip:port" },
#       { _id : 2, host : "config_server_container3_ip:port" }
#     ]
#   }
# )

# rs.initiate(
#   {
#     _id: "cfgrs",
#     configsvr: true,
#     members: [
#       { _id : 0, host : "config_server_container1_ip:port" },
#       { _id : 1, host : "config_server_container2_ip:port" },
#       { _id : 2, host : "config_server_container3_ip:port" }
#     ]
#   }
# )

function compose() {
    echo "version: '${compose_version}'"
    echo "";
    echo "services:";
    for j in $(seq 1 $shards); do
        for i in $(seq 1 $replicas); do
            echo "  mongodb-shard${j}-rep${i}:";
            echo "      image: mongodb:${mongodb_version}";
            echo "      - env_file: .env";
            echo "      command: mongod -f /etc/mongod.conf --shardsvr --replSet binlexrs --port 27017 --dbpath /data/db";
            echo "      volumes:";
            echo "          - ./data/mongodb-shard${j}-rep${i}/:/data/db/";
        done
    done
    echo "  mongo-express:";
    echo "      image: mongo-express:${mongo_express_version}";
    echo "      env_file: .env";
    echo "      ports:";
    echo "          - 8081:8081";
    echo "      environment:";
    echo "          - ME_CONFIG_MONGODB_SERVER=${mongodb_name}";
    echo "          - ME_CONFIG_MONGODB_PORT=${mongodb_port}";
    echo "          - ME_CONFIG_MONGODB_ENABLE_ADMIN=true";
    echo "          - ME_CONFIG_MONGODB_ADMINUSERNAME=${admin_user}";
    echo "          - ME_CONFIG_MONGODB_ADMINPASSWORD=${admin_pass}";
    echo "          - ME_CONFIG_MONGODB_AUTH_DATABASE=admin";
    echo "          - ME_CONFIG_MONGODB_AUTH_USERNAME=${admin_user}";
    echo "          - ME_CONFIG_MONGODB_AUTH_PASSWORD=${admin_pass}";
    echo "          - ME_CONFIG_BASICAUTH_USERNAME=${admin_user}";
    echo "          - ME_CONFIG_BASICAUTH_PASSWORD=${admin_pass}";
    echo "      volumes:";
    echo "          - ./data/mongo-express:/data/db/";
    echo "      depends_on:";
    echo "          - mongodb";
}

compose