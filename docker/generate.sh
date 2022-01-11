#!/usr/bin/env bash

# This Script Generates Files Nessasary to Build MongoDB Cluster and Replica Sets

# version: '3.3'

# services:
#   mongodb:
#     image: mongo:5.0.5
#     env_file: .env
#     ports:
#       - 27017:27017
#     environment:
#       - MONGO_INITDB_ROOT_USERNAME=${MONGO_ROOT_USER}
#       - MONGO_INITDB_ROOT_PASSWORD=${MONGO_ROOT_PASSWORD}
#       - MONGO_INITDB_DATABASE=binlex
#     volumes:
#       - ./data/mongodb/:/data/db/
#       - ./.init.js:/docker-entrypoint-initdb.d/init-mongo.js
#   mongo-express:
#     image: mongo-express:0.54.0
#     env_file: .env
#     ports:
#       - 8081:8081
#     environment:
#       - ME_CONFIG_MONGODB_SERVER=mongodb
#       - ME_CONFIG_MONGODB_PORT=27017
#       - ME_CONFIG_MONGODB_ENABLE_ADMIN=true
#       - ME_CONFIG_MONGODB_ADMINUSERNAME=${MONGO_ROOT_USER}
#       - ME_CONFIG_MONGODB_ADMINPASSWORD=${MONGO_ROOT_PASSWORD}
#       - ME_CONFIG_MONGODB_AUTH_DATABASE=admin
#       - ME_CONFIG_MONGODB_AUTH_USERNAME=${MONGO_ROOT_USER}
#       - ME_CONFIG_MONGODB_AUTH_PASSWORD=${MONGO_ROOT_PASSWORD}
#       - ME_CONFIG_BASICAUTH_USERNAME=${MONGOEXPRESS_LOGIN}
#       - ME_CONFIG_BASICAUTH_PASSWORD=${MONGOEXPRESS_PASSWORD}
#     volumes:
#       - ./data/mongo-express/:/data/db/
#     depends_on:
#       - mongodb

version=1.1.1
compose_version=3.3
mongo_express_version=0.54.0
mongodb_version=5.0.5
mongodb_name=mongodb
mongodb_port=27017
mongodb_config_port=27019
mongodb_shard_port=27018
mongodb_router_port=27017
configdb=configdb
initdb=binlex
rs=blrs
rscfg=blcfgrs
replicas=2
shards=2
routers=2

admin_user=admin
admin_pass=changeme
username=binlex
password=changeme

# rs.initiate(
#   {
#     _id: "blrs",
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
#     _id: "blcfgrs",
#     configsvr: true,
#     members: [
#       { _id : 0, host : "config_server_container1_ip:port" },
#       { _id : 1, host : "config_server_container2_ip:port" },
#       { _id : 2, host : "config_server_container3_ip:port" }
#     ]
#   }
# )

mkdir -p scripts/

openssl rand -base64 346 > scripts/keyfile

function compose() {
    echo "version: '${compose_version}'"
    echo "";
    echo "services:";
    for j in $(seq 1 $shards); do
        for i in $(seq 1 $replicas); do
            echo "  mongodb-shard${j}-rep${i}:";
            echo "      hostname: mongodb-shard${j}-rep${i}";
            echo "      container_name: mongodb-shard${j}-rep${i}";
            echo "      image: mongo:${mongodb_version}";
            echo "      command: mongod --shardsvr --bind_ip_all --replSet shard${j} --port ${mongodb_shard_port} --dbpath /data/db/";
            # echo "      environment:";
            # echo "          - MONGO_INITDB_ROOT_USERNAME=${admin_user}";
            # echo "          - MONGO_INITDB_ROOT_PASSWORD=${admin_pass}";
            # echo "          - MONGO_INITDB_DATABASE=${initdb}";
            echo "      volumes:";
            echo "          - ./data/mongodb-shard${j}-rep${i}/:/data/db/";
            #echo "          - ./scripts/initrep${j}.js:/docker-entrypoint-initdb.d/init-mongo.js";
        done
    done
    for i in $(seq 1 $replicas); do
        echo "  mongodb-config-rep${i}:";
        echo "      hostname: mongodb-config-rep${i}";
        echo "      container_name: mongodb-config-rep${i}";
        echo "      image: mongo:${mongodb_version}";
        echo "      command: mongod --configsvr --bind_ip_all --replSet ${configdb} --port ${mongodb_config_port} --dbpath /data/db/";
        echo "      volumes:";
        echo "          - ./data/mongodb-config-rep${i}/:/data/db/";
        #echo "          - ./scripts/initconfig.js:/docker-entrypoint-initdb.d/init-mongo.js";
    done
    for i in $(seq 1 $routers); do
        echo "  mongodb-router${i}:";
        echo "      hostname: mongodb-router${i}";
        echo "      container_name: mongodb-router${i}";
        echo "      image: mongo:${mongodb_version}";
        echo -n "      command: mongos --bind_ip_all --port ${mongodb_router_port} --configdb ";
        echo -n "\"${configdb}/";
        for j in $(seq 1 $replicas); do
            echo -n "mongodb-config-rep${j}:${mongodb_config_port},";
        done | sed 's/,$//'
        echo "\"";
        echo "      environment:";
        echo "          - MONGO_INITDB_ROOT_USERNAME=${admin_user}";
        echo "          - MONGO_INITDB_ROOT_PASSWORD=${admin_pass}";
        echo "          - MONGO_INITDB_DATABASE=${initdb}";
        echo "      volumes:";
        echo "          - ./data/mongodb-router${i}/:/data/db/";
        echo "      ports:";
        echo "          - `expr ${mongodb_port} + ${i} - 1`:${mongodb_router_port}"
        echo "      depends_on:";
        for j in $(seq 1 $replicas); do
            echo "          - mongodb-config-rep${j}";
        done
    done
    # echo "  mongo-express:";
    # echo "      image: mongo-express:${mongo_express_version}";
    # echo "      ports:";
    # echo "          - 8081:8081";
    # echo "      environment:";
    # echo "          - ME_CONFIG_MONGODB_SERVER=mongodb-router1";
    # echo "          - ME_CONFIG_MONGODB_PORT=${mongodb_port}";
    # echo "          - ME_CONFIG_MONGODB_ENABLE_ADMIN=true";
    # echo "          - ME_CONFIG_MONGODB_ADMINUSERNAME=${admin_user}";
    # echo "          - ME_CONFIG_MONGODB_ADMINPASSWORD=${admin_pass}";
    # echo "          - ME_CONFIG_MONGODB_AUTH_DATABASE=admin";
    # echo "          - ME_CONFIG_MONGODB_AUTH_USERNAME=${admin_user}";
    # echo "          - ME_CONFIG_MONGODB_AUTH_PASSWORD=${admin_pass}";
    # echo "          - ME_CONFIG_BASICAUTH_USERNAME=${admin_user}";
    # echo "          - ME_CONFIG_BASICAUTH_PASSWORD=${admin_pass}";
    # echo "      volumes:";
    # echo "          - ./data/mongo-express:/data/db/";
    # echo "      depends_on:";
    # for j in $(seq 1 $shards); do
    #     for k in $(seq 1 $replicas); do
    #         echo "          - mongodb-shard${j}-rep${k}";
    #     done
    # done
    # for i in $(seq 1 $routers); do
    #     echo "          - mongodb-router${i}";
    # done
    # for i in $(seq 1 $replicas); do
    #     echo "          - mongodb-config-rep${i}";
    # done
}

compose > docker-compose.yml

function db_init(){
    echo "db.createUser({user:\"${username}\",pwd:\"${password}\",roles:[{role:\"readWrite\",db:\"binlex\"}],mechanisms:[\"SCRAM-SHA-1\"]});"
    cat schema.js
}

db_init > scripts/initdb.js

function shard_init(){
    echo "#!/usr/bin/env bash";
    for i in $(seq 1 $shards); do
        for j in $(seq 1 $replicas); do
            echo "docker exec -it mongodb-router1 bash -c \"echo 'sh.addShard(\\\"shard${i}/mongodb-shard${i}-rep${j}:${mongodb_shard_port}\\\");' | mongo\"";
        done
    done
}

shard_init > scripts/initshards.sh

chmod +x scripts/initshards.sh

function replica_init(){
    echo -n "rs.initiate({_id: \\\"shard$1\\\", members: [";
    for i in $(seq 1 $replicas); do
        echo -n "{_id: `expr ${i} - 1`, host: \\\"mongodb-shard$1-rep${i}:${mongodb_shard_port}\\\"},";
    done | sed 's/,$//'
    echo -n "]});";
}

function cfg_init(){
    echo -n "rs.initiate({_id: \\\"${configdb}\\\", configsvr: true, members: [";
    for i in $(seq 1 $replicas); do
        echo -n "{_id: `expr ${i} - 1`, host: \\\"mongodb-config-rep${i}:${mongodb_config_port}\\\"},";
    done | sed 's/,$//'
    echo -n "]});";
}

function docker_replica_init(){
    echo "#!/usr/bin/env bash";
    echo "docker exec -it mongodb-router1 bash -c \"echo '`cfg_init`' | mongo --host mongodb-config-rep1:${mongodb_config_port}\"";
    for i in $(seq 1 $shards); do
        echo "docker exec -it mongodb-router1 bash -c \"echo '`replica_init ${i}`' | mongo --host mongodb-shard${i}-rep1:${mongodb_shard_port}\"";
    done
}

docker_replica_init > scripts/initrep.sh

chmod +x scripts/initrep.sh
