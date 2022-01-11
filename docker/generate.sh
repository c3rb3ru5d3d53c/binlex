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
replicas=3
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

rm -rf scripts/
mkdir -p scripts/

if [ ! -f replica.key ]; then
    openssl rand -base64 346 > replica.key;
    sudo chown 999:999 replica.key;
    sudo chmod 600 replica.key;
fi

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
            echo "      command: mongod --shardsvr --bind_ip_all --replSet shard${j} --port ${mongodb_shard_port} --dbpath /data/db/ --keyFile /data/replica.key";
            echo "      volumes:";
            echo "          - ./replica.key:/data/replica.key";
            echo "          - ./data/mongodb-shard${j}-rep${i}/:/data/db/";
            #echo "          - ./scripts/initrep${j}.js:/docker-entrypoint-initdb.d/init-mongo.js";
        done
    done
    for i in $(seq 1 $replicas); do
        echo "  mongodb-config-rep${i}:";
        echo "      hostname: mongodb-config-rep${i}";
        echo "      container_name: mongodb-config-rep${i}";
        echo "      image: mongo:${mongodb_version}";
        echo "      command: mongod --configsvr --bind_ip_all --replSet ${configdb} --port ${mongodb_config_port} --dbpath /data/db/ --keyFile /data/replica.key";
        echo "      volumes:";
        echo "          - ./replica.key:/data/replica.key";
        echo "          - ./data/mongodb-config-rep${i}/:/data/db/";
        #echo "          - ./scripts/initconfig.js:/docker-entrypoint-initdb.d/init-mongo.js";
    done
    for i in $(seq 1 $routers); do
        echo "  mongodb-router${i}:";
        echo "      hostname: mongodb-router${i}";
        echo "      container_name: mongodb-router${i}";
        echo "      image: mongo:${mongodb_version}";
        echo -n "      command: mongos --keyFile /data/replica.key --bind_ip_all --port ${mongodb_router_port} --configdb ";
        echo -n "\"${configdb}/";
        for j in $(seq 1 $replicas); do
            echo -n "mongodb-config-rep${j}:${mongodb_config_port},";
        done | sed 's/,$//'
        echo "\"";
        echo "      volumes:";
        echo "          - ./replica.key:/data/replica.key";
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

function admin_init(){
    echo "use admin;";
    echo "db.createUser({"
    echo "  user: \"${admin_user}\",";
    echo "  pwd: \"${admin_pass}\",";
    echo "  roles: [";
    echo "      {role: \"clusterAdmin\", db: \"admin\"},";
    echo "      \"userAdminAnyDatabase\","
    echo "      \"readWriteAnyDatabase\"";
    echo "  ],";
    echo "  mechanisms:[\"SCRAM-SHA-1\"]";
    echo "});"
}

function db_init(){
    echo "use ${initdb};";
    echo "db.createUser({user:\"${username}\",pwd:\"${password}\",roles:[{role:\"readWrite\",db:\"binlex\"}],mechanisms:[\"SCRAM-SHA-1\"]});"
    cat schema.js
}

function router_init(){
    echo "#!/usr/bin/env bash";
    for i in $(seq 1 $shards); do
        for j in $(seq 1 $replicas); do
            echo "sh.addShard(\"shard${i}/mongodb-shard${i}-rep${j}:${mongodb_shard_port}\");";
        done
    done
}

function shard_init(){
    echo "rs.initiate({_id: \"shard$1\", members: [";
    for i in $(seq 1 $replicas); do
        echo "  {_id: `expr ${i} - 1`, host: \"mongodb-shard$1-rep${i}:${mongodb_shard_port}\"},";
    done
    echo "]});";
}

function cfg_init(){
    echo "rs.initiate({_id: \"${configdb}\", configsvr: true, members: [";
    for i in $(seq 1 $replicas); do
        echo "  {_id: `expr ${i} - 1`, host: \"mongodb-config-rep${i}:${mongodb_config_port}\"},";
    done
    echo "]});";
}

function docker_cfg_init(){
    echo "#!/usr/bin/env bash";
    echo "docker cp init-cfgs.js mongodb-config-rep1:/tmp/init-cfgs.js"
    echo "docker exec -it mongodb-config-rep1 bash -c \"cat /tmp/init-cfgs.js | mongosh 127.0.0.1:${mongodb_config_port}\"";
}

# function docker_shard1_init(){
#     echo "#!/usr/bin/env bash";
#     echo "docker cp init-shard1.js mongodb-shard1-rep1:/tmp/init-shard1.js";
#     echo "docker exec -it mongodb-shard1-rep1 bash -c \"cat /tmp/init-shard1.js | mongosh 127.0.0.1:${mongodb_shard_port}\"";
# }

function docker_admin_init(){
    echo "#!/usr/bin/env bash";
    echo "docker cp init-admin.js mongodb-router1:/tmp/init-admin.js";
    echo "docker exec -it mongodb-router1 bash -c \"cat /tmp/init-admin.js | mongosh 127.0.0.1:${mongodb_router_port}\"";
}

function docker_shard_init(){
    echo "#!/usr/bin/env bash";
    echo "docker cp init-shard$1.js mongodb-shard$1-rep1:/tmp/init-shard$1.js";
    echo "docker exec -it mongodb-shard$1-rep1 bash -c \"cat /tmp/init-shard$1.js | mongosh 127.0.0.1:${mongodb_shard_port}\"";
}

function docker_router_init(){
    echo "#!/usr/bin/env bash";
    echo "docker cp init-router.js mongodb-router1:/tmp/init-router.js";
    echo "docker exec -it mongodb-router1 bash -c \"cat /tmp/init-router.js | mongosh 127.0.0.1:${mongodb_router_port} -u \\\"${admin_user}\\\" -p \\\"${admin_pass}\\\" --authenticationDatabase admin\""
}

function docker_db_init(){
    echo "#!/usr/bin/env bash";
    echo "docker cp init-db.js mongodb-router1:/tmp/init-db.js";
    echo "docker exec -it mongodb-router1 bash -c \"cat /tmp/init-db.js | mongosh 127.0.0.1:${mongodb_router_port} -u \\\"${admin_user}\\\" -p \\\"${admin_pass}\\\" --authenticationDatabase admin\""
}

function docker_shards_init(){
    echo "#!/usr/bin/env bash";
    for i in $(seq 1 $shards); do
        echo "./init-shard${i}.sh";
    done
}

function docker_all_init(){
    echo "#!/usr/bin/env bash";
    echo "until ./init-cfgs.sh; do";
    echo "  sleep 10;";
    echo "done";
    echo "until ./init-shards.sh; do";
    echo "  sleep 10;";
    echo "done";
    echo "until ./init-admin.sh; do";
    echo "  sleep 10;";
    echo "done";
    echo "until ./init-router.sh; do";
    echo "  sleep 10;";
    echo "done";
    echo "until ./init-db.sh; do";
    echo "  sleep 10;";
    echo "done";
}

cfg_init > scripts/init-cfgs.js
docker_cfg_init > scripts/init-cfgs.sh
chmod +x scripts/init-cfgs.sh
for i in $(seq 1 $shards); do
    shard_init ${i} > scripts/init-shard${i}.js;
done
router_init > scripts/init-router.js
db_init > scripts/init-db.js
admin_init > scripts/init-admin.js
docker_admin_init > scripts/init-admin.sh
chmod +x scripts/init-admin.sh

for i in $(seq 1 $shards); do
    docker_shard_init ${i} > scripts/init-shard${i}.sh;
    chmod +x scripts/init-shard${i}.sh;
done

docker_shards_init > scripts/init-shards.sh
chmod +x scripts/init-shards.sh

docker_router_init > scripts/init-router.sh
chmod +x scripts/init-router.sh

docker_db_init > scripts/init-db.sh
chmod +x scripts/init-db.sh

docker_all_init > scripts/init-all.sh
chmod +x scripts/init-all.sh
