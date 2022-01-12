#!/usr/bin/env bash

# This Script Generates Files Nessasary to Build MongoDB Cluster and Replica Sets

# Default Options
compose_version=3.3
mongo_express_version=0.54.0
mongodb_version=5.0.5
mongodb_port=27017
mongo_express_port=8081
configdb=configdb
initdb=binlex
replicas=3
shards=2
routers=2
admin_user=admin
admin_pass=changeme
username=binlex
password=changeme

function help_menu(){
    printf "generator.sh - MongoDB Docker Shard Generator\n";
    printf "  -h\t\t--help\t\t\tHelp Menu\n";
    printf "  -mp\t\t--mongodb-port\t\tMongoDB Port\n";
    printf "  -mep\t\t--mongo-express-port\tMongo Express Port\n";
    printf "  -c\t\t--configdb\t\tMongoDB ConfigDB Name\n";
    printf "  -i\t\t--initdb\t\tMongoDB InitDB Name\n";
    printf "  -reps\t\t--replicas\t\tMongoDB Replica Count\n";
    printf "  -shrds\t--shards\t\tMongoDB Shard Count\n";
    printf "  -rtrs\t\t--routers\t\tMongoDB Routers Count\n";
    printf "  -au\t\t--admin-user\t\tMongoDB Admin User\n";
    printf "  -ap\t\t--admin-pass\t\tMongoDB Admin Password\n";
    printf "  -u\t\t--username\t\tMongoDB InitDB Username\n";
    printf "  -p\t\t--password\t\tMongoDB InitDB Password\n";
    printf "Author: @c3rb3ru5d3d53c\n";
}

while test $# -gt 0; do
    case "$1" in
        -h|--help)
            help_menu
            exit 0
            ;;
        -mp|--mongodb-port)
            shift
            if test $# -gt 0; then
                mongodb_port=$1
            else
                echo "[x] missing argument"
                exit 1
            fi
            ;;
        -mep|--mongodb-express-port)
            shift
            if test $# -gt 0; then
                mongo_express_port=$1
            else
                echo "[x] missing argument"
                exit 1
            fi
            ;;
        -reps|--replicas)
            shift
            if test $# -gt 0; then
                replicas=$1
            else
                echo "[x] missing argument"
                exit 1
            fi
            ;;
        -shrds|--shards)
            shift
            if test $# -gt 0; then
                shards=$1
            else
                echo "[x] missing argument"
                exit 1
            fi
            ;;
        -rtrs|--routers)
            shift
            if test $# -gt 0; then
                routers=$1
            else
                echo "[x] missing argument"
                exit 1
            fi
            ;;
        -au|--admin-user)
            shift
            if test $# -gt 0; then
                admin_user=$1
            else
                echo "[x] missing argument"
                exit 1
            fi
            ;;
        -ap|--admin-pass)
            shift
            if test $# -gt 0; then
                admin_pass=$1
            else
                echo "[x] missing argument"
                exit 1
            fi
            ;;
        -u|--username)
            shift
            if test $# -gt 0; then
                username=$1
            else
                echo "[x] missing argument"
                exit 1
            fi
            ;;
        -p|--password)
            shift
            if test $# -gt 0; then
                password=$1
            else
                echo "[x] missing argument"
                exit 1
            fi
            ;;
    esac
    shift
done

function generate_alt_dns(){
    echo "[ v3_req ]";
    echo "subjectAltName = @alt_names";
    echo "[ alt_names ]";
    echo "DNS.1 = 127.0.0.1";
    echo "DNS.2 = localhost";
    echo "DNS.3 = $1";
}

function generate_certificates(){
    mkdir -p ssl/
    # Create CA
    openssl req \
        -passout pass:password \
        -new -x509 \
        -days 3650 \
        -extensions v3_ca \
        -keyout ssl/mongodb-private-ca.pem \
        -out ssl/mongodb-public-ca.pem \
        -subj "/CN=CA/OU=mongodb";

    # Create Client Certificate
    openssl req \
        -newkey rsa:4096 \
        -nodes \
        -out ssl/mongodb-client-${admin_user}.csr \
        -keyout ssl/mongodb-client-${admin_user}.key \
        -subj "/CN=${admin_user}/OU=mongodb-clients";

    # Sign Client Certificate
    openssl x509 \
        -passin pass:password \
        -sha256 -req \
        -days 365 \
        -in ssl/mongodb-client-${admin_user}.csr \
        -CA ssl/mongodb-public-ca.pem \
        -CAkey ssl/mongodb-private-ca.pem \
        -CAcreateserial \
        -out ssl/mongodb-client-${admin_user}.crt;

    cat ssl/mongodb-client-${admin_user}.crt ssl/mongodb-client-${admin_user}.key > ssl/mongodb-client-${admin_user}.pem;

    # Generate Certificates for Shards
    for i in $(seq 1 $shards); do
        for j in $(seq 1 $replicas); do
            generate_alt_dns mongodb-shard${i}-rep${j} > ssl/mongodb-shard${i}-rep${j}.ext;
            openssl req \
                -newkey rsa:4096 \
                -nodes \
                -out ssl/mongodb-shard${i}-rep${j}.csr \
                -keyout ssl/mongodb-shard${i}-rep${j}.key \
                -subj "/CN=mongodb-shard${i}-rep${j}/OU=mongodb";
            openssl x509 \
                -passin pass:password \
                -sha256 \
                -req \
                -days 365 \
                -in ssl/mongodb-shard${i}-rep${j}.csr \
                -CA ssl/mongodb-public-ca.pem \
                -CAkey ssl/mongodb-private-ca.pem \
                -CAcreateserial \
                -out ssl/mongodb-shard${i}-rep${j}.crt \
                -extensions v3_req \
                -extfile ssl/mongodb-shard${i}-rep${j}.ext;
            cat ssl/mongodb-shard${i}-rep${j}.crt ssl/mongodb-shard${i}-rep${j}.key > ssl/mongodb-shard${i}-rep${j}.pem;
        done
    done

    for i in $(seq 1 $replicas); do
        generate_alt_dns mongodb-config-rep${i} > ssl/mongodb-config-rep${i}.ext;
        openssl req \
            -newkey rsa:4096 \
            -nodes \
            -out ssl/mongodb-config-rep${i}.csr \
            -keyout ssl/mongodb-config-rep${i}.key \
            -subj "/CN=mongodb-config-rep${i}/OU=mongodb";
        openssl x509 \
            -passin pass:password \
            -sha256 \
            -req \
            -days 365 \
            -in ssl/mongodb-config-rep${i}.csr \
            -CA ssl/mongodb-public-ca.pem \
            -CAkey ssl/mongodb-private-ca.pem \
            -CAcreateserial \
            -out ssl/mongodb-config-rep${i}.crt \
            -extensions v3_req \
            -extfile ssl/mongodb-config-rep${i}.ext;
        cat ssl/mongodb-config-rep${i}.crt ssl/mongodb-config-rep${i}.key > ssl/mongodb-config-rep${i}.pem;
    done

    for i in $(seq 1 $routers); do
        generate_alt_dns mongodb-router${i} > ssl/mongodb-router${i}.ext;
        openssl req \
            -newkey rsa:4096 \
            -nodes \
            -out ssl/mongodb-router${i}.csr \
            -keyout ssl/mongodb-router${i}.key \
            -subj "/CN=mongodb-router${i}/OU=mongodb";
        openssl x509 \
            -passin pass:password \
            -sha256 \
            -req \
            -days 365 \
            -in ssl/mongodb-router${i}.csr \
            -CA ssl/mongodb-public-ca.pem \
            -CAkey ssl/mongodb-private-ca.pem \
            -CAcreateserial \
            -out ssl/mongodb-router${i}.crt \
            -extensions v3_req \
            -extfile ssl/mongodb-router${i}.ext;
        cat ssl/mongodb-router${i}.crt ssl/mongodb-router${i}.key > ssl/mongodb-router${i}.pem;
    done

    sudo chown 999:999 ssl/*;
    sudo chmod 600 ssl/*;
}

if [ ! -d ssl/ ]; then
    generate_certificates
fi

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
            echo "      command: mongod --shardsvr --bind_ip_all --replSet shard${j} --port ${mongodb_port} --dbpath /data/db/ --keyFile /data/replica.key --tlsMode requireTLS --tlsCertificateKeyFile /data/mongodb-shard${j}-rep${i}.pem --tlsCAFile /data/mongodb-public-ca.pem";
            echo "      volumes:";
            echo "          - ./ssl/mongodb-client-${admin_user}.pem:/data/mongodb-client-${admin_user}.pem";
            echo "          - ./ssl/mongodb-public-ca.pem:/data/mongodb-public-ca.pem";
            echo "          - ./ssl/mongodb-shard${j}-rep${i}.pem:/data/mongodb-shard${j}-rep${i}.pem";
            echo "          - ./replica.key:/data/replica.key";
            echo "          - ./data/mongodb-shard${j}-rep${i}/:/data/db/";
        done
    done
    for i in $(seq 1 $replicas); do
        echo "  mongodb-config-rep${i}:";
        echo "      hostname: mongodb-config-rep${i}";
        echo "      container_name: mongodb-config-rep${i}";
        echo "      image: mongo:${mongodb_version}";
        echo "      command: mongod --configsvr --bind_ip_all --replSet ${configdb} --port ${mongodb_port} --dbpath /data/db/ --keyFile /data/replica.key --tlsMode requireTLS --tlsCertificateKeyFile /data/mongodb-config-rep${i}.pem --tlsCAFile /data/mongodb-public-ca.pem";
        echo "      volumes:";
        echo "          - ./ssl/mongodb-client-${admin_user}.pem:/data/mongodb-client-${admin_user}.pem"
        echo "          - ./ssl/mongodb-public-ca.pem:/data/mongodb-public-ca.pem";
        echo "          - ./ssl/mongodb-config-rep${i}.pem:/data/mongodb-config-rep${i}.pem";
        echo "          - ./replica.key:/data/replica.key";
        echo "          - ./data/mongodb-config-rep${i}/:/data/db/";
    done
    for i in $(seq 1 $routers); do
        echo "  mongodb-router${i}:";
        echo "      hostname: mongodb-router${i}";
        echo "      container_name: mongodb-router${i}";
        echo "      image: mongo:${mongodb_version}";
        echo -n "      command: mongos --keyFile /data/replica.key --bind_ip_all --port ${mongodb_port} --tlsMode requireTLS --tlsCertificateKeyFile /data/mongodb-router${i}.pem --tlsCAFile /data/mongodb-public-ca.pem --configdb ";
        echo -n "\"${configdb}/";
        for j in $(seq 1 $replicas); do
            echo -n "mongodb-config-rep${j}:${mongodb_port},";
        done | sed 's/,$//'
        echo "\"";
        echo "      volumes:";
        echo "          - ./ssl/mongodb-client-${admin_user}.pem:/data/mongodb-client-${admin_user}.pem"
        echo "          - ./ssl/mongodb-public-ca.pem:/data/mongodb-public-ca.pem";
        echo "          - ./ssl/mongodb-router${i}.pem:/data/mongodb-router${i}.pem";
        echo "          - ./replica.key:/data/replica.key";
        echo "          - ./data/mongodb-router${i}/:/data/db/";
        echo "      ports:";
        echo "          - `expr ${mongodb_port} + ${i} - 1`:${mongodb_port}"
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
            echo "sh.addShard(\"shard${i}/mongodb-shard${i}-rep${j}:${mongodb_port}\");";
        done
    done
}

function shard_init(){
    echo "rs.initiate({_id: \"shard$1\", members: [";
    for i in $(seq 1 $replicas); do
        echo "  {_id: `expr ${i} - 1`, host: \"mongodb-shard$1-rep${i}:${mongodb_port}\"},";
    done
    echo "]});";
}

function cfg_init(){
    echo "rs.initiate({_id: \"${configdb}\", configsvr: true, members: [";
    for i in $(seq 1 $replicas); do
        echo "  {_id: `expr ${i} - 1`, host: \"mongodb-config-rep${i}:${mongodb_port}\"},";
    done
    echo "]});";
}

function docker_cfg_init(){
    echo "#!/usr/bin/env bash";
    echo "docker cp init-cfgs.js mongodb-config-rep1:/tmp/init-cfgs.js"
    echo "docker exec -it mongodb-config-rep1 bash -c \"cat /tmp/init-cfgs.js | mongosh 127.0.0.1:27017 --tls --tlsCertificateKeyFile /data/mongodb-client-${admin_user}.pem --tlsCAFile /data/mongodb-public-ca.pem --tlsAllowInvalidHostnames\"";
}

function docker_admin_init(){
    echo "#!/usr/bin/env bash";
    echo "docker cp init-admin.js mongodb-router1:/tmp/init-admin.js";
    echo "docker exec -it mongodb-router1 bash -c \"cat /tmp/init-admin.js | mongosh 127.0.0.1:${mongodb_port} --tls --tlsCertificateKeyFile /data/mongodb-client-${admin_user}.pem --tlsCAFile /data/mongodb-public-ca.pem --tlsAllowInvalidHostnames\"";
}

function docker_shard_init(){
    echo "#!/usr/bin/env bash";
    echo "docker cp init-shard$1.js mongodb-shard$1-rep1:/tmp/init-shard$1.js";
    echo "docker exec -it mongodb-shard$1-rep1 bash -c \"cat /tmp/init-shard$1.js | mongosh 127.0.0.1:${mongodb_port} --tls --tlsCertificateKeyFile /data/mongodb-client-${admin_user}.pem --tlsCAFile /data/mongodb-public-ca.pem --tlsAllowInvalidHostnames\"";
}

function docker_router_init(){
    echo "#!/usr/bin/env bash";
    echo "docker cp init-router.js mongodb-router1:/tmp/init-router.js";
    echo "docker exec -it mongodb-router1 bash -c \"cat /tmp/init-router.js | mongosh 127.0.0.1:${mongodb_port} --tls --tlsCertificateKeyFile /data/mongodb-client-${admin_user}.pem --tlsCAFile /data/mongodb-public-ca.pem --tlsAllowInvalidHostnames -u \\\"${admin_user}\\\" -p \\\"${admin_pass}\\\" --authenticationDatabase admin\""
}

function docker_db_init(){
    echo "#!/usr/bin/env bash";
    echo "docker cp init-db.js mongodb-router1:/tmp/init-db.js";
    echo "docker exec -it mongodb-router1 bash -c \"cat /tmp/init-db.js | mongosh 127.0.0.1:${mongodb_port} --tls --tlsCertificateKeyFile /data/mongodb-client-${admin_user}.pem --tlsCAFile /data/mongodb-public-ca.pem --tlsAllowInvalidHostnames -u \\\"${admin_user}\\\" -p \\\"${admin_pass}\\\" --authenticationDatabase admin\""
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

function docker_admin_shell(){
    echo "#!/usr/bin/env bash";
    echo "docker exec -it \$1 mongosh 127.0.0.1:${mongodb_port} --tls --tlsCertificateKeyFile /data/mongodb-client-${admin_user}.pem --tlsCAFile /data/mongodb-public-ca.pem --tlsAllowInvalidHostnames -u \\\"${admin_user}\\\" -p \\\"${admin_pass}\\\" --authenticationDatabase admin"
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

docker_admin_shell > scripts/shell.sh
chmod +x scripts/shell.sh
