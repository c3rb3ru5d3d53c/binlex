#!/usr/bin/env bash

# This Script Generates Files Nessasary to Build MongoDB Cluster and Replica Sets

# Default Options
compose_version=3.3
node_version=latest
mongo_express_version=0.54.0
mongodb_version=5.0.5
mongodb_sh_version=1.1.8
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

threads=4

# RabbitMQ
brokers=4
rabbitmq_version=3.9.12
rabbitmq_cookie=$(cat /dev/urandom | tr -dc 'a-z0-9' | fold -w 32 | head -n 1)
rabbitmq_port=5672
rabbitmq_http_port=15672

blworkers=8
blworker_version=1.1.1

blapis=1
blapi_version=1.1.1

function help_menu(){
    printf "docker.sh - Binlex Production Docker Generator\n";
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
    echo "IP.1 = 127.0.0.1";
    echo "DNS.2 = localhost";
    echo "DNS.3 = $1";
}

function generate_certificates(){
    mkdir -p ssl/
    # Create CA
    openssl req \
        -passout pass:${admin_pass} \
        -new -x509 \
        -days 365 \
        -extensions v3_ca \
        -keyout ssl/binlex-private-ca.pem \
        -out ssl/binlex-public-ca.pem \
        -subj "/CN=CA/OU=binlex";

    openssl x509 -outform der -in ssl/binlex-public-ca.pem -out ssl/binlex-public-ca.crt;

    # Create Client Certificate
    openssl req \
        -newkey rsa:4096 \
        -nodes \
        -out ssl/binlex-client.csr \
        -keyout ssl/binlex-client.key \
        -subj "/CN=binlex-client/OU=binlex-clients";

    # Sign Client Certificate
    openssl x509 \
        -passin pass:${admin_pass} \
        -sha256 -req \
        -days 365 \
        -in ssl/binlex-client.csr \
        -CA ssl/binlex-public-ca.pem \
        -CAkey ssl/binlex-private-ca.pem \
        -CAcreateserial \
        -out ssl/binlex-client.crt;

    cat ssl/binlex-client.crt ssl/binlex-client.key > ssl/binlex-client.pem;

    # Generate Certificates for Shards
    for i in $(seq 1 $shards); do
        for j in $(seq 1 $replicas); do
            generate_alt_dns mongodb-shard${i}-rep${j} > ssl/mongodb-shard${i}-rep${j}.ext;
            openssl req \
                -newkey rsa:4096 \
                -nodes \
                -out ssl/mongodb-shard${i}-rep${j}.csr \
                -keyout ssl/mongodb-shard${i}-rep${j}.key \
                -subj "/CN=mongodb-shard${i}-rep${j}/OU=binlex-mongodb";
            openssl x509 \
                -passin pass:${admin_pass} \
                -sha256 \
                -req \
                -days 365 \
                -in ssl/mongodb-shard${i}-rep${j}.csr \
                -CA ssl/binlex-public-ca.pem \
                -CAkey ssl/binlex-private-ca.pem \
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
            -subj "/CN=mongodb-config-rep${i}/OU=binlex-mongodb";
        openssl x509 \
            -passin pass:${admin_pass} \
            -sha256 \
            -req \
            -days 365 \
            -in ssl/mongodb-config-rep${i}.csr \
            -CA ssl/binlex-public-ca.pem \
            -CAkey ssl/binlex-private-ca.pem \
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
            -subj "/CN=mongodb-router${i}/OU=binlex-mongodb";
        openssl x509 \
            -passin pass:${admin_pass} \
            -sha256 \
            -req \
            -days 365 \
            -in ssl/mongodb-router${i}.csr \
            -CA ssl/binlex-public-ca.pem \
            -CAkey ssl/binlex-private-ca.pem \
            -CAcreateserial \
            -out ssl/mongodb-router${i}.crt \
            -extensions v3_req \
            -extfile ssl/mongodb-router${i}.ext;
        cat ssl/mongodb-router${i}.crt ssl/mongodb-router${i}.key > ssl/mongodb-router${i}.pem;
    done

    for i in $(seq 1 $brokers); do
        generate_alt_dns rabbitmq-broker${i} > ssl/rabbitmq-broker${i}.ext;
        openssl req \
            -newkey rsa:4096 \
            -nodes \
            -out ssl/rabbitmq-broker${i}.csr \
            -keyout ssl/rabbitmq-broker${i}.key \
            -subj "/CN=rabbitmq-broker${i}/OU=binlex-rabbitmq";
        openssl x509 \
            -passin pass:${admin_pass} \
            -sha256 \
            -req \
            -days 365 \
            -in ssl/rabbitmq-broker${i}.csr \
            -CA ssl/binlex-public-ca.pem \
            -CAkey ssl/binlex-private-ca.pem \
            -CAcreateserial \
            -out ssl/rabbitmq-broker${i}.crt \
            -extensions v3_req \
            -extfile ssl/rabbitmq-broker${i}.ext;
        cat ssl/rabbitmq-broker${i}.crt ssl/rabbitmq-broker${i}.key > ssl/rabbitmq-broker${i}.pem;
    done

    for i in $(seq 1 $blapis); do
        generate_alt_dns blapi${i} > ssl/blapi${i}.ext;
        openssl req \
            -newkey rsa:4096 \
            -nodes \
            -out ssl/blapi${i}.csr \
            -keyout ssl/blapi${i}.key \
            -subj "/CN=blapi${i}/OU=binlex-rabbitmq";
        openssl x509 \
            -passin pass:${admin_pass} \
            -sha256 \
            -req \
            -days 365 \
            -in ssl/blapi${i}.csr \
            -CA ssl/binlex-public-ca.pem \
            -CAkey ssl/binlex-private-ca.pem \
            -CAcreateserial \
            -out ssl/blapi${i}.crt \
            -extensions v3_req \
            -extfile ssl/blapi${i}.ext;
        cat ssl/blapi${i}.crt ssl/blapi${i}.key > ssl/blapi${i}.pem;
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
            echo "      command: mongod --shardsvr --bind_ip_all --replSet shard${j} --port ${mongodb_port} --dbpath /data/db/ --keyFile /data/replica.key --tlsMode requireTLS --tlsCertificateKeyFile /data/mongodb-shard${j}-rep${i}.pem --tlsCAFile /data/binlex-public-ca.pem";
            echo "      volumes:";
            echo "          - ./ssl/binlex-client.pem:/data/binlex-client.pem";
            echo "          - ./ssl/binlex-public-ca.pem:/data/binlex-public-ca.pem";
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
        echo "      command: mongod --configsvr --bind_ip_all --replSet ${configdb} --port ${mongodb_port} --dbpath /data/db/ --keyFile /data/replica.key --tlsMode requireTLS --tlsCertificateKeyFile /data/mongodb-config-rep${i}.pem --tlsCAFile /data/binlex-public-ca.pem";
        echo "      volumes:";
        echo "          - ./ssl/binlex-client.pem:/data/binlex-client.pem"
        echo "          - ./ssl/binlex-public-ca.pem:/data/binlex-public-ca.pem";
        echo "          - ./ssl/mongodb-config-rep${i}.pem:/data/mongodb-config-rep${i}.pem";
        echo "          - ./replica.key:/data/replica.key";
        echo "          - ./data/mongodb-config-rep${i}/:/data/db/";
    done
    for i in $(seq 1 $routers); do
        echo "  mongodb-router${i}:";
        echo "      hostname: mongodb-router${i}";
        echo "      container_name: mongodb-router${i}";
        echo "      image: mongo:${mongodb_version}";
        echo -n "      command: mongos --keyFile /data/replica.key --bind_ip_all --port ${mongodb_port} --tlsMode requireTLS --tlsCertificateKeyFile /data/mongodb-router${i}.pem --tlsCAFile /data/binlex-public-ca.pem --configdb ";
        echo -n "\"${configdb}/";
        for j in $(seq 1 $replicas); do
            echo -n "mongodb-config-rep${j}:${mongodb_port},";
        done | sed 's/,$//'
        echo "\"";
        echo "      volumes:";
        echo "          - ./ssl/binlex-client.pem:/data/binlex-client.pem"
        echo "          - ./ssl/binlex-public-ca.pem:/data/binlex-public-ca.pem";
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
    for i in $(seq 1 $brokers); do
        echo "  rabbitmq-broker${i}:";
        echo "      hostname: rabbitmq-broker${i}";
        echo "      container_name: rabbitmq-broker${i}";
        echo "      image: rabbitmq:${rabbitmq_version}-management";
        echo "      environment:";
        echo "          RABBITMQ_ERLANG_COOKIE: \"${rabbitmq_cookie}\"";
        echo "          RABBITMQ_DEFAULT_USER: \"${admin_user}\"";
        echo "          RABBITMQ_DEFAULT_PASS: \"${admin_pass}\"";
        echo "          RABBITMQ_CONFIG_FILE: \"/config/rabbitmq-broker${i}.conf\"";
        echo "      ports:";
        echo "          - `expr ${rabbitmq_port} + ${i} - 1`:5672";
        echo "          - `expr ${rabbitmq_http_port} + ${i} - 1`:15672";
        echo "      volumes:";
        echo "          - ./data/rabbitmq-broker${i}/:/var/lib/rabbitmq/mnesia/";
        echo "          - ./config/rabbitmq-broker${i}.conf:/config/rabbitmq-broker${i}.conf";
        echo "          - ./ssl/rabbitmq-broker${i}.pem:/config/rabbitmq-broker${i}.pem";
        echo "          - ./ssl/rabbitmq-broker${i}.crt:/config/rabbitmq-broker${i}.crt";
        echo "          - ./ssl/rabbitmq-broker${i}.key:/config/rabbitmq-broker${i}.key";
        echo "          - ./ssl/binlex-client.pem:/config/binlex-client.pem";
        echo "          - ./ssl/binlex-public-ca.pem:/config/binlex-public-ca.pem";
        echo "          - ./ssl/binlex-public-ca.crt:/config/binlex-public-ca.crt";
    done
    rabbitmq_iter=1;
    mongodb_iter=1;
    for i in $(seq 1 $blworkers); do
        echo "  blworker${i}:";
        echo "      hostname: blworker${i}";
        echo "      container_name: blworker${i}";
        echo "      image: blworker:${blworker_version}";
        echo "      build:";
        echo "          context: docker/blworker/";
        echo "          dockerfile: Dockerfile";
        echo "      command: blworker --debug --amqp-tls --amqp-queue binlex --amqp-user \"${admin_user}\" --amqp-pass \"${admin_pass}\" --amqp-ca /config/binlex-public-ca.pem --amqp-cert /config/binlex-client.crt --amqp-key /config/binlex-client.key --amqp-port ${rabbitmq_port} --amqp-host rabbitmq-broker${rabbitmq_iter} --mongodb-tls --mongodb-ca /config/binlex-public-ca.pem --mongodb-key /config/binlex-client.pem  --mongodb-url \"mongodb://${admin_user}:${admin_pass}@mongodb-router${mongodb_iter}:${mongodb_port}\"";
        echo "      volumes:";
        echo "          - ./ssl/binlex-client.crt:/config/binlex-client.crt";
        echo "          - ./ssl/binlex-client.key:/config/binlex-client.key";
        echo "          - ./ssl/binlex-client.pem:/config/binlex-client.pem";
        echo "          - ./ssl/binlex-public-ca.pem:/config/binlex-public-ca.pem";
        echo "      depends_on:";
        for j in $(seq 1 $brokers); do
            echo "          - rabbitmq-broker${j}";
        done
        if [ ${rabbitmq_iter} -eq $brokers ]; then
            rabbitmq_iter=1;
        else
            rabbitmq_iter=$((rabbitmq_iter+1));
        fi
        if [ ${mongodb_iter} -eq $routers ]; then
            mongodb_iter=1;
        else
            mongodb_iter=$((mongodb_iter+1));
        fi
    done
    for i in $(seq 1 $blapis); do
        echo "  blapi${i}:";
        echo "      hostname: blapi${i}";
        echo "      container_name: blapi${i}";
        echo "      image: blapi:${blapi_version}";
        echo "      build:";
        echo "          context: .";
        echo "          dockerfile: docker/blapi/Dockerfile";
        echo "      command: blapi -l 0.0.0.0 -p 8080 --debug"
        echo "      ports:";
        echo "          - 8080:8080";
        echo "      volumes:";
        echo "          - ./ssl/binlex-client.crt:/config/binlex-client.crt";
        echo "          - ./ssl/binlex-client.key:/config/binlex-client.key";
        echo "          - ./ssl/binlex-client.pem:/config/binlex-client.pem";
        echo "          - ./ssl/binlex-public-ca.pem:/config/binlex-public-ca.pem";
        # echo "      depends_on:";
        # for j in $(seq 1 $brokers); do
        #     echo "          - rabbitmq-broker${j}";
        # done
        # for j in $(seq 1 $routers); do
        #     echo "          - mongodb-router${j}";
        # done
        # for j in $(seq 1 $blworkers); do
        #     echo "          - blworker${j}";
        # done
    done
}

compose > docker-compose.yml

function rabbitmq_config_init(){
    echo "listeners.tcp = none";
    echo "loopback_users.guest = false";
    echo "listeners.ssl.default = 0.0.0.0:5672";
    echo "cluster_formation.peer_discovery_backend = rabbit_peer_discovery_classic_config";
    for i in $(seq 1 $brokers); do
        echo "cluster_formation.classic_config.nodes.${i} = rabbit@rabbitmq-broker${i}";
    done
    echo "ssl_options.cacertfile = /config/binlex-public-ca.pem";
    echo "ssl_options.certfile = /config/$1.crt";
    echo "ssl_options.keyfile = /config/$1.key";
    echo "ssl_options.verify = verify_peer";
    echo "ssl_options.fail_if_no_peer_cert = true";
    echo "management.ssl.port = 15672";
    echo "management.ssl.cacertfile = /config/binlex-public-ca.pem";
    echo "management.ssl.certfile = /config/$1.crt";
    echo "management.ssl.keyfile = /config/$1.key";
}

function docker_rabbitmq_policy_init(){
    echo "#!/usr/bin/env bash";
    echo -n "docker exec -it rabbitmq-broker1 rabbitmqctl set_policy ha-fed '.*' '{\"federation-upstream-set\":\"all\", \"ha-sync-mode\":\"automatic\", \"ha-mode\":\"nodes\", \"ha-params\":[";
    for i in $(seq 1 $brokers); do
        echo -n "\"rabbit@rabbitmq-broker${i}\",";
    done | sed 's/,$//'
    echo "]}' --priority 1 --apply-to queues";
}

function docker_rabbitmq_plugin_init(){
    echo "#!/usr/bin/env bash";
    echo "docker exec -it $1 rabbitmq-plugins enable rabbitmq_federation";
}

function docker_rabbitmq_plugins_init(){
    echo "#!/usr/bin/env bash";
    for i in $(seq 1 $brokers); do
        echo "./rabbitmq-init-plugin-broker${i}.sh";
    done
}

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
    echo "docker exec -it mongodb-config-rep1 bash -c \"cat /tmp/init-cfgs.js | mongosh 127.0.0.1:27017 --tls --tlsCertificateKeyFile /data/binlex-client.pem --tlsCAFile /data/binlex-public-ca.pem --tlsAllowInvalidHostnames\"";
}

function docker_admin_init(){
    echo "#!/usr/bin/env bash";
    echo "docker cp init-admin.js mongodb-router1:/tmp/init-admin.js";
    echo "docker exec -it mongodb-router1 bash -c \"cat /tmp/init-admin.js | mongosh 127.0.0.1:${mongodb_port} --tls --tlsCertificateKeyFile /data/binlex-client.pem --tlsCAFile /data/binlex-public-ca.pem --tlsAllowInvalidHostnames\"";
}

function docker_shard_init(){
    echo "#!/usr/bin/env bash";
    echo "docker cp init-shard$1.js mongodb-shard$1-rep1:/tmp/init-shard$1.js";
    echo "docker exec -it mongodb-shard$1-rep1 bash -c \"cat /tmp/init-shard$1.js | mongosh 127.0.0.1:${mongodb_port} --tls --tlsCertificateKeyFile /data/binlex-client.pem --tlsCAFile /data/binlex-public-ca.pem --tlsAllowInvalidHostnames\"";
}

function docker_router_init(){
    echo "#!/usr/bin/env bash";
    echo "docker cp init-router.js mongodb-router1:/tmp/init-router.js";
    echo "docker exec -it mongodb-router1 bash -c \"cat /tmp/init-router.js | mongosh 127.0.0.1:${mongodb_port} --tls --tlsCertificateKeyFile /data/binlex-client.pem --tlsCAFile /data/binlex-public-ca.pem --tlsAllowInvalidHostnames -u \\\"${admin_user}\\\" -p \\\"${admin_pass}\\\" --authenticationDatabase admin\""
}

function docker_db_init(){
    echo "#!/usr/bin/env bash";
    echo "docker cp init-db.js mongodb-router1:/tmp/init-db.js";
    echo "docker exec -it mongodb-router1 bash -c \"cat /tmp/init-db.js | mongosh 127.0.0.1:${mongodb_port} --tls --tlsCertificateKeyFile /data/binlex-client.pem --tlsCAFile /data/binlex-public-ca.pem --tlsAllowInvalidHostnames -u \\\"${admin_user}\\\" -p \\\"${admin_pass}\\\" --authenticationDatabase admin\""
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
    echo "until ./rabbitmq-init-plugins.sh; do";
    echo "  sleep 10;";
    echo "done";
    echo "until ./rabbitmq-init-policy.sh; do";
    echo "  sleep 10;";
    echo "done";
}

function docker_admin_shell(){
    echo "#!/usr/bin/env bash";
    echo "docker exec -it \$1 mongosh 127.0.0.1:${mongodb_port} --tls --tlsCertificateKeyFile /data/binlex-client.pem --tlsCAFile /data/binlex-public-ca.pem --tlsAllowInvalidHostnames -u \\\"${admin_user}\\\" -p \\\"${admin_pass}\\\" --authenticationDatabase admin"
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

docker_admin_shell > scripts/mongodb-shell.sh
chmod +x scripts/mongodb-shell.sh

mkdir -p config/

for i in $(seq 1 $brokers); do
    rabbitmq_config_init rabbitmq-broker${i} > config/rabbitmq-broker${i}.conf;
done

for i in $(seq 1 $brokers); do
    docker_rabbitmq_plugin_init rabbitmq-broker${i} > scripts/rabbitmq-init-plugin-broker${i}.sh;
    chmod +x scripts/rabbitmq-init-plugin-broker${i}.sh;
done

docker_rabbitmq_plugins_init > scripts/rabbitmq-init-plugins.sh;
chmod +x scripts/rabbitmq-init-plugins.sh;

docker_rabbitmq_policy_init > scripts/rabbitmq-init-policy.sh
chmod +x scripts/rabbitmq-init-policy.sh

# if [ ! -f scripts/rabbitmqadmin ]; then
#     wget "https://raw.githubusercontent.com/rabbitmq/rabbitmq-server/v${rabbitmq_version}/deps/rabbitmq_management/bin/rabbitmqadmin" -O scripts/rabbitmqadmin;
#     chmod +x scripts/rabbitmqadmin;
# fi

# if [ ! -f scripts/mongosh ]; then
#     wget "https://downloads.mongodb.com/compass/mongodb-mongosh_${mongodb_sh_version}_amd64.deb" -O scripts/mongosh.deb;
#     dpkg --fsys-tarfile scripts/mongosh.deb | tar xOf - ./usr/bin/mongosh > scripts/mongosh;
#     chmod +x scripts/mongosh;
# fi