#!/usr/bin/env node

const amqp = require('amqplib');
const {MongoClient} = require('mongodb');
const ArgumentParser = require('argparse').ArgumentParser;

var mongodb_url = "mongodb://binlex:changeme@127.0.0.1:27017/?authSource=binlex";
var amqplib_url = "amqp://admin:changeme@127.0.0.1:5672";

// Parse Args Here

const parser = new ArgumentParser({
    add_help: true,
    description: 'Binlex MongoDB Worker',
    epilog: 'Author: @c3rb3ru5d3d53c'
});

parser.add_argument('--mongodb-url', {
    help: 'MongoDB Connection URL',
    default: 'mongodb://127.0.0.1:27017'
});

parser.add_argument('--amqp-url', {
    help: 'AMQP Connection URL',
    default: 'amqp://127.0.0.1:5672'
});

parser.add_argument('--mongodb-tls', {
    help: 'Enable TLS Authentication',
    action: 'store_true',
    default: false
});

parser.add_argument('--mongodb-tlsCAFile', {
    help: 'TLS Certificate Authority File'
});

parser.add_argument('--mongodb-tlsAllowInvalidHostnames', {
    help: 'TLS Certificate Authority File',
    action: 'store_true'
});

parser.add_argument('--mongodb-tlsInsecure', {
    help: 'Allow Insecure TLS Connections',
    action: 'store_true',
    default: false
});

parser.add_argument('--mongodb-tlsCertificateKeyFile', {
    help: 'Client Certificate Key File (PEM)'
});

parser.add_argument('--amqp-consumerTag', {
    help: 'Consumer Tag',
    default: 'default'
});

var args = parser.parse_args();

var mongodb_options = {
    tls: args.mongodb_tls,
    tlsCAFile: args.mongodb_tlsCAFile,
    tlsAllowInvalidHostnames: args.mongodb_tlsAllowInvalidHostnames,
    tlsInsecure: args.mongodb_tlsInsecure,
    tlsCertificateKeyFile: args.mongodb_tlsCertificateKeyFile
};

async function consume(db) {
    const connection = await amqp.connect(amqplib_url);
    const channel = await connection.createChannel();
    channel.assertQueue('binlex', {durable: true});
    channel.consume('binlex', (job) => {
        try {
            let trait_id = null;
            let data = JSON.parse(job.content.toString());
            let offset = data['offset'];
            delete data['offset'];
            if (data['corpus'].startsWith('default')){
                db.db('binlex').collection('default').insertOne(data, function(err, res){});
                trait_id = db.db('binlex').collection('default').find({bytes_sha256: data['bytes_sha256']});
                console.log(trait_id);
            } else if (data['corpus'].startsWith('malware')){
                trait_id = db.db('binlex').collection('malware').insertOne(data, function(err, res){});
            } else if  (data['corpus'].startsWith('goodware')){
                trait_id = db.db('binlex').collection('goodware').insertOne(data, function(err, res){});
            } else {
                console.log('[x] invalid corpus in message');
            }
            //console.log(job.content.toString());
        } catch (error){
            console.log('[x] ' + error);
        }
        channel.ack(job);
    });
}

MongoClient.connect(mongodb_url, mongodb_options, function(err, db) {
    console.log("Connected to MongoDB!");
    consume(db);
});