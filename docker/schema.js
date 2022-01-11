var trait_schema = {
    bsonType: "object",
    required: [
        "corpus",
        "type",
        "architecture",
        "blocks",
        "edges",
        "instructions",
        "invalid_instructions",
        "offset",
        "bytes",
        "bytes_sha256",
        "bytes_entropy",
        "trait",
        "trait_sha256",
        "trait_entropy",
        "size",
        "average_instructions_per_block",
        "cyclomatic_complexity",
    ],
    properties: {
        corpus: {
            bsonType: "string",
            description: "The Corpus Name"
        },
        type: {
            bsonType: "string",
            description: "Trait Type"
        },
        architecture: {
            bsonType: "string",
            description: "Code Architecture"
        },
        blocks: {
            bsonType: "int",
            description: "Number of Blocks"
        },
        edges: {
            bsonType: "int",
            description: "Number of Edges"
        },
        instructions: {
            bsonType: "int",
            description: "Number of Instructions"
        },
        invalid_instructions: {
            bsonType: "int",
            description: "Number of Invalid Instructions"
        },
        offset: {
            bsonType: "int",
            description: "File Offset"
        },
        bytes: {
            bsonType: "objectId",
            description: "Hexadecimal Byte String"
        },
        bytes_sha256: {
            bsonType: "string",
            description: "Byte String SHA256"
        },
        bytes_entropy: {
            bsonType: "double",
            description: "Byte String Entropy"
        },
        trait: {
            bsonType: "objectId",
            description: "Wildcarded Trait String"
        },
        trait_sha256: {
            bsonType: "string",
            description: "Trait String SHA256"
        },
        trait_entropy: {
            bsonType: "double",
            description: "Trait String Entropy"
        },
        size: {
            bsonType: "int",
            description: "Size in Bytes"
        },
        average_instructions_per_block: {
            bsonType: "int",
            description: "Average Instructions per Block"
        },
        cyclomatic_complexity: {
            bsonType: "int",
            description: "Cyclomatic Complexity"
        }
    }
};

var traits_schema = {
    bsonType: "object",
    required: [
        "trait"
    ],
    properties: {
        trait: {
            bsonType: "string",
            description: "Trait String"
        }
    }
};

var bytes_schema = {
    bsonType: "object",
    required: [
        "bytes"
    ],
    properties: {
        trait: {
            bsonType: "string",
            description: "Bytes String"
        }
    }
};

db.createCollection("bytes", {
    validator: {
        $jsonSchema: bytes_schema
    }
});

db.bytes.createIndex({bytes: 1}, {unique: true});


db.createCollection("traits", {
    validator: {
        $jsonSchema: traits_schema
    }
});

db.traits.createIndex({trait: 1}, {unique: true});

db.createCollection('default', {
    validator: {
        $jsonSchema: trait_schema
    }
});

db.default.createIndex({bytes_sha256: 1}, {unique: true});
db.default.createIndex({trait_sha256: 1}, {unique: true});

db.createCollection('malware', {
    validator: {
        $jsonSchema: trait_schema
    }
});

db.malware.createIndex({bytes_sha256: 1}, {unique: true});
db.malware.createIndex({trait_sha256: 1}, {unique: true});

db.createCollection('goodware', {
    validator: {
        $jsonSchema: trait_schema
    }
});

db.goodware.createIndex({bytes_sha256: 1}, {unique: true});
db.goodware.createIndex({trait_sha256: 1}, {unique: true});