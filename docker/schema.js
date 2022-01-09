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
            bsonType: "string",
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
            bsonType: "string",
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

db.createCollection('default', {
    validator: {
        $jsonSchema: trait_schema
    }
});

db.createCollection('malware', {
    validator: {
        $jsonSchema: trait_schema
    }
});

db.createCollection('goodware', {
    validator: {
        $jsonSchema: trait_schema
    }
});