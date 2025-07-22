#!/usr/bin/env python
# MIT License
#
# Copyright (c) [2025] [c3rb3ru5d3d53c]
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


import os
import random
import json
import numpy as np
import tensorflow as tf
from tensorflow.keras.layers import Input, LSTM, Dense, Dropout, BatchNormalization, Masking, RepeatVector
from tensorflow.keras.models import Model
from tensorflow.keras.initializers import GlorotUniform, Zeros
from tensorflow.keras.preprocessing.sequence import pad_sequences
from sklearn.preprocessing import MinMaxScaler
from collections import defaultdict

##############################################################################
#                       1. FORCE CPU + SINGLE-THREADED                       #
##############################################################################
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"         # Force CPU execution
os.environ["TF_DETERMINISTIC_OPS"] = "1"          # Use deterministic ops if possible
tf.config.threading.set_intra_op_parallelism_threads(1)
tf.config.threading.set_inter_op_parallelism_threads(1)

##############################################################################
#                          2. FIX ALL RANDOM SEEDS                           #
##############################################################################
SEED = 42
random.seed(SEED)
np.random.seed(SEED)
tf.random.set_seed(SEED)
os.environ["PYTHONHASHSEED"] = str(SEED)

##############################################################################
#                       3. HELPER FUNCTIONS                                  #
##############################################################################

def preprocess_nibbles(nibble_sequences, max_len=None):
    """
    Convert variable-length nibble sequences into a padded 2D array.
    Handles nested or malformed input gracefully.
    """
    validated_sequences = []
    for seq in nibble_sequences:
        if isinstance(seq, (list, np.ndarray)):
            # Flatten nested sequences
            if any(isinstance(i, (list, np.ndarray)) for i in seq):
                seq = [item for sublist in seq for item in sublist]
            # Validate sequence content
            if all(isinstance(i, (int, float)) for i in seq):
                validated_sequences.append(seq)
            else:
                print(f"Warning: Invalid sequence skipped: {seq}")
        else:
            print(f"Warning: Non-sequence input skipped: {seq}")

    if not validated_sequences:
        raise ValueError("All input nibble sequences are invalid or empty.")

    # Determine max length if not provided
    if max_len is None:
        max_len = max(len(seq) for seq in validated_sequences)

    # Pad sequences
    return pad_sequences(validated_sequences, maxlen=max_len, padding='post', value=0)

def normalize_and_scale(vectors):
    """
    Normalize vectors to unit length, then scale from [-1,1] to [0,1].
    """
    eps = 1e-12
    norm = np.linalg.norm(vectors, axis=1, keepdims=True) + eps
    normalized_vectors = vectors / norm
    scaled_vectors = (normalized_vectors + 1) / 2
    return scaled_vectors

def compute_function_entropy(nibble_sequence):
    """
    Compute entropy of the nibble sequence for added features.
    Handles nested or malformed sequences gracefully.
    """
    try:
        # Flatten if nested
        if any(isinstance(i, (list, np.ndarray)) for i in nibble_sequence):
            nibble_sequence = [item for sublist in nibble_sequence for item in sublist]

        # Ensure the sequence is numeric
        if not all(isinstance(i, (int, float)) for i in nibble_sequence):
            print(f"Warning: Non-numeric or invalid sequence skipped: {nibble_sequence}")
            return 0  # Return a default entropy value for invalid sequences

        values, counts = np.unique(nibble_sequence, return_counts=True)
        probabilities = counts / counts.sum()
        entropy = -np.sum(probabilities * np.log2(probabilities))
        return entropy
    except Exception as e:
        print(f"Error computing entropy for sequence {nibble_sequence}: {e}")
        return 0  # Return a default value in case of errors

def encode_function_contiguity(is_contiguous):
    """
    One-hot encode the contiguity status of the function (binary).
    """
    return [1, 0] if is_contiguous else [0, 1]

def preprocess_features(nibble_sequences, contiguity_flags):
    """
    Combine nibbles, entropy, and contiguity features into a unified array.
    Handles input validation and error resilience.
    """
    try:
        max_len = max(len(seq) for seq in nibble_sequences if isinstance(seq, (list, np.ndarray)))
    except ValueError:
        raise ValueError("No valid nibble sequences provided.")

    padded_nibbles = preprocess_nibbles(nibble_sequences, max_len=max_len) / 15.0

    # Calculate entropy for each sequence
    entropies = np.array([
        compute_function_entropy(seq) if isinstance(seq, (list, np.ndarray)) else 0
        for seq in nibble_sequences
    ]).reshape(-1, 1)

    # Add contiguity information
    contiguity_vectors = np.array([
        encode_function_contiguity(flag) if isinstance(flag, bool) else [0, 0]
        for flag in contiguity_flags
    ])

    # Concatenate all features
    combined_features = np.hstack([padded_nibbles, entropies, contiguity_vectors])
    return combined_features

def construct_cfg(function_blocks):
    """
    Construct a Control Flow Graph (CFG) from basic blocks of a function.
    """
    cfg = defaultdict(list)
    for block in function_blocks:
        block_address = block['address']
        successors = block.get('successors', [])
        for succ in successors:
            cfg[block_address].append(succ)
    return cfg

def extract_cfg_features(cfg):
    """
    Extract features from a control flow graph for model input.
    """
    node_count = len(cfg)
    edge_count = sum(len(succs) for succs in cfg.values())
    max_degree = max(len(succs) for succs in cfg.values()) if cfg else 0
    return [node_count, edge_count, max_degree]

##############################################################################
#                       4. AUTOENCODER TRAINING                              #
##############################################################################

def train_autoencoder(data, input_dim, time_steps, epochs=50):
    """
    Build & train an LSTM-based autoencoder.
    """
    input_layer = Input(shape=(time_steps, input_dim))

    # Encoder
    x = Masking(mask_value=0.0)(input_layer)
    x = LSTM(128, activation='relu', kernel_initializer=GlorotUniform(seed=SEED), return_sequences=True)(x)
    x = Dropout(0.2)(x)
    x = LSTM(64, activation='relu', kernel_initializer=GlorotUniform(seed=SEED), return_sequences=False)(x)
    bottleneck = Dense(3, activation='tanh', name='bottleneck')(x)

    # Decoder
    x = RepeatVector(time_steps)(bottleneck)
    x = LSTM(64, activation='relu', kernel_initializer=GlorotUniform(seed=SEED), return_sequences=True)(x)
    x = Dropout(0.2)(x)
    x = LSTM(128, activation='relu', kernel_initializer=GlorotUniform(seed=SEED), return_sequences=True)(x)
    output_layer = Dense(input_dim, activation='sigmoid')(x)

    autoencoder = Model(inputs=input_layer, outputs=output_layer)

    # Use Adam optimizer
    optimizer = tf.keras.optimizers.Adam(learning_rate=0.001)

    autoencoder.compile(optimizer=optimizer, loss='mse')

    autoencoder.fit(
        data, data,
        epochs=epochs,
        batch_size=32,
        shuffle=True,
        verbose=0
    )

    # Return encoder and the full autoencoder
    encoder = Model(inputs=input_layer, outputs=bottleneck)
    return autoencoder, encoder

##############################################################################
#                              5. MAIN                                       #
##############################################################################

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Process JSON file with functions.")
    parser.add_argument("input_file", type=str, help="Path to the JSON file containing functions.")
    args = parser.parse_args()

    # Load and parse the JSON file
    with open(args.input_file, 'r') as f:
        functions = [json.loads(line.strip()) for line in f]

    # Initialize autoencoder variables
    autoencoder, encoder = None, None
    current_input_dim = None
    current_time_steps = None

    for function in functions:
        if function.get("type") == "function":
            nibble_sequence = function["chromosome"]["feature"] if function.get("contiguous", True) else \
                             [block["chromosome"]["feature"] for block in function.get("blocks", [])]

            contiguity_flag = function.get("contiguous", True)

            # Preprocess single function features
            input_features = preprocess_features([nibble_sequence], [contiguity_flag])
            input_features = np.expand_dims(input_features, axis=-1)  # Reshape for LSTM

            input_dim = input_features.shape[2]
            time_steps = input_features.shape[1]

            # Check input dimensions and reinitialize autoencoder if necessary
            if autoencoder is None or encoder is None or input_dim != current_input_dim or time_steps != current_time_steps:
                print(f"Reinitializing autoencoder for input_dim: {input_dim}, time_steps: {time_steps}")
                autoencoder, encoder = train_autoencoder(input_features, input_dim, time_steps, epochs=50)
                current_input_dim = input_dim
                current_time_steps = time_steps

            # Encode the function to get the 3D vector
            try:
                raw_vector = encoder.predict(input_features)

                # Compute reconstruction error as confidence score
                reconstruction = autoencoder.predict(input_features)
                mse = np.mean(np.square(input_features - reconstruction))
                confidence_score = 1 - mse  # Confidence is inversely related to error

                # Use the encoded vector directly
                print("Function Address:", function.get("address", "unknown"))
                print(f'Function Size: {function["size"]}')
                print("3D Vector [a, b, c]:", raw_vector[0].tolist())
                print("Confidence Score:", confidence_score)
            except Exception as e:
                print(f"Error processing function {function.get('address', 'unknown')}: {e}")
