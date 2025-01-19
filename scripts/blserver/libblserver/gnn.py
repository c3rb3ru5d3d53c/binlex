#!/usr/bin/env python

import torch
import random
import numpy as np
import pandas as pd
from torch import Tensor
from torch import float32
from torch import float as torch_float
from torch import long as torch_long
from torch import tensor
from torch import manual_seed
from torch import zeros
from torch import cat
from torch import stack
from torch.nn import functional
from torch.nn import Module, BatchNorm1d, Dropout
from torch_geometric.data import Data
from torch_geometric.nn import GCNConv, global_mean_pool
from dataclasses import dataclass
from torch_pca import PCA


@dataclass
class BinlexVectorEmbedding:
    vector: list[float]
    data: dict

    def to_pandas(self) -> pd.DataFrame:
        return pd.DataFrame(
            {
                'vector': [self.vector],
                'data': [self.data],
            }
        )

    def to_dict(self) -> dict:
        return {
            'vector': self.vector,
            'data': self.data,
        }


class BinlexInnerGNN(Module):
    def __init__(self, node_features_dim: int, hidden_dim: int, output_dim: int):
        super().__init__()
        self.conv1 = GCNConv(
            in_channels=node_features_dim,
            out_channels=hidden_dim
        )
        self.bn1 = BatchNorm1d(hidden_dim)
        self.dropout = Dropout(p=0.3)
        self.conv2 = GCNConv(hidden_dim, output_dim)
        self.bn2 = BatchNorm1d(output_dim)

    def forward(self, x: Tensor, edge_index: Tensor) -> Tensor:
        x = self.conv1(x, edge_index)
        if x.size(0) > 1:
            x = self.bn1(x)
        x = x.relu()
        x = self.dropout(x)
        x = self.conv2(x, edge_index)
        if x.size(0) > 1:
            x = self.bn2(x)
        return x


class BinlexGNN:
    def __init__(
        self,
        data: dict,
        seed: int = 0,
        block_pca_dim: int = 16,
        gnn_hidden_dim: int = 32,
        gnn_output_dim: int = 16,
    ):
        """
        Initialize the GNN with data (either function or block). You can then call train(...)
        to train the model on that data, and then call to_embedding() to retrieve an embedding.

        The 'data' dict is expected to have at least a 'type' key with the value
        'function' or 'block', plus the necessary fields for extracting features.

        Example data for function:
            {
              "type": "function",
              "average_instructions_per_block": 5,
              "blocks": [
                  {
                      "size": ...,
                      "entropy": ...,
                      "number_of_instructions": ...,
                      "conditional": ...,
                      "edges": ...,
                      "functions": [...],
                      "chromosome": {
                          "feature": [...]
                      },
                      "blocks": [ ... adjacency list ... ],
                      "address": ...
                  },
                  ...
              ]
            }

        Example data for block:
            {
              "type": "block",
              "size": ...,
              "entropy": ...,
              "number_of_instructions": ...,
              "conditional": ...,
              "edges": ...,
              "functions": [...],
              "chromosome": {
                  "feature": [...]
              }
            }
        """
        random.seed(seed)
        np.random.seed(seed)
        manual_seed(seed)

        self.data = data
        self.block_pca_dim = block_pca_dim
        self.gnn_hidden_dim = gnn_hidden_dim
        self.gnn_output_dim = gnn_output_dim

        self.model = None
        self.criterion = torch.nn.MSELoss()
        self.optimizer = None

        # Will store the most recent Data object for training, and the original data
        self._last_graph_data = None
        self._last_data_dict = None

    @staticmethod
    def nibbles_to_histogram_vector(nibbles: list[int]) -> list[float]:
        """
        Convert a list of nibbles (0-15) into a histogram vector.
        Each nibble count is appended as [nibble_value, ratio_of_total].
        """
        histogram = [0] * 16
        for nibble in nibbles:
            if 0 <= nibble <= 15:
                histogram[nibble] += 1
        total_count = sum(histogram)
        encoded_histogram = []
        for nibble, count in enumerate(histogram):
            ratio = count / total_count if total_count > 0 else 0.0
            encoded_histogram.extend([float(nibble), ratio])
        return encoded_histogram

    @staticmethod
    def to_nx3_array(values: list[float]) -> np.ndarray:
        """
        Reshape the list of floats into an Nx3 array (padding if necessary).
        """
        arr = np.array(values, dtype=float)
        if arr.size == 0:
            return arr.reshape(-1, 3)
        padding = (3 - (len(arr) % 3)) % 3
        if padding > 0:
            arr = np.pad(arr, (0, padding), constant_values=0.0)
        return arr.reshape(-1, 3)

    @staticmethod
    def pca_reduce(values: np.ndarray, output_dim: int) -> np.ndarray:
        """
        Apply PCA to reduce Nx3 values to a single vector of size output_dim,
        then average across principal components to get a 1D vector.
        """
        if values.size == 0:
            return np.zeros(output_dim)
        values_torch = tensor(values, dtype=float32)
        n_rows, n_features = values_torch.shape
        n_components = min(output_dim, n_features)
        try:
            pca = PCA(n_components=n_components)
            principal_components = pca.fit_transform(values_torch)
            # Average across principal components to get a 1D vector
            values = principal_components.mean(dim=0).detach().numpy()
            # If n_components < output_dim, pad with zeros
            if n_components < output_dim:
                padding = np.zeros(output_dim - n_components)
                values = np.concatenate([values, padding])
        except Exception as e:
            print(f"PCA Reduction Error: {e}")
            values = np.zeros(output_dim)
        return values

    def _extract_block_features(self, block: dict) -> list:
        """
        Extract and assemble features from a single block.
        """
        features = [
            block['size'],
            block['entropy'],
            block['number_of_instructions'],
            block['conditional'],
            block['edges'],
            len(block['functions']),
        ]
        chromosome_feature_histogram = self.nibbles_to_histogram_vector(
            block['chromosome']['feature']
        )
        features.extend(chromosome_feature_histogram)
        return features

    def _extract_function_features(
        self,
        function: dict
    ) -> tuple[list[int], list[int], list[list[float]]]:
        """
        Build the adjacency (a, b) and node feature list for a function graph.
        """
        a, b = [], []
        features = []

        for block in function['blocks']:
            feature = self._extract_block_features(block)
            # Append function-level info
            feature.append(function['average_instructions_per_block'])

            feature_nx3 = self.to_nx3_array(feature)
            feature_reduced = self.pca_reduce(feature_nx3, output_dim=self.block_pca_dim)
            features.append(feature_reduced.tolist())

            # Build adjacency from each block's internal references
            for address in block['blocks']:
                a.append(block['address'])
                b.append(address)

        return a, b, features

    def _build_graph(
        self,
        a: list[int],
        b: list[int],
        features: list[list[float]]
    ) -> Data:
        """
        Given adjacency (a, b) and features, build a torch_geometric Data object.
        """
        max_node_index = len(features) - 1
        a_clamped = [min(max_node_index, idx) for idx in a]
        b_clamped = [min(max_node_index, idx) for idx in b]

        node_features = tensor(features, dtype=torch_float)
        edge_index = tensor([a_clamped, b_clamped], dtype=torch_long)

        # Make edges bidirectional and remove duplicates
        edge_index_rev = stack((edge_index[1], edge_index[0]), dim=0)
        edge_index = cat([edge_index, edge_index_rev], dim=1).unique(dim=1)

        return Data(x=node_features, edge_index=edge_index)

    def _initialize_model(self, input_dim: int):
        """
        Initialize the GNN model and optimizer based on input dimensions.
        """
        self.model = BinlexInnerGNN(
            node_features_dim=input_dim,
            hidden_dim=self.gnn_hidden_dim,
            output_dim=self.gnn_output_dim,
        )
        self.optimizer = torch.optim.Adam(self.model.parameters(), lr=1e-3)

    def _gnn_embedding(self, data: Data) -> Tensor:
        """
        Forward pass through the stored model to get node embeddings.
        Returns a Tensor for further processing (e.g., loss computation).
        """
        if self.model is None:
            input_dim = data.x.shape[1]
            self._initialize_model(input_dim)

        return self.model(data.x, data.edge_index)

    def train(
        self,
        epochs: int = 10
    ):
        """
        Train the GNN on the data passed into the constructor (either a single function or a block)
        using node-level MSE loss. The target is to reconstruct the original node features.

        Parameters:
        - epochs: Number of training epochs
        """
        if 'type' not in self.data:
            raise ValueError("Data must include a 'type' field, either 'function' or 'block'.")

        if self.data['type'] == 'function':
            # Extract graph data for function
            a, b, features = self._extract_function_features(self.data)
            graph_data = self._build_graph(a, b, features)
        elif self.data['type'] == 'block':
            # Extract block features
            block_features = self._extract_block_features(self.data)
            block_features_nx3 = self.to_nx3_array(block_features)
            block_features_reduced = self.pca_reduce(
                block_features_nx3,
                output_dim=self.block_pca_dim
            )

            # Only one node => trivial graph
            features = [block_features_reduced.tolist()]
            a, b = [], []
            graph_data = self._build_graph(a, b, features)
        else:
            raise ValueError(f"Unsupported data type: {self.data['type']}")

        # Store for inference/embedding
        self._last_graph_data = graph_data
        self._last_data_dict = self.data

        # Initialize the model if not already
        if self.model is None:
            input_dim = graph_data.x.shape[1]
            self._initialize_model(input_dim)
        else:
            # If model exists, ensure input dimensions match
            if self.model.conv1.in_channels != graph_data.x.shape[1]:
                raise ValueError(
                    f"Model expects input dimension {self.model.conv1.in_channels}, "
                    f"but got {graph_data.x.shape[1]}."
                )

        self.model.train()

        for epoch in range(epochs):
            self.optimizer.zero_grad()
            node_embeddings = self.model(graph_data.x, graph_data.edge_index)
            loss = self.criterion(node_embeddings, graph_data.x)
            loss.backward()
            self.optimizer.step()

        self.model.eval()

    def to_embedding(self) -> BinlexVectorEmbedding | None:
        """
        After training on the data in the constructor, produce a graph-level embedding
        for that data. Returns a BinlexVectorEmbedding with the normalized embedding vector,
        or None if no training has occurred yet.
        """
        if self._last_graph_data is None or self._last_data_dict is None:
            return None

        node_embeddings = self._gnn_embedding(self._last_graph_data)

        # Global mean pool over all nodes to get a single embedding
        graph_embedding = global_mean_pool(
            node_embeddings,
            batch=zeros(node_embeddings.size(0), dtype=torch_long),
        )
        # L2 normalize
        norm_embedding = functional.normalize(graph_embedding, p=2, dim=1)

        return BinlexVectorEmbedding(
            vector=norm_embedding.squeeze().tolist(),
            data=self._last_data_dict,
        )
