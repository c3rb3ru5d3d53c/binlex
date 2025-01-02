#!/usr/bin/env python

import json
import torch
import random
from torch.nn import Module
from torch.nn import BatchNorm1d
from torch.nn import Dropout
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
import numpy as np
import pandas as pd
from torch_geometric.data import Data
from torch_geometric.nn import GCNConv, global_mean_pool
from dataclasses import dataclass
from torch.nn import CosineSimilarity
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
        self.conv1 = GCNConv(node_features_dim, hidden_dim)
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
        random.seed(seed)
        np.random.seed(seed)
        manual_seed(seed)
        self.data = data
        self.block_pca_dim = block_pca_dim
        self.gnn_hidden_dim = gnn_hidden_dim
        self.gnn_output_dim = gnn_output_dim

    @staticmethod
    def nibbles_to_histogram_vector(nibbles: list[int]) -> list[int]:
        histogram = [0] * 16
        for nibble in nibbles:
            if 0 <= nibble <= 15:
                histogram[nibble] += 1

        encoded_histogram = []
        for value, count in enumerate(histogram):
            encoded_histogram.extend([value, count])
        return encoded_histogram

    @staticmethod
    def to_nx3_array(values: list[float]) -> np.ndarray:
        arr = np.array(values, dtype=float)
        if arr.size == 0:
            return arr.reshape(-1, 3)
        padding = (3 - (len(arr) % 3)) % 3
        if padding > 0:
            arr = np.pad(arr, (0, padding), constant_values=0.0)
        return arr.reshape(-1, 3)

    @staticmethod
    def pca_reduce(values: np.ndarray, output_dim: int) -> np.ndarray:
        if values.size == 0:
            return np.zeros(output_dim)
        values_torch = tensor(values, dtype=float32)
        n_rows, _ = values_torch.shape
        if n_rows < output_dim:
            pad_rows = output_dim - n_rows
            values_torch = functional.pad(values_torch, (0, 0, 0, pad_rows), value=0.0)
        try:
            pca = PCA(n_components=output_dim)
            principal_components = pca.fit_transform(values_torch)
            values = principal_components.mean(dim=0).detach().numpy()
        except Exception:
            values = np.zeros(output_dim)
        return values

    def _extract_block_features(self, block: dict) -> list:
        features =  [
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

    def _extract_function_features(self, function: dict) -> tuple[list[int], list[int], list[list[float]]]:
        a, b = [], []
        features = []

        for block in function['blocks']:
            feature = self._extract_block_features(block)

            feature.append(function['average_instructions_per_block'])

            feature_nx3 = self.to_nx3_array(feature)
            feature_reduced = self.pca_reduce(feature_nx3, output_dim=self.block_pca_dim)
            features.append(feature_reduced.tolist())

            for address in block['blocks']:
                a.append(block['address'])
                b.append(address)

        return a, b, features

    def _build_graph(self, a: list[int], b: list[int], features: list[list[float]]) -> Data:
        max_node_index = len(features) - 1

        a_clamped = [min(max_node_index, idx) for idx in a]
        b_clamped = [min(max_node_index, idx) for idx in b]

        node_features = tensor(features, dtype=torch_float)

        edge_index = tensor([a_clamped, b_clamped], dtype=torch_long)

        edge_index_rev = stack((edge_index[1], edge_index[0]), dim=0)
        edge_index = cat([edge_index, edge_index_rev], dim=1).unique(dim=1)

        return Data(x=node_features, edge_index=edge_index)


    def _gnn_embedding(self, data: Data) -> list[float]:
        gnn = BinlexInnerGNN(
            node_features_dim=data.x.shape[1],
            hidden_dim=self.gnn_hidden_dim,
            output_dim=self.gnn_output_dim,
        )
        node_embeddings = gnn(data.x, data.edge_index)

        graph_embedding = global_mean_pool(
            node_embeddings,
            batch=zeros(node_embeddings.size(0), dtype=torch_long),
        )

        # Normalize embedding to unit length (L2 normalization)
        norm_embedding = functional.normalize(graph_embedding, p=2, dim=1)
        return norm_embedding.squeeze().tolist()

    def to_embedding(self) -> BinlexVectorEmbedding | None:
        if 'type' not in self.data: return None
        if self.data['type'] == 'function':
            a, b, features = self._extract_function_features(self.data)
            data = self._build_graph(a, b, features)
            vector = self._gnn_embedding(data)
            return BinlexVectorEmbedding(
                vector=vector,
                data=self.data,
            )
        return None
