import json
import torch
import numpy as np
import lancedb
import pandas as pd
import pyarrow as pa
from torch_geometric.data import Data
from torch_geometric.nn import GCNConv, global_mean_pool
from dataclasses import dataclass
from pyarrow import schema, field
from torch.nn import CosineSimilarity
from torch_pca import PCA
from binlex import Config
from binlex.controlflow import FunctionJsonDeserializer

@dataclass
class FunctionVector:
    """
    Lightweight container for storing an N-dimensional vector embedding
    of a function along with the original function metadata.
    """
    vector: list[float]
    function: dict

    def to_pandas(self) -> pd.DataFrame:
        """
        Converts this FunctionVector to a single-row DataFrame.
        """
        return pd.DataFrame(
            {
                'vector': [self.vector],
                'function': [self.function],
            }
        )


class BinlexGNN(torch.nn.Module):
    """
    A simple GCN-based model for generating graph embeddings of functions.
    """

    def __init__(self, node_features_dim: int, hidden_dim: int, output_dim: int):
        """
        Args:
            node_features_dim (int): The dimension of the node features.
            hidden_dim (int): The dimension of the hidden GCN layer.
            output_dim (int): The dimension of the final GCN output.
        """
        super().__init__()
        self.conv1 = GCNConv(node_features_dim, hidden_dim)
        self.conv2 = GCNConv(hidden_dim, output_dim)

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        """
        Forward pass through the GNN.

        Args:
            x (torch.Tensor): Node feature tensor of shape [num_nodes, node_features_dim].
            edge_index (torch.Tensor): Graph edges of shape [2, num_edges].

        Returns:
            torch.Tensor: Output features for each node, shape [num_nodes, output_dim].
        """
        x = self.conv1(x, edge_index).relu()
        x = self.conv2(x, edge_index)
        return x


class BinlexVectorDB:
    """
    Provides a high-level interface for:
      - Extracting function embeddings from JSON via Binlex.
      - Storing the embeddings in a LanceDB database.
      - Performing vector similarity queries.
    """

    def __init__(
        self,
        db: str,
        config: Config,
        seed: int = 0,
        block_pca_dim: int = 16,
        gnn_hidden_dim: int = 32,
        gnn_output_dim: int = 16,
    ):
        """
        Initialize the BinlexVectorDB with user-defined dimensions.

        Args:
            db (str): Path or URI to the LanceDB instance.
            config (Config): Binlex Config object.
            seed (int, optional): Random seed for reproducibility. Defaults to 0.
            block_pca_dim (int, optional): Dimension to reduce each block's feature set via PCA. Defaults to 3.
            gnn_hidden_dim (int, optional): Dimension for the hidden layer of the GNN. Defaults to 4.
            gnn_output_dim (int, optional): Dimension for the GNN output layer. Defaults to 3.
        """
        torch.manual_seed(seed)
        self.config = config
        self.db = lancedb.connect(db)

        # User-defined dimensions
        self.block_pca_dim = block_pca_dim
        self.gnn_hidden_dim = gnn_hidden_dim
        self.gnn_output_dim = gnn_output_dim

    # -------------------------------------------------------------------------
    # Feature Extraction + Graph Construction
    # -------------------------------------------------------------------------

    @staticmethod
    def nibbles_to_histogram_vector(nibbles: list[int]) -> list[int]:
        """
        Convert a list of nibble values (0-15) into a histogram
        of length 16, then flatten into an array of (value, count) pairs.

        Args:
            nibbles (list[int]): List of nibble values from 0 to 15.

        Returns:
            list[int]: Flattened histogram of size 32 (16 pairs of (value, count)).
        """
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
        """
        Reshape a flat list of values into Nx3 shape, padding if necessary.

        Args:
            values (list[float]): A list of numeric values.

        Returns:
            np.ndarray: Reshaped array of shape (N, 3).
        """
        arr = np.array(values, dtype=float)
        if arr.size == 0:
            # In case we have no features, return an empty 0x3 array
            return arr.reshape(-1, 3)

        padding = (3 - (len(arr) % 3)) % 3
        if padding > 0:
            arr = np.pad(arr, (0, padding), constant_values=0.0)
        return arr.reshape(-1, 3)

    @staticmethod
    def pca_reduce(values: np.ndarray, output_dim: int) -> np.ndarray:
        """
        Perform a PCA transform to reduce the Nx3 array down to 'output_dim',
        then take the mean across rows to get a single vector of length 'output_dim'.

        If the number of rows is fewer than 'output_dim', we pad them to have
        at least 'output_dim' rows. If PCA fails for any reason, returns zeros.

        Args:
            values (np.ndarray): A NumPy array of shape (N, 3).
            output_dim (int): Number of PCA components to reduce to.

        Returns:
            np.ndarray: A 1D vector of length 'output_dim'.
        """
        if values.size == 0:
            return np.zeros(output_dim)

        values_torch = torch.tensor(values, dtype=torch.float32)
        # Ensure at least `output_dim` rows for PCA
        n_rows, _ = values_torch.shape
        if n_rows < output_dim:
            pad_rows = output_dim - n_rows
            values_torch = torch.nn.functional.pad(values_torch, (0, 0, 0, pad_rows), value=0.0)

        try:
            pca = PCA(n_components=output_dim)
            # shape => [N, output_dim]
            principal_components = pca.fit_transform(values_torch)
            # Average across rows => [output_dim]
            values = principal_components.mean(dim=0).detach().numpy()
        except Exception:
            # If PCA fails, fallback to zeros
            values = np.zeros(output_dim)

        return values

    def _extract_block_features(self, function: FunctionJsonDeserializer) -> tuple[list[int], list[int], list[list[float]]]:
        """
        Extract adjacency lists (a, b) and reduced PCA features for each block in a function.

        Returns:
            tuple of:
              - a (list[int]): list of "from" node indices
              - b (list[int]): list of "to" node indices
              - features (list[list[float]]): list of PCA-reduced block features
        """
        a, b = [], []
        features = []

        for block in function.blocks():
            # Basic stats about the block
            feature = [
                block.size(),
                block.entropy(),
                block.number_of_instructions(),
                block.conditional(),
                block.edges(),
                len(block.functions()),
            ]
            # Chromosome nibble histogram
            chromosome_feature_histogram = self.nibbles_to_histogram_vector(
                block.chromosome().feature()
            )
            feature.extend(chromosome_feature_histogram)

            # Convert to Nx3 array
            feature_nx3 = self.to_nx3_array(feature)
            # Then reduce to user-specified block_pca_dim
            feature_reduced = self.pca_reduce(feature_nx3, output_dim=self.block_pca_dim)
            features.append(feature_reduced.tolist())

            # Adjacency for each sub-block
            for address in block.blocks():
                a.append(block.address())
                b.append(address)

        return a, b, features

    def _build_graph(self, a: list[int], b: list[int], features: list[list[float]]) -> Data:
        """
        Build torch_geometric Data from adjacency lists and node features.

        Args:
            a (list[int]): "from" node indices
            b (list[int]): "to" node indices
            features (list[list[float]]): Node feature vectors

        Returns:
            Data: torch_geometric graph data object.
        """
        # Ensure edges do not exceed the number of nodes
        max_node_index = len(features) - 1
        a_clamped = [min(max_node_index, idx) for idx in a]
        b_clamped = [min(max_node_index, idx) for idx in b]

        node_features = torch.tensor(features, dtype=torch.float)
        edge_index = torch.tensor([a_clamped, b_clamped], dtype=torch.long)

        return Data(x=node_features, edge_index=edge_index)

    def _gnn_embedding(self, data: Data) -> list[float]:
        """
        Run the GNN on the input graph data and global-mean-pool for a single embedding.

        Args:
            data (Data): torch_geometric graph data with x and edge_index.

        Returns:
            list[float]: GNN output embedding of length gnn_output_dim.
        """
        # Build and run the GNN
        gnn = BinlexGNN(
            node_features_dim=data.x.shape[1],
            hidden_dim=self.gnn_hidden_dim,
            output_dim=self.gnn_output_dim,
        )
        node_embeddings = gnn(data.x, data.edge_index)

        # Mean pool => single vector
        graph_embedding = global_mean_pool(
            node_embeddings,
            batch=torch.zeros(node_embeddings.size(0), dtype=torch.long),
        )
        return graph_embedding.squeeze().tolist()

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    def create_function_vector(self, function: FunctionJsonDeserializer) -> FunctionVector:
        """
        Convert a FunctionJsonDeserializer object into a FunctionVector embedding.

        Steps:
            1) Extract block-level features and reduce them to 'block_pca_dim' via PCA.
            2) Build a graph (edges and nodes) for the function in torch_geometric Data.
            3) Generate node embeddings from a GCN, then take mean pool for the graph.

        Args:
            function (FunctionJsonDeserializer): The function-deserialization object.

        Returns:
            FunctionVector: The resulting embedding with function metadata.
        """
        a, b, features = self._extract_block_features(function)
        data = self._build_graph(a, b, features)
        vector = self._gnn_embedding(data)

        return FunctionVector(
            vector=vector,
            function=function.to_dict(),
        )

    def deserialize_json_file_functions(self, file_path: str) -> list[FunctionJsonDeserializer]:
        """
        Read a JSON file line-by-line, deserializing functions where 'type' = 'function'.

        Args:
            file_path (str): Path to the JSON file.

        Returns:
            list[FunctionJsonDeserializer]: List of deserialized function objects.
        """
        deserialized = []
        with open(file_path, "r") as f:
            for line in f:
                data = json.loads(line)
                if data.get("type") == "function":
                    deserialized.append(FunctionJsonDeserializer(line, self.config))
        return deserialized

    def insert_function_vector(
        self, function_vector: FunctionVector, table_name: str = 'functions'
    ) -> lancedb.table.Table:
        """
        Insert a FunctionVector into LanceDB, avoiding near-duplicate entries
        by comparing cosine similarity of the newly generated vector with
        the top-1 nearest neighbor in the table.

        Steps:
            1) Create the table if it doesn't exist.
            2) Search for the top-1 nearest neighbor (vector search).
            3) If there's a near-identical vector (same sha256 + similarity > threshold), skip.
            4) Otherwise, insert.

        Args:
            function_vector (FunctionVector): The vector + function metadata to insert.
            table_name (str, optional): Name of the target table. Defaults to 'functions'.

        Returns:
            lancedb.table.Table: The LanceDB table object that was created or updated.
        """
        # Convert the FunctionVector to a DataFrame, then to a dict
        record = function_vector.to_pandas().to_dict(orient="records")[0]
        # JSON-serialize the 'function' dict
        record["function"] = json.dumps(record["function"])

        # Extract sha256 from the function's attributes
        func_dict = json.loads(record["function"])
        sha256_hash = None
        attributes = func_dict.get('attributes', [])
        for attr in attributes:
            if attr.get('type') == 'file':
                sha256_hash = attr.get('sha256')
                break

        if not sha256_hash:
            raise ValueError("Missing 'sha256' in function attributes. Cannot insert.")

        record['sha256'] = sha256_hash

        # If the table doesn't exist, create it (with user-defined dimension for vectors)
        if table_name not in self.db.table_names():
            vec_dim = len(record['vector'])  # e.g. self.gnn_output_dim
            table_schema = schema([
                field("vector", lancedb.vector(vec_dim, pa.float32())),
                field("function", pa.string()),
                field("sha256", pa.utf8()),
            ])
            table = self.db.create_table(table_name, data=[record], schema=table_schema)
            return table

        # Otherwise, open the existing table
        table = self.db.open_table(table_name)

        # Top-1 nearest neighbor search
        top_match_df = table.search(record['vector']).limit(1).to_pandas()

        if not top_match_df.empty:
            new_vector = torch.tensor(record['vector'], dtype=torch.float32)
            cos = CosineSimilarity(dim=0)
            # Check only the top match
            existing_row = top_match_df.iloc[0]
            existing_vector = torch.tensor(existing_row['vector'], dtype=torch.float32)
            similarity = cos(new_vector, existing_vector).item()

            SIM_THRESHOLD = 0.9999
            # If near-identical vector is found for the same sha256
            if existing_row['sha256'] == sha256_hash and similarity >= SIM_THRESHOLD:
                print(
                    f"Skipping insertion. Found a near-identical vector (cos sim={similarity:.4f}) "
                    f"with the same sha256={sha256_hash}."
                )
                return table

        # If we didn't skip, insert the new record
        table.add([record])
        return table

    def query_vector(
    self,
    query_vector: list[float],
    table_name: str = 'functions',
    top_k: int = 3
    ) -> list[tuple[float, str]]:
        """
        Perform a vector search against a LanceDB table (using LanceDB's built-in
        similarity search), then calculate and return the cosine similarity in PyTorch.

        Args:
            query_vector (list[float]): The query embedding vector.
            table_name (str, optional): Name of the table to query. Defaults to 'functions'.
            top_k (int, optional): Number of nearest neighbors to return. Defaults to 3.

        Returns:
            list[tuple[float, str]]: List of (cosine_similarity, function_json_string).
        """
        if table_name not in self.db.table_names():
            raise ValueError(f"Table '{table_name}' does not exist in the database.")

        # 1) Use LanceDB’s vector search (table.search(...)) instead of reading all rows:
        table = self.db.open_table(table_name)
        top_match_df = (
            table.search(query_vector)
                .limit(top_k)
                .to_pandas()
        )

        # 2) Still compute PyTorch cosine similarity for each match:
        cos = CosineSimilarity(dim=0)
        query_tensor = torch.tensor(query_vector, dtype=torch.float32)

        results = []
        for _, row in top_match_df.iterrows():
            candidate_vec = torch.tensor(row['vector'], dtype=torch.float32)
            sim = cos(query_tensor, candidate_vec).item()
            if sim > 0.99: sim = 1.0
            # row['function'] is a JSON-serialized function
            results.append((sim, row['function']))

        return results
