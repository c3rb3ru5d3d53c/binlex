from __future__ import annotations

from binlex.config import Config
from binlex.controlflow import (
    BlockJsonDeserializer,
    FunctionJsonDeserializer,
    Graph,
    InstructionJsonDeserializer,
)
from binlex.core.architecture import Architecture, _coerce_architecture
from binlex.core.magic import Magic, _coerce_magic
from binlex.indexing import Collection
from binlex_bindings.binlex.clients import Server as _ServerBinding
from binlex_bindings.binlex.clients import AdminCommentsResponse as _AdminCommentsResponseBinding
from binlex_bindings.binlex.clients import AdminPasswordResetResponse as _AdminPasswordResetResponseBinding
from binlex_bindings.binlex.clients import AdminUserCreateResponse as _AdminUserCreateResponseBinding
from binlex_bindings.binlex.clients import AuthSession as _AuthSessionBinding
from binlex_bindings.binlex.clients import AuthUser as _AuthUserBinding
from binlex_bindings.binlex.clients import Captcha as _CaptchaBinding
from binlex_bindings.binlex.clients import CollectionTagSearchItem as _CollectionTagSearchItemBinding
from binlex_bindings.binlex.clients import CollectionTagSearchResponse as _CollectionTagSearchResponseBinding
from binlex_bindings.binlex.clients import CorporaCatalog as _CorporaCatalogBinding
from binlex_bindings.binlex.clients import CorporaResponse as _CorporaResponseBinding
from binlex_bindings.binlex.clients import EntityComment as _EntityCommentBinding
from binlex_bindings.binlex.clients import EntityCommentsResponse as _EntityCommentsResponseBinding
from binlex_bindings.binlex.clients import KeyRegenerateResponse as _KeyRegenerateResponseBinding
from binlex_bindings.binlex.clients import MetadataUser as _MetadataUserBinding
from binlex_bindings.binlex.clients import MetadataItem as _MetadataItemBinding
from binlex_bindings.binlex.clients import QueryResult as _QueryResultBinding
from binlex_bindings.binlex.clients import RecoveryCodesResponse as _RecoveryCodesResponseBinding
from binlex_bindings.binlex.clients import SearchDetail as _SearchDetailBinding
from binlex_bindings.binlex.clients import SearchResponse as _SearchResponseBinding
from binlex_bindings.binlex.clients import SearchRow as _SearchRowBinding
from binlex_bindings.binlex.clients import SearchResult as _SearchResultBinding
from binlex_bindings.binlex.clients import SymbolsCatalog as _SymbolsCatalogBinding
from binlex_bindings.binlex.clients import SymbolsResponse as _SymbolsResponseBinding
from binlex_bindings.binlex.clients import TagsCatalog as _TagsCatalogBinding
from binlex_bindings.binlex.clients import TagsResponse as _TagsResponseBinding
from binlex_bindings.binlex.clients import TwoFactorSetup as _TwoFactorSetupBinding
from binlex_bindings.binlex.clients import UploadResponse as _UploadResponseBinding
from binlex_bindings.binlex.clients import UploadStatusResponse as _UploadStatusResponseBinding
from binlex_bindings.binlex.clients import UsernameCheck as _UsernameCheckBinding
from binlex_bindings.binlex.clients import UsersListResponse as _UsersListResponseBinding
from binlex_bindings.binlex.clients import Web as _WebBinding

AdminCommentsResponse = _AdminCommentsResponseBinding
AdminPasswordResetResponse = _AdminPasswordResetResponseBinding
AdminUserCreateResponse = _AdminUserCreateResponseBinding
AuthSession = _AuthSessionBinding
AuthUser = _AuthUserBinding
Captcha = _CaptchaBinding
CollectionTagSearchItem = _CollectionTagSearchItemBinding
CollectionTagSearchResponse = _CollectionTagSearchResponseBinding
CorporaCatalog = _CorporaCatalogBinding
CorporaResponse = _CorporaResponseBinding
EntityComment = _EntityCommentBinding
EntityCommentsResponse = _EntityCommentsResponseBinding
KeyRegenerateResponse = _KeyRegenerateResponseBinding
MetadataUser = _MetadataUserBinding
MetadataItem = _MetadataItemBinding
RecoveryCodesResponse = _RecoveryCodesResponseBinding
SearchDetail = _SearchDetailBinding
SearchResponse = _SearchResponseBinding
SearchRow = _SearchRowBinding
SymbolsCatalog = _SymbolsCatalogBinding
SymbolsResponse = _SymbolsResponseBinding
TagsCatalog = _TagsCatalogBinding
TagsResponse = _TagsResponseBinding
TwoFactorSetup = _TwoFactorSetupBinding
UploadResponse = _UploadResponseBinding
UploadStatusResponse = _UploadStatusResponseBinding
UsernameCheck = _UsernameCheckBinding
UsersListResponse = _UsersListResponseBinding


class SearchResult:
    def __init__(self, binding):
        self._inner = binding

    def score(self):
        return self._inner.score()

    def sha256(self):
        return self._inner.sha256()

    def address(self):
        return self._inner.address()

    def size(self):
        return self._inner.size()

    def timestamp(self):
        return self._inner.timestamp()

    def symbol(self):
        return self._inner.symbol()

    def architecture(self):
        return self._inner.architecture()

    def embedding(self):
        return self._inner.embedding()

    def embeddings(self):
        return self._inner.embeddings()

    def collection(self):
        return self._inner.collection()

    def vector(self):
        return self._inner.vector()

    def json(self):
        return self._inner.json()

    def username(self):
        return self._inner.username()

    def cyclomatic_complexity(self):
        return self._inner.cyclomatic_complexity()

    def average_instructions_per_block(self):
        return self._inner.average_instructions_per_block()

    def instructions(self):
        return self._inner.instructions()

    def blocks(self):
        return self._inner.blocks()

    def markov(self):
        return self._inner.markov()

    def entropy(self):
        return self._inner.entropy()

    def contiguous(self):
        return self._inner.contiguous()

    def chromosome_entropy(self):
        return self._inner.chromosome_entropy()

    def corpora_count(self):
        return self._inner.corpora_count()

    def tag_count(self):
        return self._inner.tag_count()

    def comment_count(self):
        return self._inner.comment_count()

    def symbols(self, web, page=None, limit=None):
        return self._inner.symbols(web._inner, page, limit)

    def tags(self, web, page=None, limit=None):
        return self._inner.tags(web._inner, page, limit)

    def corpora(self, web, page=None, limit=None):
        return self._inner.corpora(web._inner, page, limit)

    def function(self, web):
        result = self._inner.function(web._inner)
        return None if result is None else FunctionJsonDeserializer._from_binding(result)

    def block(self, web):
        result = self._inner.block(web._inner)
        return None if result is None else BlockJsonDeserializer._from_binding(result)

    def instruction(self, web):
        result = self._inner.instruction(web._inner)
        return None if result is None else InstructionJsonDeserializer._from_binding(result)


class QueryResult:
    def __init__(self, binding):
        self._inner = binding

    def lhs(self):
        result = self._inner.lhs()
        return None if result is None else SearchResult(result)

    def rhs(self):
        result = self._inner.rhs()
        return None if result is None else SearchResult(result)

    def score(self):
        return self._inner.score()


class Server:
    def __init__(
        self,
        config: Config,
        url: str | None = None,
        verify: bool | None = None,
        compression: bool | None = None,
    ) -> None:
        self._inner = _ServerBinding(config, url, verify, compression)

    def url(self):
        return self._inner.url()

    def verify(self):
        return self._inner.verify()

    def compression(self):
        return self._inner.compression()

    def version(self):
        return self._inner.version()

    def health(self):
        return self._inner.health()

    def analyze_file(
        self,
        path: str,
        magic: Magic | None = None,
        architecture: Architecture | None = None,
    ) -> Graph:
        native_magic = None if magic is None else str(_coerce_magic(magic))
        native_architecture = (
            None if architecture is None else str(_coerce_architecture(architecture))
        )
        return Graph._from_binding(
            self._inner.analyze_file(path, native_magic, native_architecture)
        )

    def analyze_bytes(
        self,
        data: bytes,
        magic: Magic | None = None,
        architecture: Architecture | None = None,
    ) -> Graph:
        native_magic = None if magic is None else str(_coerce_magic(magic))
        native_architecture = (
            None if architecture is None else str(_coerce_architecture(architecture))
        )
        return Graph._from_binding(
            self._inner.analyze_bytes(data, native_magic, native_architecture)
        )

    def execute_processor(
        self,
        processor: str,
        binlex_version: str,
        requires: str,
        data,
    ):
        return self._inner.execute_processor(
            processor, binlex_version, requires, data
        )


class Web:
    def __init__(
        self,
        config: Config,
        url: str | None = None,
        verify: bool | None = None,
        api_key: str | None = None,
    ) -> None:
        self._inner = _WebBinding(config, url, verify, api_key)

    def url(self):
        return self._inner.url()

    def verify(self):
        return self._inner.verify()

    def api_key(self):
        return self._inner.api_key()

    def set_api_key(self, api_key: str | None) -> None:
        self._inner.set_api_key(api_key)

    def graph(self, sha256: str) -> Graph:
        return Graph._from_binding(self._inner.graph(sha256))

    def version(self):
        return self._inner.version()

    def upload_sample(
        self,
        data: bytes,
        filename: str | None = None,
        format: str | None = None,
        architecture: str | None = None,
        corpora: list[str] | None = None,
        tags: list[str] | None = None,
    ):
        return self._inner.upload_sample(
            data, filename, format, architecture, corpora, tags
        )

    def upload_status(self, sha256: str):
        return self._inner.upload_status(sha256)

    def index_graph(
        self,
        sha256: str,
        graph: Graph,
        collections: list[Collection] | None = None,
        corpora: list[str] | None = None,
    ) -> bool:
        return self._inner.index_graph(sha256, graph, collections, corpora)

    def index_function(
        self,
        sha256: str,
        function,
        corpora: list[str] | None = None,
    ) -> bool:
        return self._inner.index_function(sha256, function, corpora)

    def index_block(
        self,
        sha256: str,
        block,
        corpora: list[str] | None = None,
    ) -> bool:
        return self._inner.index_block(sha256, block, corpora)

    def index_instruction(
        self,
        sha256: str,
        instruction,
        corpora: list[str] | None = None,
    ) -> bool:
        return self._inner.index_instruction(sha256, instruction, corpora)

    def commit_index(self) -> bool:
        return self._inner.commit_index()

    def clear_index(self) -> bool:
        return self._inner.clear_index()

    def collection_tags(
        self,
        sha256: str,
        collection: Collection,
        address: int,
        page: int | None = None,
        limit: int | None = None,
    ):
        return self._inner.collection_tags(sha256, collection, address, page, limit)

    def search_response(
        self,
        query: str,
        top_k: int | None = None,
        page: int | None = None,
    ):
        return self._inner.search_response(query, top_k, page)

    def search_detail(
        self,
        sha256: str,
        collection: Collection,
        architecture: str,
        address: int,
        symbol: str | None = None,
    ):
        return self._inner.search_detail(
            sha256, collection, architecture, address, symbol
        )

    def search_tags(self, query: str, limit: int | None = None):
        return self._inner.search_tags(query, limit)

    def add_tag(self, tag: str) -> bool:
        return self._inner.add_tag(tag)

    def search_corpora(self, query: str):
        return self._inner.search_corpora(query)

    def add_corpus(self, corpus: str) -> bool:
        return self._inner.add_corpus(corpus)

    def add_collection_tag(
        self,
        sha256: str,
        collection: Collection,
        address: int,
        tag: str,
    ) -> bool:
        return self._inner.add_collection_tag(sha256, collection, address, tag)

    def remove_collection_tag(
        self,
        sha256: str,
        collection: Collection,
        address: int,
        tag: str,
    ) -> bool:
        return self._inner.remove_collection_tag(sha256, collection, address, tag)

    def replace_collection_tags(
        self,
        sha256: str,
        collection: Collection,
        address: int,
        tags: list[str],
    ) -> bool:
        return self._inner.replace_collection_tags(sha256, collection, address, tags)

    def collection_symbols(
        self,
        sha256: str,
        collection: Collection,
        architecture: str,
        address: int,
        page: int | None = None,
        limit: int | None = None,
    ):
        return self._inner.collection_symbols(
            sha256, collection, architecture, address, page, limit
        )

    def search_symbols(self, query: str, limit: int | None = None):
        return self._inner.search_symbols(query, limit)

    def add_symbol(self, symbol: str) -> bool:
        return self._inner.add_symbol(symbol)

    def add_collection_symbol(
        self,
        sha256: str,
        collection: Collection,
        architecture: str,
        address: int,
        symbol: str,
    ) -> bool:
        return self._inner.add_collection_symbol(
            sha256, collection, architecture, address, symbol
        )

    def remove_collection_symbol(
        self,
        sha256: str,
        collection: Collection,
        architecture: str,
        address: int,
        symbol: str,
    ) -> bool:
        return self._inner.remove_collection_symbol(
            sha256, collection, architecture, address, symbol
        )

    def replace_collection_symbols(
        self,
        sha256: str,
        collection: Collection,
        architecture: str,
        address: int,
        symbols: list[str],
    ) -> bool:
        return self._inner.replace_collection_symbols(
            sha256, collection, architecture, address, symbols
        )

    def collection_corpora(
        self,
        sha256: str,
        collection: Collection,
        architecture: str,
        address: int,
        page: int | None = None,
        limit: int | None = None,
    ):
        return self._inner.collection_corpora(
            sha256, collection, architecture, address, page, limit
        )

    def add_collection_corpus(
        self,
        sha256: str,
        collection: Collection,
        architecture: str,
        address: int,
        corpus: str,
    ) -> bool:
        return self._inner.add_collection_corpus(
            sha256, collection, architecture, address, corpus
        )

    def remove_collection_corpus(
        self,
        sha256: str,
        collection: Collection,
        architecture: str,
        address: int,
        corpus: str,
    ) -> bool:
        return self._inner.remove_collection_corpus(
            sha256, collection, architecture, address, corpus
        )

    def entity_comments(
        self,
        sha256: str,
        collection: Collection,
        address: int,
        page: int | None = None,
        page_size: int | None = None,
    ):
        return self._inner.entity_comments(
            sha256, collection, address, page, page_size
        )

    def add_entity_comment(
        self,
        sha256: str,
        collection: Collection,
        address: int,
        body: str,
    ):
        return self._inner.add_entity_comment(sha256, collection, address, body)

    def delete_entity_comment(self, id: int) -> bool:
        return self._inner.delete_entity_comment(id)

    def admin_comments(
        self,
        query: str = "",
        page: int | None = None,
        page_size: int | None = None,
    ):
        return self._inner.admin_comments(query, page, page_size)

    def render_yara(self, query: str, items) -> str:
        return self._inner.render_yara(query, items)

    def download_sample(self, sha256: str) -> bytes:
        return self._inner.download_sample(sha256)

    def download_samples(self, sha256: list[str]) -> bytes:
        return self._inner.download_samples(sha256)

    def download_json(
        self,
        corpus: str,
        sha256: str,
        collection: Collection,
        address: int,
    ):
        return self._inner.download_json(corpus, sha256, collection, address)

    def auth_bootstrap(
        self,
        username: str,
        password: str,
        password_confirm: str,
    ):
        return self._inner.auth_bootstrap(username, password, password_confirm)

    def auth_login(self, username: str, password: str):
        return self._inner.auth_login(username, password)

    def auth_login_two_factor(self, challenge_token: str, code: str):
        return self._inner.auth_login_two_factor(challenge_token, code)

    def auth_login_two_factor_setup(self, challenge_token: str):
        return self._inner.auth_login_two_factor_setup(challenge_token)

    def auth_login_two_factor_enable(self, challenge_token: str, code: str):
        return self._inner.auth_login_two_factor_enable(challenge_token, code)

    def auth_captcha(self):
        return self._inner.auth_captcha()

    def auth_register(
        self,
        username: str,
        password: str,
        password_confirm: str,
        captcha_id: str,
        captcha_answer: str,
    ):
        return self._inner.auth_register(
            username, password, password_confirm, captcha_id, captcha_answer
        )

    def auth_logout(self) -> bool:
        return self._inner.auth_logout()

    def auth_me(self):
        return self._inner.auth_me()

    def auth_username_check(self, username: str):
        return self._inner.auth_username_check(username)

    def auth_password_reset(
        self,
        username: str,
        recovery_code: str,
        new_password: str,
        password_confirm: str,
        captcha_id: str,
        captcha_answer: str,
    ) -> bool:
        return self._inner.auth_password_reset(
            username,
            recovery_code,
            new_password,
            password_confirm,
            captcha_id,
            captcha_answer,
        )

    def profile(self):
        return self._inner.profile()

    def profile_password(
        self,
        current_password: str,
        new_password: str,
        password_confirm: str,
    ) -> bool:
        return self._inner.profile_password(
            current_password, new_password, password_confirm
        )

    def profile_picture_upload(
        self,
        data: bytes,
        filename: str | None = None,
    ):
        return self._inner.profile_picture_upload(data, filename)

    def profile_picture_delete(self):
        return self._inner.profile_picture_delete()

    def profile_picture_get(self, username: str) -> bytes:
        return self._inner.profile_picture_get(username)

    def profile_key_regenerate(self):
        return self._inner.profile_key_regenerate()

    def profile_recovery_regenerate(self):
        return self._inner.profile_recovery_regenerate()

    def profile_two_factor_setup(self):
        return self._inner.profile_two_factor_setup()

    def profile_two_factor_enable(self, current_password: str, code: str):
        return self._inner.profile_two_factor_enable(current_password, code)

    def profile_two_factor_disable(self, current_password: str, code: str):
        return self._inner.profile_two_factor_disable(current_password, code)

    def profile_delete(self, password: str) -> bool:
        return self._inner.profile_delete(password)

    def admin_users(
        self,
        query: str = "",
        page: int | None = None,
        limit: int | None = None,
    ):
        return self._inner.admin_users(query, page, limit)

    def admin_user_create(
        self,
        username: str,
        password: str,
        password_confirm: str,
        role: str,
    ):
        return self._inner.admin_user_create(
            username, password, password_confirm, role
        )

    def admin_user_role(self, username: str, role: str):
        return self._inner.admin_user_role(username, role)

    def admin_user_enabled(self, username: str, enabled: bool):
        return self._inner.admin_user_enabled(username, enabled)

    def admin_user_password_reset(self, username: str):
        return self._inner.admin_user_password_reset(username)

    def admin_user_key_regenerate(self, username: str):
        return self._inner.admin_user_key_regenerate(username)

    def admin_user_delete(self, username: str) -> bool:
        return self._inner.admin_user_delete(username)

    def admin_user_picture_delete(self, username: str):
        return self._inner.admin_user_picture_delete(username)

    def admin_user_two_factor_require(self, username: str, required: bool):
        return self._inner.admin_user_two_factor_require(username, required)

    def admin_user_two_factor_disable(self, username: str):
        return self._inner.admin_user_two_factor_disable(username)

    def admin_user_two_factor_reset(self, username: str):
        return self._inner.admin_user_two_factor_reset(username)

    def admin_delete_corpus(self, corpus: str) -> bool:
        return self._inner.admin_delete_corpus(corpus)

    def admin_delete_tag(self, tag: str) -> bool:
        return self._inner.admin_delete_tag(tag)

    def admin_delete_symbol(self, symbol: str) -> bool:
        return self._inner.admin_delete_symbol(symbol)

    def search(self, query: str, top_k: int = 10, page: int = 1):
        return [QueryResult(item) for item in self._inner.search(query, top_k, page)]


__all__ = [
    "AdminCommentsResponse",
    "AdminPasswordResetResponse",
    "AdminUserCreateResponse",
    "AuthSession",
    "AuthUser",
    "Captcha",
    "CollectionTagSearchItem",
    "CollectionTagSearchResponse",
    "CorporaCatalog",
    "CorporaResponse",
    "EntityComment",
    "EntityCommentsResponse",
    "KeyRegenerateResponse",
    "MetadataUser",
    "MetadataItem",
    "QueryResult",
    "RecoveryCodesResponse",
    "SearchDetail",
    "SearchResponse",
    "SearchResult",
    "SearchRow",
    "Server",
    "SymbolsCatalog",
    "SymbolsResponse",
    "TagsCatalog",
    "TagsResponse",
    "TwoFactorSetup",
    "UploadResponse",
    "UploadStatusResponse",
    "UsernameCheck",
    "UsersListResponse",
    "Web",
]
