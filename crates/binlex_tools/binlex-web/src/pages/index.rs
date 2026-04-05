use crate::assets::{SCRIPT, STYLES};
use crate::{PageData, build_search_response};
use askama::Template;

#[derive(Template)]
#[template(path = "pages/index.html")]
struct IndexTemplate<'a> {
    styles: &'a str,
    script: &'a str,
    bootstrap: String,
    server_status_badge: String,
    index_status_badge: String,
    database_status_badge: String,
    uploads_enabled: bool,
    uploaded_sha256: Option<&'a str>,
    corpora_options_json: String,
    architecture_options_json: String,
    collection_options_json: String,
    query_completion_specs_json: String,
    query: &'a str,
    top_k: usize,
    page: usize,
    upload_modal_html: String,
}

#[derive(Template)]
#[template(path = "pages/partials/status_badge.html")]
struct StatusBadgeTemplate<'a> {
    label: &'a str,
    value: &'a str,
    healthy: bool,
}

#[derive(Template)]
#[template(path = "pages/partials/upload_modal.html")]
struct UploadModalTemplate {
    format_select_html: String,
    has_corpus_picker: bool,
    architecture_select_html: String,
    corpus_picker_html: Option<String>,
    tag_picker_html: String,
}

#[derive(Template)]
#[template(path = "pages/partials/single_select.html")]
struct SingleSelectTemplate<'a> {
    name: &'a str,
    label: &'a str,
    selected: &'a str,
    options: &'a [String],
}

#[derive(Template)]
#[template(path = "pages/partials/upload_corpus_picker.html")]
struct UploadCorpusPickerTemplate {
    options_json: String,
    selected_json: String,
}

#[derive(Template)]
#[template(path = "pages/partials/upload_tag_picker.html")]
struct UploadTagPickerTemplate {
    options_json: String,
    selected_json: String,
}

pub(crate) fn render_page(data: &PageData) -> String {
    let template = IndexTemplate {
        styles: STYLES,
        script: SCRIPT,
        bootstrap: render_search_bootstrap(data),
        server_status_badge: status_badge(
            "Server",
            if data.status.server_ok {
                "connected"
            } else {
                "disconnected"
            },
            data.status.server_ok,
        ),
        index_status_badge: status_badge("Index", "local", data.status.index_ok),
        database_status_badge: status_badge("Database", "local", data.status.database_ok),
        uploads_enabled: data.uploads_enabled,
        uploaded_sha256: data.uploaded_sha256.as_deref(),
        corpora_options_json: serde_json::to_string(&data.corpora_options)
            .unwrap_or_else(|_| "[]".to_string()),
        architecture_options_json: serde_json::to_string(&data.architecture_options)
            .unwrap_or_else(|_| "[]".to_string()),
        collection_options_json: serde_json::to_string(&data.collection_options)
            .unwrap_or_else(|_| "[]".to_string()),
        query_completion_specs_json: serde_json::to_string(&data.query_completion_specs)
            .unwrap_or_else(|_| "[]".to_string()),
        query: &data.query,
        top_k: data.top_k,
        page: data.page,
        upload_modal_html: if data.uploads_enabled {
            render_upload_modal(data)
        } else {
            String::new()
        },
    };
    template.render().unwrap_or_else(|_| String::new())
}

fn render_search_bootstrap(data: &PageData) -> String {
    let value =
        serde_json::to_string(&build_search_response(data)).unwrap_or_else(|_| "{}".to_string());
    let escaped = value.replace('<', "\\u003c");
    format!("window.__BINLEX_SEARCH_DATA__ = {};", escaped)
}

fn render_upload_modal(data: &PageData) -> String {
    UploadModalTemplate {
        format_select_html: render_single_select_dropdown(
            "upload-format",
            "Format",
            &data.upload_format_options,
            "Auto",
        ),
        has_corpus_picker: !data.upload_corpora_locked,
        architecture_select_html: render_single_select_dropdown(
            "upload-architecture",
            "Architecture",
            &data.upload_architecture_options,
            "Auto",
        ),
        corpus_picker_html: if data.upload_corpora_locked {
            None
        } else {
            Some(render_upload_corpus_picker(
                &data.upload_corpus_options,
                &data.upload_selected_corpora,
            ))
        },
        tag_picker_html: render_upload_tag_picker(
            &data.upload_tag_options,
            &data.upload_selected_tags,
        ),
    }
    .render()
    .unwrap_or_else(|_| String::new())
}

fn render_single_select_dropdown(
    name: &str,
    label: &str,
    options: &[String],
    selected: &str,
) -> String {
    SingleSelectTemplate {
        name,
        label,
        selected,
        options,
    }
    .render()
    .unwrap_or_else(|_| String::new())
}

fn render_upload_corpus_picker(options: &[String], selected: &[String]) -> String {
    UploadCorpusPickerTemplate {
        options_json: serde_json::to_string(options).unwrap_or_else(|_| "[]".to_string()),
        selected_json: serde_json::to_string(selected).unwrap_or_else(|_| "[]".to_string()),
    }
    .render()
    .unwrap_or_else(|_| String::new())
}

fn render_upload_tag_picker(options: &[String], selected: &[String]) -> String {
    UploadTagPickerTemplate {
        options_json: serde_json::to_string(options).unwrap_or_else(|_| "[]".to_string()),
        selected_json: serde_json::to_string(selected).unwrap_or_else(|_| "[]".to_string()),
    }
    .render()
    .unwrap_or_else(|_| String::new())
}

fn status_badge(label: &str, value: &str, healthy: bool) -> String {
    StatusBadgeTemplate {
        label,
        value,
        healthy,
    }
    .render()
    .unwrap_or_else(|_| String::new())
}

pub(crate) fn display_architecture(value: &str) -> String {
    value.to_ascii_uppercase()
}
