use crate::PageData;
use crate::assets::{SCRIPT, STYLES};
use binlex::index::SearchResult;

pub(crate) fn render_page(data: &PageData) -> String {
    let mut html = String::new();
    html.push_str("<!doctype html><html><head><meta charset=\"utf-8\">");
    html.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
    html.push_str("<title>Binlex Web</title><style>");
    html.push_str(STYLES);
    html.push_str("</style></head><body><main class=\"page\">");
    html.push_str("<header class=\"header\"><h1>Binlex Web</h1><div class=\"status-row\">");
    html.push_str("<div class=\"theme-toggle\" role=\"group\" aria-label=\"Theme\"><button type=\"button\" class=\"theme-button active\" id=\"theme-dark\" onclick=\"setTheme('dark')\" aria-label=\"Dark mode\">🌙</button><button type=\"button\" class=\"theme-button\" id=\"theme-light\" onclick=\"setTheme('light')\" aria-label=\"Light mode\">☀️</button></div>");
    html.push_str(&status_badge(
        "server",
        if data.status.server_ok {
            "connected"
        } else {
            "disconnected"
        },
        data.status.server_ok,
    ));
    html.push_str(&status_badge("index", "local", data.status.index_ok));
    html.push_str("</div></header>");

    if let Some(message) = &data.message {
        html.push_str(&render_notice("success", message));
    }
    if let Some(error) = &data.error {
        html.push_str(&render_notice("error", error));
    }

    html.push_str("<section class=\"controls\">");
    html.push_str("<div class=\"action-row\">");
    if data.uploads_enabled {
        html.push_str("<form method=\"post\" action=\"/upload\" enctype=\"multipart/form-data\" class=\"upload-form\" id=\"upload-form\">");
        html.push_str(
            "<input id=\"upload-input\" type=\"file\" name=\"file\" class=\"hidden-file\">",
        );
        html.push_str("<input id=\"upload-format\" type=\"hidden\" name=\"format\" value=\"\">");
        html.push_str("<input id=\"upload-architecture-override\" type=\"hidden\" name=\"architecture_override\" value=\"\">");
        html.push_str(&format!(
            "<input type=\"hidden\" name=\"query\" value=\"{}\">",
            escape_html(&data.query)
        ));
        html.push_str(&format!(
            "<input type=\"hidden\" name=\"top_k\" value=\"{}\">",
            data.top_k
        ));
        html.push_str(&format!(
            "<input type=\"hidden\" name=\"page\" value=\"{}\">",
            data.page
        ));
        if let Some(sha256) = &data.uploaded_sha256 {
            html.push_str(&format!(
                "<input type=\"hidden\" name=\"uploaded_sha256\" value=\"{}\">",
                escape_html(sha256)
            ));
        }
        html.push_str("<button class=\"secondary upload-button\" type=\"button\" onclick=\"openUploadModal()\">Upload</button>");
        html.push_str("</form>");
    }
    html.push_str(&format!(
        "<form method=\"post\" action=\"/search\" class=\"search-form\" id=\"search-form\" onsubmit=\"syncSearchState()\" data-corpora='{}' data-architectures='{}' data-collections='{}' data-query-completions='{}'>",
        escape_html(&serde_json::to_string(&data.corpora_options).unwrap_or_else(|_| "[]".to_string())),
        escape_html(&serde_json::to_string(&data.architecture_options).unwrap_or_else(|_| "[]".to_string())),
        escape_html(&serde_json::to_string(&data.collection_options).unwrap_or_else(|_| "[]".to_string())),
        escape_html(&serde_json::to_string(&data.query_completion_specs).unwrap_or_else(|_| "[]".to_string()))
    ));
    html.push_str("<input type=\"hidden\" name=\"search\" value=\"1\">");
    if let Some(sha256) = &data.uploaded_sha256 {
        html.push_str(&format!(
            "<input type=\"hidden\" name=\"uploaded_sha256\" value=\"{}\">",
            escape_html(sha256)
        ));
    }
    html.push_str("<div class=\"search-stack\">");
    html.push_str("<div class=\"search-row\">");
    html.push_str(&format!(
        "<input type=\"hidden\" name=\"top_k\" id=\"top-k-input\" value=\"{}\">",
        data.top_k
    ));
    html.push_str(&format!(
        "<input type=\"hidden\" name=\"page\" id=\"page-input\" value=\"{}\">",
        data.page
    ));
    html.push_str("<div class=\"query-input-stack\">");
    html.push_str(&format!(
        "<input class=\"search-input\" id=\"query-input\" type=\"text\" name=\"query\" value=\"{}\" placeholder=\"Search\" autocomplete=\"off\" oninput=\"updateQueryAssistant()\" onfocus=\"scheduleQueryAssistantUpdate()\" onmouseup=\"scheduleQueryAssistantUpdate()\" onkeyup=\"handleQueryInputKeyup(event)\" onkeydown=\"handleQueryInputKeydown(event)\">",
        escape_html(&data.query)
    ));
    html.push_str("<div class=\"query-assistant\" id=\"query-assistant\" hidden>");
    html.push_str("</div></div>");
    html.push_str(&format!(
        "<div class=\"top-k-control\"><button type=\"button\" class=\"secondary top-k-trigger\" id=\"top-k-trigger\" onclick=\"toggleTopKPopover()\">Top K: <span id=\"top-k-label\">{}</span></button><div class=\"top-k-popover\" id=\"top-k-popover\" hidden><div class=\"top-k-slider-wrap\"><span class=\"top-k-tick top\">64</span><input type=\"range\" min=\"1\" max=\"64\" value=\"{}\" id=\"top-k-slider\" class=\"top-k-slider\" orient=\"vertical\" oninput=\"updateTopKValue(this.value)\"><span class=\"top-k-tick bottom\">1</span></div></div></div>",
        data.top_k,
        data.top_k
    ));
    html.push_str("<button class=\"primary\" type=\"submit\">Search</button>");
    html.push_str("</div></div></form></div></section>");

    html.push_str("<section class=\"results\"><table><thead><tr>");
    for header in [
        "Date (UTC)",
        "size",
        "score",
        "embeddings",
        "embedding",
        "corpus",
        "architecture",
        "sha256",
        "collection",
        "address",
        "symbol",
        "action",
    ] {
        let class = if header == "action" {
            " class=\"action-cell\""
        } else {
            ""
        };
        if header == "action" {
            html.push_str(&format!(
                "<th{}>{}</th>",
                class,
                render_global_results_actions(data)
            ));
        } else {
            html.push_str(&format!("<th{}>{}</th>", class, escape_html(header)));
        }
    }
    html.push_str("</tr></thead><tbody>");

    if data.results.is_empty() {
        html.push_str("<tr><td colspan=\"12\" class=\"empty\">No results yet.</td></tr>");
    } else {
        for result in &data.results {
            html.push_str("<tr>");
            html.push_str(&format!(
                "<td title=\"{}\">{}</td>",
                escape_html(&result.date().to_rfc3339()),
                escape_html(&format_result_date(result))
            ));
            html.push_str(&format!(
                "<td title=\"{} bytes\">{}</td>",
                result.size(),
                escape_html(&format_result_size(result.size()))
            ));
            html.push_str(&format!("<td>{:.4}</td>", result.score()));
            html.push_str(&format!(
                "<td title=\"{}\">{}</td>",
                result.embeddings(),
                compact_count(result.embeddings())
            ));
            html.push_str(&format!(
                "<td><code title=\"{}\">{}</code></td>",
                escape_html(result.embedding()),
                escape_html(&abbreviate_hex(result.embedding()))
            ));
            html.push_str(&format!("<td>{}</td>", escape_html(result.corpus())));
            html.push_str(&format!(
                "<td>{}</td>",
                escape_html(&display_architecture(result.architecture()))
            ));
            html.push_str(&format!(
                "<td class=\"sha256-cell\"><code title=\"{}\">{}</code></td>",
                escape_html(result.sha256()),
                escape_html(&abbreviate_hex(result.sha256()))
            ));
            html.push_str(&format!(
                "<td>{}</td>",
                escape_html(&display_collection(result.collection().as_str()))
            ));
            html.push_str(&format!("<td>{:#x}</td>", result.address()));
            html.push_str(&format!(
                "<td>{}</td>",
                escape_html(result.symbol().unwrap_or("-"))
            ));
            html.push_str(&format!(
                "<td class=\"action-cell\">{}</td>",
                render_result_actions(result, data.sample_downloads_enabled)
            ));
            html.push_str("</tr>");
        }
    }
    html.push_str("</tbody></table>");
    html.push_str(&render_pagination(data));
    html.push_str("</section>");
    if data.uploads_enabled {
        html.push_str(&render_upload_modal(data));
    }
    html.push_str("<div id=\"row-action-popover\" class=\"row-actions-popover\" hidden data-actions=\"[]\" data-path=\"\"><div class=\"row-actions-header\"><button type=\"button\" class=\"secondary row-actions-back\" onclick=\"navigateRowActions(this)\" hidden>Back</button><div class=\"row-actions-breadcrumb\">Action</div></div><input class=\"menu-search\" type=\"text\" placeholder=\"Search action\" oninput=\"renderRowActionMenu(this.closest('.row-actions-popover'))\"><div class=\"row-action-options\"></div></div>");
    html.push_str("<script>");
    html.push_str(SCRIPT);
    html.push_str("</script></main></body></html>");
    html
}

fn render_notice(kind: &str, message: &str) -> String {
    format!(
        "<div class=\"notice {}\"><span>{}</span><button type=\"button\" class=\"notice-dismiss\" onclick=\"dismissNotice(this)\">Close</button></div>",
        escape_html(kind),
        escape_html(message)
    )
}

fn render_result_actions(result: &SearchResult, sample_downloads_enabled: bool) -> String {
    let actions = build_result_action_tree(result, sample_downloads_enabled);
    if actions.is_empty() {
        return "-".to_string();
    }
    format!(
        "<button type=\"button\" class=\"row-actions-trigger\" data-actions=\"{}\" onclick=\"toggleRowActionMenu(this)\">Action</button>",
        escape_html(&serde_json::to_string(&actions).unwrap_or_else(|_| "[]".to_string()))
    )
}

fn render_global_results_actions(data: &PageData) -> String {
    let actions = build_global_results_action_tree(&data.results, data.sample_downloads_enabled);
    if actions.is_empty() {
        return "ACTION".to_string();
    }
    format!(
        "<button type=\"button\" class=\"row-actions-trigger global-actions-trigger\" data-actions=\"{}\" onclick=\"toggleRowActionMenu(this)\">ACTION</button>",
        escape_html(&serde_json::to_string(&actions).unwrap_or_else(|_| "[]".to_string()))
    )
}

fn render_pagination(data: &PageData) -> String {
    if !data.has_previous_page && !data.has_next_page {
        return String::new();
    }
    let mut html = String::new();
    html.push_str("<div class=\"pagination\">");
    if data.has_previous_page {
        html.push_str(&render_pagination_button(
            "←",
            data.page.saturating_sub(1),
            data,
        ));
    } else {
        html.push_str("<span class=\"pagination-spacer\" aria-hidden=\"true\"></span>");
    }
    html.push_str(&format!(
        "<span class=\"pagination-label\">Page {}</span>",
        data.page
    ));
    if data.has_next_page {
        html.push_str(&render_pagination_button("→", data.page + 1, data));
    } else {
        html.push_str("<span class=\"pagination-spacer\" aria-hidden=\"true\"></span>");
    }
    html.push_str("</div>");
    html
}

fn render_pagination_button(label: &str, page: usize, data: &PageData) -> String {
    let mut html = String::new();
    html.push_str("<form method=\"post\" action=\"/search\" class=\"pagination-form\">");
    html.push_str("<input type=\"hidden\" name=\"search\" value=\"1\">");
    html.push_str(&format!(
        "<input type=\"hidden\" name=\"query\" value=\"{}\">",
        escape_html(&data.query)
    ));
    html.push_str(&format!(
        "<input type=\"hidden\" name=\"top_k\" value=\"{}\">",
        data.top_k
    ));
    html.push_str(&format!(
        "<input type=\"hidden\" name=\"page\" value=\"{}\">",
        page
    ));
    if let Some(sha256) = &data.uploaded_sha256 {
        html.push_str(&format!(
            "<input type=\"hidden\" name=\"uploaded_sha256\" value=\"{}\">",
            escape_html(sha256)
        ));
    }
    html.push_str(&format!(
        "<button type=\"submit\" class=\"secondary pagination-button\" aria-label=\"Page {}\">{}</button>",
        page,
        escape_html(label)
    ));
    html.push_str("</form>");
    html
}

fn format_result_date(result: &SearchResult) -> String {
    result.date().format("%Y-%m-%d %H:%M").to_string()
}

fn format_result_size(value: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = 1024.0 * 1024.0;
    const GB: f64 = 1024.0 * 1024.0 * 1024.0;
    let value_f = value as f64;
    if value_f >= GB {
        return format_compact_bytes(value_f / GB, "GB");
    }
    if value_f >= MB {
        return format_compact_bytes(value_f / MB, "MB");
    }
    if value_f >= KB {
        return format_compact_bytes(value_f / KB, "KB");
    }
    format!("{} B", value)
}

fn format_compact_bytes(value: f64, suffix: &str) -> String {
    let rounded = (value * 10.0).round() / 10.0;
    if rounded.fract().abs() < f64::EPSILON {
        format!("{} {}", rounded as u64, suffix)
    } else {
        format!("{rounded:.1} {suffix}")
    }
}

fn build_result_action_tree(
    result: &SearchResult,
    sample_downloads_enabled: bool,
) -> Vec<serde_json::Value> {
    let mut copy_children = Vec::<serde_json::Value>::new();
    let mut search_children = Vec::<serde_json::Value>::new();
    let mut root = Vec::<serde_json::Value>::new();

    if let Some(json) = result.json() {
        copy_children.push(action_leaf(
            "JSON",
            serde_json::to_string(json).unwrap_or_else(|_| "null".to_string()),
        ));
    }
    if !result.vector().is_empty() {
        copy_children.push(action_leaf(
            "Vector",
            serde_json::to_string(result.vector()).unwrap_or_else(|_| "[]".to_string()),
        ));
    }
    copy_children.push(action_leaf("Score", format!("{:.4}", result.score())));
    copy_children.push(action_leaf("Embeddings", result.embeddings().to_string()));
    copy_children.push(action_leaf("Size", result.size().to_string()));
    copy_children.push(action_leaf("Address", format!("{:#x}", result.address())));
    copy_children.push(action_leaf("Date", result.date().to_rfc3339()));
    copy_children.push(action_leaf("SHA256", result.sha256().to_string()));
    copy_children.push(action_leaf("Embedding", result.embedding().to_string()));
    copy_children.push(action_leaf("Corpus", result.corpus().to_string()));
    copy_children.push(action_leaf(
        "Architecture",
        result.architecture().to_string(),
    ));
    if let Some(symbol) = result.symbol().filter(|symbol| *symbol != "-") {
        copy_children.push(action_leaf("Symbol", symbol.to_string()));
    }

    if let Some(chromosome) = result.json().and_then(|json| json.get("chromosome")) {
        let mut chromosome_children = Vec::<serde_json::Value>::new();
        if let Some(pattern) = chromosome
            .get("pattern")
            .and_then(serde_json::Value::as_str)
        {
            chromosome_children.push(action_leaf("Pattern", pattern.to_string()));
        }
        if let Some(minhash) = chromosome
            .get("minhash")
            .and_then(serde_json::Value::as_str)
        {
            chromosome_children.push(action_leaf("Minhash", minhash.to_string()));
        }
        if let Some(tlsh) = chromosome.get("tlsh").and_then(serde_json::Value::as_str) {
            chromosome_children.push(action_leaf("TLSH", tlsh.to_string()));
        }
        if let Some(sha256) = chromosome.get("sha256").and_then(serde_json::Value::as_str) {
            chromosome_children.push(action_leaf("SHA256", sha256.to_string()));
        }
        if !chromosome_children.is_empty() {
            copy_children.push(action_branch("Chromosome", chromosome_children));
        }
    }

    if !copy_children.is_empty() {
        root.push(action_branch("Copy", copy_children));
    }

    search_children.push(action_navigate(
        "Embedding",
        format!(
            "/?search=1&query={}",
            url_encode(&format!(
                "embedding:{} AND collection:{} AND architecture:{}",
                result.embedding(),
                result.collection().as_str(),
                result.architecture()
            ))
        ),
    ));
    search_children.push(action_navigate(
        "SHA256",
        format!(
            "/?search=1&query={}",
            url_encode(&format!(
                "sha256:{} AND collection:{} AND architecture:{}",
                result.sha256(),
                result.collection().as_str(),
                result.architecture()
            ))
        ),
    ));
    search_children.push(action_navigate(
        "Vector",
        format!(
            "/?search=1&query={}",
            url_encode(&format!(
                "vector:{} AND collection:{} AND architecture:{}",
                serde_json::to_string(result.vector()).unwrap_or_else(|_| "[]".to_string()),
                result.collection().as_str(),
                result.architecture()
            ))
        ),
    ));
    root.push(action_branch("Search", search_children));

    let mut download_children = Vec::<serde_json::Value>::new();
    if sample_downloads_enabled {
        download_children.push(action_download(
            "Sample",
            format!("/download/sample?sha256={}", url_encode(result.sha256())),
        ));
    }
    if result.json().is_some() {
        download_children.push(action_download(
            "JSON",
            format!(
                "/download/json?corpus={}&sha256={}&collection={}&address={}",
                url_encode(result.corpus()),
                url_encode(result.sha256()),
                url_encode(result.collection().as_str()),
                result.address()
            ),
        ));
    }
    if !download_children.is_empty() {
        root.push(action_branch("Download", download_children));
    }

    root
}

fn build_global_results_action_tree(
    results: &[SearchResult],
    sample_downloads_enabled: bool,
) -> Vec<serde_json::Value> {
    if results.is_empty() {
        return Vec::new();
    }

    let csv = render_results_csv(results);
    let json = serde_json::to_string_pretty(results).unwrap_or_else(|_| "[]".to_string());
    let sha256 = unique_result_values(
        &results
            .iter()
            .map(|result| result.sha256().to_string())
            .collect::<Vec<_>>(),
    )
    .join("\n");
    let embedding = unique_result_values(
        &results
            .iter()
            .map(|result| result.embedding().to_string())
            .collect::<Vec<_>>(),
    )
    .join("\n");
    let sample_hashes = results
        .iter()
        .map(|result| result.sha256().to_string())
        .collect::<Vec<_>>();

    let mut root = Vec::<serde_json::Value>::new();
    root.push(action_branch(
        "Copy",
        vec![
            action_copy("CSV", csv.clone()),
            action_copy("JSON", json.clone()),
            action_copy("SHA256", sha256),
            action_copy("Embedding", embedding),
        ],
    ));

    let mut download_children = vec![
        action_download_payload("CSV", "results.csv", "text/csv;charset=utf-8", csv),
        action_download_payload(
            "JSON",
            "results.json",
            "application/json",
            json,
        ),
    ];
    if sample_downloads_enabled {
        let mut query = String::new();
        for hash in unique_result_values(&sample_hashes) {
            if !query.is_empty() {
                query.push('&');
            }
            query.push_str("sha256=");
            query.push_str(&url_encode(&hash));
        }
        download_children.push(action_download(
            "Samples",
            format!("/download/samples?{}", query),
        ));
    }
    root.push(action_branch("Download", download_children));
    root
}

fn action_leaf(label: &str, payload: String) -> serde_json::Value {
    serde_json::json!({
        "label": label,
        "payload": payload,
    })
}

fn action_copy(label: &str, payload: String) -> serde_json::Value {
    serde_json::json!({
        "label": label,
        "action": "copy",
        "payload": payload,
    })
}

fn action_branch(label: &str, children: Vec<serde_json::Value>) -> serde_json::Value {
    serde_json::json!({
        "label": label,
        "children": children,
    })
}

fn action_download(label: &str, url: String) -> serde_json::Value {
    serde_json::json!({
        "label": label,
        "action": "download",
        "url": url,
    })
}

fn action_download_payload(
    label: &str,
    filename: &str,
    content_type: &str,
    payload: String,
) -> serde_json::Value {
    serde_json::json!({
        "label": label,
        "action": "download_text",
        "filename": filename,
        "content_type": content_type,
        "payload": payload,
    })
}

fn action_navigate(label: &str, url: String) -> serde_json::Value {
    serde_json::json!({
        "label": label,
        "action": "navigate",
        "url": url,
    })
}

fn render_results_csv(results: &[SearchResult]) -> String {
    let mut rows = Vec::with_capacity(results.len() + 1);
    rows.push(
        [
            "date",
            "size",
            "score",
            "embeddings",
            "embedding",
            "corpus",
            "architecture",
            "sha256",
            "collection",
            "address",
            "symbol",
        ]
        .join(","),
    );
    for result in results {
        rows.push(
            [
                csv_cell(&result.date().to_rfc3339()),
                csv_cell(&format!("{:.4}", result.score())),
                csv_cell(&result.size().to_string()),
                csv_cell(&result.embeddings().to_string()),
                csv_cell(result.embedding()),
                csv_cell(result.corpus()),
                csv_cell(result.architecture()),
                csv_cell(result.sha256()),
                csv_cell(result.collection().as_str()),
                csv_cell(&format!("{:#x}", result.address())),
                csv_cell(result.symbol().unwrap_or("")),
            ]
            .join(","),
        );
    }
    rows.join("\n")
}

fn csv_cell(value: &str) -> String {
    let escaped = value.replace('"', "\"\"");
    format!("\"{}\"", escaped)
}

fn unique_result_values(values: &[String]) -> Vec<String> {
    let mut unique = std::collections::BTreeSet::new();
    for value in values {
        unique.insert(value.clone());
    }
    unique.into_iter().collect()
}

fn render_upload_modal(data: &PageData) -> String {
    let mut html = String::new();
    html.push_str("<div id=\"upload-modal\" class=\"modal-backdrop\" hidden>");
    html.push_str(
        "<div class=\"modal-card\" role=\"dialog\" aria-modal=\"true\" aria-label=\"Upload\">",
    );
    html.push_str("<div class=\"modal-grid modal-grid-single\">");
    html.push_str("<div class=\"modal-field modal-file-field\">");
    html.push_str("<input id=\"upload-file-picker\" type=\"file\" class=\"hidden-file\">");
    html.push_str(
        "<label for=\"upload-file-picker\" id=\"upload-dropzone\" class=\"upload-dropzone\">",
    );
    html.push_str("<strong>Click to Upload or Drag and Drop</strong>");
    html.push_str("<em id=\"upload-file-name\">No file selected</em>");
    html.push_str("</label>");
    html.push_str("</div>");
    html.push_str("<div class=\"modal-select-row\">");
    html.push_str(&render_single_select_dropdown(
        "upload-format",
        "Format",
        &data.upload_format_options,
        "Auto",
    ));
    html.push_str(&render_single_select_dropdown(
        "upload-architecture",
        "Architecture",
        &data.upload_architecture_options,
        "Auto",
    ));
    html.push_str("</div>");
    html.push_str("</div>");
    html.push_str("<p id=\"upload-modal-tip\" class=\"modal-tip\"></p>");
    html.push_str("<div class=\"modal-actions\">");
    html.push_str("<button type=\"button\" class=\"secondary\" onclick=\"closeUploadModal()\">Cancel</button>");
    html.push_str("<button type=\"button\" class=\"primary\" id=\"upload-submit\" onclick=\"submitUploadModal()\">Upload</button>");
    html.push_str("</div></div></div>");
    html.push_str("<div id=\"upload-status-modal\" class=\"modal-backdrop\" hidden>");
    html.push_str(
        "<div class=\"modal-card upload-status-card\" role=\"dialog\" aria-modal=\"true\" aria-label=\"Upload Status\">",
    );
    html.push_str("<div class=\"upload-status-body\">");
    html.push_str("<div id=\"upload-status-icon\" class=\"upload-status-icon uploading\"><div class=\"upload-status-spinner\"></div><div class=\"upload-status-checkmark\">&#10003;</div><div class=\"upload-status-fail\">!</div></div>");
    html.push_str("<h2 id=\"upload-status-title\">Uploading Sample</h2>");
    html.push_str("<p id=\"upload-status-text\" class=\"modal-tip\">Binlex Web is uploading and processing the sample.</p>");
    html.push_str("<div id=\"upload-status-extra\"></div>");
    html.push_str("</div><div class=\"modal-actions\">");
    html.push_str("<button type=\"button\" class=\"secondary\" id=\"upload-status-close\" onclick=\"closeUploadStatusModal()\" hidden>Close</button>");
    html.push_str("</div></div></div>");
    html
}

fn render_single_select_dropdown(
    name: &str,
    label: &str,
    options: &[String],
    selected: &str,
) -> String {
    let mut html = format!(
        "<details class=\"multiselect modal-select\" data-single-select=\"{}\"><summary>{}: {}</summary><div class=\"menu\">",
        escape_html(name),
        escape_html(label),
        escape_html(selected)
    );
    html.push_str(&format!(
        "<input class=\"menu-search\" type=\"text\" placeholder=\"Search {}\" oninput=\"filterSingleOptions(this, '{}')\">",
        escape_html(label),
        escape_html(name)
    ));
    html.push_str("<div class=\"menu-options\">");
    for option in options {
        let checked = if option == selected { " checked" } else { "" };
        html.push_str(&format!(
            "<label class=\"menu-option\" data-single-group=\"{}\" data-option=\"{}\"><input type=\"radio\" name=\"{}\" value=\"{}\"{} onchange=\"selectSingleOption('{}', this.value)\"> <span>{}</span></label>",
            escape_html(name),
            escape_html(option),
            escape_html(name),
            escape_html(option),
            checked,
            escape_html(name),
            escape_html(option)
        ));
    }
    html.push_str("</div></div></details>");
    html
}

fn status_badge(label: &str, value: &str, healthy: bool) -> String {
    format!(
        "<span class=\"status\"><span class=\"dot {}\"></span>{}: {}</span>",
        if healthy { "ok" } else { "fail" },
        escape_html(label),
        escape_html(value)
    )
}

fn url_encode(value: &str) -> String {
    serde_urlencoded::to_string([("v", value)])
        .unwrap_or_else(|_| format!("v={}", value))
        .trim_start_matches("v=")
        .to_string()
}

pub(crate) fn display_architecture(value: &str) -> String {
    value.to_ascii_uppercase()
}

pub(crate) fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn display_collection(value: &str) -> String {
    let mut chars = value.chars();
    match chars.next() {
        Some(first) => {
            first.to_uppercase().collect::<String>() + &chars.as_str().to_ascii_lowercase()
        }
        None => String::new(),
    }
}

fn abbreviate_hex(value: &str) -> String {
    const EDGE: usize = 4;
    if value.len() <= EDGE * 2 + 3 {
        return value.to_string();
    }
    format!("{}...{}", &value[..EDGE], &value[value.len() - EDGE..])
}

fn compact_count(value: u64) -> String {
    const THOUSAND: u64 = 1_000;
    const MILLION: u64 = 1_000_000;
    const BILLION: u64 = 1_000_000_000;
    if value < THOUSAND {
        return value.to_string();
    }
    if value < MILLION {
        return compact_count_with_suffix(value, THOUSAND, "k");
    }
    if value < BILLION {
        return compact_count_with_suffix(value, MILLION, "m");
    }
    compact_count_with_suffix(value, BILLION, "b")
}

fn compact_count_with_suffix(value: u64, unit: u64, suffix: &str) -> String {
    let scaled = value as f64 / unit as f64;
    if scaled < 10.0 {
        let rounded = (scaled * 10.0).round() / 10.0;
        if rounded.fract().abs() < f64::EPSILON {
            format!("{}{}", rounded as u64, suffix)
        } else {
            format!("{rounded:.1}{suffix}")
        }
    } else {
        format!("{}{suffix}", scaled.round() as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_count_formats_large_values() {
        assert_eq!(compact_count(999), "999");
        assert_eq!(compact_count(1_000), "1k");
        assert_eq!(compact_count(1_532), "1.5k");
        assert_eq!(compact_count(12_000_000), "12m");
        assert_eq!(compact_count(1_500_000_000), "1.5b");
    }

    #[test]
    fn format_result_size_uses_compact_units() {
        assert_eq!(format_result_size(17), "17 B");
        assert_eq!(format_result_size(1024), "1 KB");
        assert_eq!(format_result_size(1536), "1.5 KB");
        assert_eq!(format_result_size(1024 * 1024), "1 MB");
    }

    #[test]
    fn abbreviate_hex_shortens_long_identifiers() {
        assert_eq!(abbreviate_hex("abcd"), "abcd");
        assert_eq!(
            abbreviate_hex("0123456789abcdef0123456789abcdef"),
            "0123...cdef"
        );
    }

    #[test]
    fn unique_result_values_dedupes_and_sorts() {
        assert_eq!(
            unique_result_values(&[
                "bbb".to_string(),
                "aaa".to_string(),
                "bbb".to_string(),
            ]),
            vec!["aaa".to_string(), "bbb".to_string()]
        );
    }
}
