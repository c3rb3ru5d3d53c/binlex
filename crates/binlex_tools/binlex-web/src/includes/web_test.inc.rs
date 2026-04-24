#[cfg(test)]
mod tests {
    use super::*;
    use binlex::controlflow::{Function, Graph, Instruction};

    fn build_test_state(root: &std::path::Path, sha256: &str) -> AppState {
        let mut analysis_config = Config::default();
        analysis_config.index.local.dimensions = Some(64);
        let mut graph = Graph::new(Architecture::AMD64, analysis_config.clone());
        let mut instruction =
            Instruction::create(0x1000, Architecture::AMD64, analysis_config.clone());
        instruction.bytes = vec![0xC3];
        instruction.pattern = "c3".to_string();
        instruction.is_return = true;
        graph.insert_instruction(instruction);
        assert!(graph.set_block(0x1000));
        assert!(graph.set_function(0x1000));

        let index =
            LocalIndex::with_options(analysis_config.clone(), Some(root.to_path_buf()), Some(64))
                .expect("create local index");
        index
            .graph(sha256, &graph, &[], None, None)
            .expect("stage graph");
        let function = Function::new(0x1000, &graph).expect("build function");
        let block = function.blocks()[0].clone();
        let instruction = block.instructions()[0].clone();
        index
            .function(&function, &[1.0; 64], sha256, &[])
            .expect("stage function");
        index
            .block(&block, &[2.0; 64], sha256, &[])
            .expect("stage block");
        index
            .instruction(&instruction, &[3.0; 64], sha256, &[])
            .expect("stage instruction");
        index.commit().expect("commit local index");

        let client = Server::new(
            Config::default(),
            Some("http://127.0.0.1:5000".to_string()),
            Some(false),
            Some(true),
        )
        .expect("create client");

        AppState {
            ui: BinlexWebConfig::default(),
            client,
            index,
            database: Arc::new(
                LocalDB::with_path(&analysis_config, Some(root.join("local.db")))
                    .expect("create localdb"),
            ),
            analysis_config,
            index_root: root.to_path_buf(),
            staged_indexes: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    #[test]
    fn execute_search_returns_rows_for_single_sided_lhs_query() {
        let root = std::env::temp_dir().join(format!(
            "binlex-web-main-execute-search-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let sha256 = "d60f9eaa4f62f0ee84531d9aa633c5bb390ea0056953e58d80b9a62277dbe5c5";
        let state = build_test_state(&root, sha256);

        let page = execute_search(
            &state,
            &PageParams {
                search: Some("1".to_string()),
                query: format!("sample:{sha256}"),
                top_k: Some(16),
                page: Some(1),
                ..PageParams::default()
            },
        )
        .expect("execute search");

        assert!(!page.rows.is_empty());
        assert!(page.rows.iter().all(|row| matches!(row.side, RowSide::Lhs)));
        assert!(
            page.rows
                .iter()
                .all(|row| row.result.sha256().eq_ignore_ascii_case(sha256))
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn execute_search_supports_username_filter() {
        let root = std::env::temp_dir().join(format!(
            "binlex-web-main-username-filter-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let sha256 = "d60f9eaa4f62f0ee84531d9aa633c5bb390ea0056953e58d80b9a62277dbe5c5";
        let state = build_test_state(&root, sha256);

        let page = execute_search(
            &state,
            &PageParams {
                search: Some("1".to_string()),
                query: format!("sample:{sha256} | username:anonymous"),
                top_k: Some(16),
                page: Some(1),
                ..PageParams::default()
            },
        )
        .expect("execute search");

        assert!(!page.rows.is_empty());
        assert!(
            page.rows
                .iter()
                .all(|row| row.result.username().eq_ignore_ascii_case("anonymous"))
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn execute_search_supports_limit_then_ascending_on_search_stream() {
        let root = std::env::temp_dir().join(format!(
            "binlex-web-main-search-ordering-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let sha256 = "d60f9eaa4f62f0ee84531d9aa633c5bb390ea0056953e58d80b9a62277dbe5c5";
        let state = build_test_state(&root, sha256);

        let page = execute_search(
            &state,
            &PageParams {
                search: Some("1".to_string()),
                query: format!("sample:{sha256} | limit:10 | ascending:score"),
                top_k: Some(16),
                page: Some(1),
                ..PageParams::default()
            },
        )
        .expect("execute search");

        assert_eq!(page.rows.len(), 2);
        assert!(
            page.rows
                .iter()
                .all(|row| row.result.sha256().eq_ignore_ascii_case(sha256))
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn execute_search_supports_expand_blocks_from_function_rows() {
        let root = std::env::temp_dir().join(format!(
            "binlex-web-main-expand-blocks-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let sha256 = "d60f9eaa4f62f0ee84531d9aa633c5bb390ea0056953e58d80b9a62277dbe5c5";
        let state = build_test_state(&root, sha256);

        let page = execute_search(
            &state,
            &PageParams {
                search: Some("1".to_string()),
                query: format!(
                    "sample:{sha256} | collection:functions | address:0x1000 | expand:blocks | collection:blocks"
                ),
                top_k: Some(16),
                page: Some(1),
                ..PageParams::default()
            },
        )
        .expect("execute search");

        assert_eq!(page.rows.len(), 1);
        assert_eq!(page.rows[0].result.collection(), Collection::Block);
        assert_eq!(page.rows[0].result.address(), 0x1000);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn execute_search_supports_expand_instructions_from_block_rows() {
        let root = std::env::temp_dir().join(format!(
            "binlex-web-main-expand-instructions-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let sha256 = "d60f9eaa4f62f0ee84531d9aa633c5bb390ea0056953e58d80b9a62277dbe5c5";
        let state = build_test_state(&root, sha256);

        let page = execute_search(
            &state,
            &PageParams {
                search: Some("1".to_string()),
                query: format!(
                    "sample:{sha256} | collection:blocks | address:0x1000 | expand:instructions | collection:instructions"
                ),
                top_k: Some(16),
                page: Some(1),
                ..PageParams::default()
            },
        )
        .expect("execute search");

        assert_eq!(page.rows.len(), 1);
        assert_eq!(page.rows[0].result.collection(), Collection::Instruction);
        assert_eq!(page.rows[0].result.address(), 0x1000);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn execute_search_does_not_apply_number_of_blocks_filter_to_block_rows() {
        let root = std::env::temp_dir().join(format!(
            "binlex-web-main-block-number-of-blocks-filter-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let sha256 = "d60f9eaa4f62f0ee84531d9aa633c5bb390ea0056953e58d80b9a62277dbe5c5";
        let state = build_test_state(&root, sha256);

        let error = match execute_search(
            &state,
            &PageParams {
                search: Some("1".to_string()),
                query: format!("sample:{sha256} | collection:blocks | blocks:>1"),
                top_k: Some(16),
                page: Some(1),
                ..PageParams::default()
            },
        ) {
            Ok(_) => panic!("reject function-only blocks filter on block rows"),
            Err(error) => error,
        };
        assert!(error.contains("blocks"));
        assert!(error.contains("collection:functions"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn detect_project_tool_supports_bundle_zip() {
        assert_eq!(detect_project_tool("analysis-bundle.zip"), Some("bundle"));
        assert_eq!(
            content_type_for_filename("analysis-bundle.zip"),
            "application/zip"
        );
        assert!(project_tool_extensions("bundle").contains(&"zip"));
    }

    #[test]
    fn render_entity_llvm_ir_returns_raw_llvm_text() {
        let root = std::env::temp_dir().join(format!(
            "binlex-web-main-render-llvm-ir-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let sha256 = "d60f9eaa4f62f0ee84531d9aa633c5bb390ea0056953e58d80b9a62277dbe5c5";
        let state = build_test_state(&root, sha256);

        let ir = render_entity_llvm_ir(&state, sha256, Collection::Function, "amd64", 0x1000)
            .expect("render llvm ir");

        assert!(ir.contains("define void"));
        assert!(ir.contains("@function_"));

        let _ = std::fs::remove_dir_all(&root);
    }
}
