pub(crate) const STYLES: &str = include_str!("assets/styles.css");
pub(crate) const SCRIPT: &str = concat!(
    include_str!("../../../../src/search/query.js"),
    "\n",
    include_str!("assets/js/render.js"),
    "\n",
    include_str!("assets/js/search.js"),
    "\n",
    include_str!("assets/app.js"),
);
