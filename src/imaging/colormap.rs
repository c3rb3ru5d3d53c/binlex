use clap::ValueEnum;
use std::fmt;
use std::collections::BTreeMap;
use std::io::Error;
use std::io::ErrorKind;

#[derive(Debug, Clone, ValueEnum)]
pub enum ColorMapType {
    Grayscale,
    Heatmap,
    Bluegreen,
    Redblack,
}

impl fmt::Display for ColorMapType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                ColorMapType::Grayscale => "grayscale",
                ColorMapType::Heatmap => "heatmap",
                ColorMapType::Bluegreen => "bluegreen",
                ColorMapType::Redblack => "redblack",
            }
        )
    }
}

impl ColorMapType {

    pub fn from_string(s: &str) -> Result<Self, Error> {
        match s.trim().to_lowercase().as_str() {
            "grayscale" => Ok(ColorMapType::Grayscale),
            "heatmap" => Ok(ColorMapType::Heatmap),
            "bluegreen" => Ok(ColorMapType::Bluegreen),
            "redblack" => Ok(ColorMapType::Redblack),
            _ => Err(Error::new(
                ErrorKind::InvalidInput,
                format!("'{}' is not a valid ColorMapType", s),
            )),
        }
    }

    pub fn map_byte(&self, byte: u8) -> String {
        match self {
            ColorMapType::Grayscale => format!("rgb({},{},{})", byte, byte, byte),
            ColorMapType::Heatmap => {
                let r = (byte as f32 * 1.2).min(255.0) as u8;
                let g = (255 - byte).max(0) as u8;
                let b = (byte as f32 * 0.5).min(255.0) as u8;
                format!("rgb({},{},{})", r, g, b)
            }
            ColorMapType::Bluegreen => {
                let r = (byte as f32 * 0.2).min(255.0) as u8;
                let g = (byte as f32 * 0.8).min(255.0) as u8;
                let b = (255 - byte).max(0) as u8;
                format!("rgb({},{},{})", r, g, b)
            }
            ColorMapType::Redblack => {
                let r = byte;
                let g = 0;
                let b = 0;
                format!("rgb({},{},{})", r, g, b)
            }
        }
    }
}

pub struct ColorMap {
    cell_size: usize,
    color_map_type: ColorMapType,
    metadata_entries: BTreeMap<String, String>,
    svg_rectangles: Vec<String>,
    total_cells: usize,
    fixed_width: usize,
}

impl ColorMap {
    pub fn new() -> Self {
        Self {
            cell_size: 10,
            color_map_type: ColorMapType::Grayscale,
            metadata_entries: BTreeMap::new(),
            svg_rectangles: Vec::new(),
            total_cells: 0,
            fixed_width: 256,
        }
    }

    pub fn set_cell_size(&mut self, cell_size: usize) {
        self.cell_size = cell_size;
    }

    pub fn set_color_map_type(&mut self, color_map_type: ColorMapType) {
        self.color_map_type = color_map_type;
    }

    pub fn set_fixed_width(&mut self, fixed_width: usize) {
        self.fixed_width = fixed_width;
    }

    pub fn insert_metadata(&mut self, key: String, value: String) {
        self.metadata_entries.insert(key, value);
    }

    pub fn append(&mut self, offset: u64, data: &[u8]) {
        for (i, &byte) in data.iter().enumerate() {
            let cell_index = i;
            self.total_cells = self.total_cells.max(cell_index + 1);

            let row = cell_index / self.fixed_width;
            let col = cell_index % self.fixed_width;

            let x = col * self.cell_size;
            let y = row * self.cell_size;

            let color = self.color_map_type.map_byte(byte);

            self.svg_rectangles.push(format!(
                r#"<rect x="{}" y="{}" width="{}" height="{}" fill="{}" cell-index="{}" address="{}"/>
"#,
                x, y, self.cell_size, self.cell_size, color, cell_index, offset + i as u64
            ));
        }
    }

    fn generate_metadata(&self) -> String {
        let mut metadata_section = String::new();
        for (key, value) in &self.metadata_entries {
            metadata_section.push_str(r#"<metadata>
"#);
            metadata_section.push_str(&format!(r#"<{}>{}</{}>
"#, key, value, key));
            metadata_section.push_str(r#"</metadata>
"#);
        }
        metadata_section
    }

    pub fn to_svg_string(&self) -> String {
        let total_width = self.fixed_width * self.cell_size;
        let total_height = ((self.total_cells as f64) / (self.fixed_width as f64)).ceil() as usize * self.cell_size;

        let mut svg_content = String::new();
        svg_content.push_str(&format!(
            r#"<svg xmlns="http://www.w3.org/2000/svg" width="{}" height="{}" viewBox="0 0 {} {}">
"#,
            total_width,
            total_height,
            total_width,
            total_height
        ));

        svg_content.push_str(&self.generate_metadata());

        // Write each rectangle into the SVG
        for rectangle in &self.svg_rectangles {
            svg_content.push_str(rectangle);
        }

        svg_content.push_str("</svg>\n");

        svg_content
    }

    pub fn write(&self, file_path: &str) -> Result<(), std::io::Error> {
        std::fs::write(file_path, self.to_svg_string())
    }
}
