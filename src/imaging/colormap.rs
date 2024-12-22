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

pub struct ColorMap <'colormap> {
    bytes: &'colormap[u8],
    shape_size: usize,
    colormaptype: ColorMapType,
    metadata: BTreeMap::<String, String>,
    offset: u64,
}

impl <'colormap> ColorMap <'colormap> {
    pub fn new(bytes: &'colormap [u8]) -> Self {
        Self {
            bytes: bytes,
            shape_size: 10,
            colormaptype: ColorMapType::Grayscale,
            metadata: BTreeMap::<String, String>::new(),
            offset: 0,
        }
    }

    pub fn set_shape_size(&mut self, shape_size: usize) {
        self.shape_size = shape_size
    }

    pub fn set_type(&mut self, colormaptype: ColorMapType) {
        self.colormaptype = colormaptype;
    }

    pub fn insert_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }

    pub fn set_offset(&mut self, offset: u64) {
        self.offset = offset
    }

    fn metadata(&self) -> String {
        let mut svg = String::new();
        for (key, value) in &self.metadata {
            svg.push_str(r#"<metadata>\n"#);
            svg.push_str(&format!(r#"<{}>{}</{}>\n"#, key, value, key));
            svg.push_str(r#"</metadata>\n"#);
        }
        svg
    }

    pub fn to_string(&self) -> String {
        let num_bytes = self.bytes.len();
        let grid_size = (num_bytes as f64).sqrt().ceil() as usize;

        let mut svg = String::new();

        svg.push_str(&format!(
            r#"<svg xmlns="http://www.w3.org/2000/svg" width="{}" height="{}" viewBox="0 0 {} {}">\n"#,
            grid_size * self.shape_size,
            grid_size * self.shape_size,
            grid_size * self.shape_size,
            grid_size * self.shape_size
        ));

        svg.push_str(&self.metadata());

        for (i, &byte) in self.bytes.iter().enumerate() {
            let row = i / grid_size;
            let col = i % grid_size;

            let x = col * self.shape_size;
            let y = row * self.shape_size;

            let color = self.colormaptype.map_byte(byte);

            svg.push_str(&format!(
                r#"<rect x="{}" y="{}" width="{}" height="{}" fill="{}" offset="{}"/>\n"#,
                x, y, self.shape_size, self.shape_size, color, i as u64 + self.offset
            ));
        }

        svg.push_str("</svg>\n");

        svg
    }

    pub fn write(&self, file_path: String) -> Result<(), Error> {
        Ok(std::fs::write(file_path, self.to_string())?)
    }
}
