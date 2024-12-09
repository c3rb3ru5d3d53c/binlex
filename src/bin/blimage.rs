use std::fs::File;
use std::io::Read;
use std::process;
use clap::Parser;
use binlex::AUTHOR;
use binlex::VERSION;
use clap::ValueEnum;
use std::fmt;
use binlex::io::Stdout;
use std::collections::BTreeMap;
use binlex::hashing::SHA256;

#[derive(Parser, Debug)]
#[command(
    name = "blimage",
    version = VERSION,
    about =  format!("A Binlex Binary Visualization Tool\n\nVersion: {}", VERSION),
    after_help = format!("Author: {}", AUTHOR),
)]
struct Args {
    #[arg(short, long)]
    input: String,
    #[arg(short, long)]
    output: Option<String>,
    #[arg(short, long, value_enum, default_value = "grayscale")]
    color: ColorMap,
    #[arg(short, long, default_value_t = 10)]
    shape_size: usize,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum ColorMap {
    Grayscale,
    Heatmap,
    Bluegreen,
    Redblack,
}

impl fmt::Display for ColorMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                ColorMap::Grayscale => "grayscale",
                ColorMap::Heatmap => "heatmap",
                ColorMap::Bluegreen => "bluegreen",
                ColorMap::Redblack => "redblack",
            }
        )
    }
}

impl ColorMap {

    pub fn map_byte(&self, byte: u8) -> String {
        match self {
            ColorMap::Grayscale => format!("rgb({},{},{})", byte, byte, byte),
            ColorMap::Heatmap => {
                let r = (byte as f32 * 1.2).min(255.0) as u8;
                let g = (255 - byte).max(0) as u8;
                let b = (byte as f32 * 0.5).min(255.0) as u8;
                format!("rgb({},{},{})", r, g, b)
            }
            ColorMap::Bluegreen => {
                let r = (byte as f32 * 0.2).min(255.0) as u8;
                let g = (byte as f32 * 0.8).min(255.0) as u8;
                let b = (255 - byte).max(0) as u8;
                format!("rgb({},{},{})", r, g, b)
            }
            ColorMap::Redblack => {
                let r = byte;
                let g = 0;
                let b = 0;
                format!("rgb({},{},{})", r, g, b)
            }
        }
    }
}

fn main() {

    let args = Args::parse();

    let colormap = ColorMap::from_str(&args.color.to_string(), false).unwrap_or_else(|error| {
        eprintln!("{}", error);
        process::exit(1);
    });

    if args.output.is_some() {
        let mut file = File::open(args.input).unwrap_or_else(|error| {
            eprintln!("{}", error);
            process::exit(1);
        });

        let mut byte_data = Vec::new();

        file.read_to_end(&mut byte_data).unwrap_or_else(|error| {
            eprintln!("{}", error);
            process::exit(1);
        });

        let mut metadata = BTreeMap::<String, String>::new();
        metadata.insert("Hash".to_string(), "sha256:".to_string() + &SHA256::new(&byte_data).hexdigest().unwrap());

        let svg_content = bytes_to_svg(&byte_data, args.shape_size, &colormap, metadata);

        std::fs::write(args.output.unwrap(), svg_content).unwrap_or_else(|error| {
            eprintln!("{}", error);
            process::exit(1);
        });
    } else {
        let mut file = File::open(args.input).unwrap_or_else(|error| {
            eprintln!("{}", error);
            process::exit(1);
        });

        let mut byte_data = Vec::new();

        file.read_to_end(&mut byte_data).unwrap_or_else(|error| {
            eprintln!("{}", error);
            process::exit(1);
        });

        let mut metadata = BTreeMap::<String, String>::new();
        metadata.insert("Hash".to_string(), "sha256:".to_string() + &SHA256::new(&byte_data).hexdigest().unwrap());

        let svg_content = bytes_to_svg(&byte_data, args.shape_size, &colormap, metadata);
        Stdout::print(svg_content);
    }

    process::exit(0);
}


fn map_to_svg_metadata(metadata: BTreeMap::<String, String>) -> String {
    let mut svg = String::new();
    for (key, value) in metadata {
        svg.push_str(r#"<metadata>\n"#);
        svg.push_str(&format!(r#"<{}>{}</{}>\n"#, key, value, key));
        svg.push_str(r#"</metadata>\n"#);
    }
    svg
}

/// Converts byte data into an SVG representation with a given colormap
///
/// # Arguments
///
/// * `byte_data` - A slice of bytes to visualize.
/// * `shape_size` - The size of each rectangle in the grid (in pixels).
/// * `colormap` - The colormap to use for color mapping.
fn bytes_to_svg(byte_data: &[u8], shape_size: usize, colormap: &ColorMap, metadata: BTreeMap::<String, String>) -> String {
    let num_bytes = byte_data.len();
    let grid_size = (num_bytes as f64).sqrt().ceil() as usize;

    let mut svg = String::new();

    // SVG Header
    svg.push_str(&format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" width="{}" height="{}" viewBox="0 0 {} {}">\n"#,
        grid_size * shape_size,
        grid_size * shape_size,
        grid_size * shape_size,
        grid_size * shape_size
    ));

    svg.push_str(&map_to_svg_metadata(metadata));

    // Add rectangles for each byte
    for (i, &byte) in byte_data.iter().enumerate() {
        let row = i / grid_size;
        let col = i % grid_size;

        let x = col * shape_size;
        let y = row * shape_size;

        let color = colormap.map_byte(byte);

        svg.push_str(&format!(
            r#"<rect x="{}" y="{}" width="{}" height="{}" fill="{}" />\n"#,
            x, y, shape_size, shape_size, color
        ));
    }

    // SVG Footer
    svg.push_str("</svg>\n");

    svg
}
