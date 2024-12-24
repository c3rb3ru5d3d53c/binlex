//                    GNU LESSER GENERAL PUBLIC LICENSE
//                        Version 3, 29 June 2007
//
//  Copyright (C) 2007 Free Software Foundation, Inc. <https://fsf.org/>
//  Everyone is permitted to copy and distribute verbatim copies
//  of this license document, but changing it is not allowed.
//
//
//   This version of the GNU Lesser General Public License incorporates
// the terms and conditions of version 3 of the GNU General Public
// License, supplemented by the additional permissions listed below.
//
//   0. Additional Definitions.
//
//   As used herein, "this License" refers to version 3 of the GNU Lesser
// General Public License, and the "GNU GPL" refers to version 3 of the GNU
// General Public License.
//
//   "The Library" refers to a covered work governed by this License,
// other than an Application or a Combined Work as defined below.
//
//   An "Application" is any work that makes use of an interface provided
// by the Library, but which is not otherwise based on the Library.
// Defining a subclass of a class defined by the Library is deemed a mode
// of using an interface provided by the Library.
//
//   A "Combined Work" is a work produced by combining or linking an
// Application with the Library.  The particular version of the Library
// with which the Combined Work was made is also called the "Linked
// Version".
//
//   The "Minimal Corresponding Source" for a Combined Work means the
// Corresponding Source for the Combined Work, excluding any source code
// for portions of the Combined Work that, considered in isolation, are
// based on the Application, and not on the Linked Version.
//
//   The "Corresponding Application Code" for a Combined Work means the
// object code and/or source code for the Application, including any data
// and utility programs needed for reproducing the Combined Work from the
// Application, but excluding the System Libraries of the Combined Work.
//
//   1. Exception to Section 3 of the GNU GPL.
//
//   You may convey a covered work under sections 3 and 4 of this License
// without being bound by section 3 of the GNU GPL.
//
//   2. Conveying Modified Versions.
//
//   If you modify a copy of the Library, and, in your modifications, a
// facility refers to a function or data to be supplied by an Application
// that uses the facility (other than as an argument passed when the
// facility is invoked), then you may convey a copy of the modified
// version:
//
//    a) under this License, provided that you make a good faith effort to
//    ensure that, in the event an Application does not supply the
//    function or data, the facility still operates, and performs
//    whatever part of its purpose remains meaningful, or
//
//    b) under the GNU GPL, with none of the additional permissions of
//    this License applicable to that copy.
//
//   3. Object Code Incorporating Material from Library Header Files.
//
//   The object code form of an Application may incorporate material from
// a header file that is part of the Library.  You may convey such object
// code under terms of your choice, provided that, if the incorporated
// material is not limited to numerical parameters, data structure
// layouts and accessors, or small macros, inline functions and templates
// (ten or fewer lines in length), you do both of the following:
//
//    a) Give prominent notice with each copy of the object code that the
//    Library is used in it and that the Library and its use are
//    covered by this License.
//
//    b) Accompany the object code with a copy of the GNU GPL and this license
//    document.
//
//   4. Combined Works.
//
//   You may convey a Combined Work under terms of your choice that,
// taken together, effectively do not restrict modification of the
// portions of the Library contained in the Combined Work and reverse
// engineering for debugging such modifications, if you also do each of
// the following:
//
//    a) Give prominent notice with each copy of the Combined Work that
//    the Library is used in it and that the Library and its use are
//    covered by this License.
//
//    b) Accompany the Combined Work with a copy of the GNU GPL and this license
//    document.
//
//    c) For a Combined Work that displays copyright notices during
//    execution, include the copyright notice for the Library among
//    these notices, as well as a reference directing the user to the
//    copies of the GNU GPL and this license document.
//
//    d) Do one of the following:
//
//        0) Convey the Minimal Corresponding Source under the terms of this
//        License, and the Corresponding Application Code in a form
//        suitable for, and under terms that permit, the user to
//        recombine or relink the Application with a modified version of
//        the Linked Version to produce a modified Combined Work, in the
//        manner specified by section 6 of the GNU GPL for conveying
//        Corresponding Source.
//
//        1) Use a suitable shared library mechanism for linking with the
//        Library.  A suitable mechanism is one that (a) uses at run time
//        a copy of the Library already present on the user's computer
//        system, and (b) will operate properly with a modified version
//        of the Library that is interface-compatible with the Linked
//        Version.
//
//    e) Provide Installation Information, but only if you would otherwise
//    be required to provide such information under section 6 of the
//    GNU GPL, and only to the extent that such information is
//    necessary to install and execute a modified version of the
//    Combined Work produced by recombining or relinking the
//    Application with a modified version of the Linked Version. (If
//    you use option 4d0, the Installation Information must accompany
//    the Minimal Corresponding Source and Corresponding Application
//    Code. If you use option 4d1, you must provide the Installation
//    Information in the manner specified by section 6 of the GNU GPL
//    for conveying Corresponding Source.)
//
//   5. Combined Libraries.
//
//   You may place library facilities that are a work based on the
// Library side by side in a single library together with other library
// facilities that are not Applications and are not covered by this
// License, and convey such a combined library under terms of your
// choice, if you do both of the following:
//
//    a) Accompany the combined library with a copy of the same work based
//    on the Library, uncombined with any other library facilities,
//    conveyed under the terms of this License.
//
//    b) Give prominent notice with the combined library that part of it
//    is a work based on the Library, and explaining where to find the
//    accompanying uncombined form of the same work.
//
//   6. Revised Versions of the GNU Lesser General Public License.
//
//   The Free Software Foundation may publish revised and/or new versions
// of the GNU Lesser General Public License from time to time. Such new
// versions will be similar in spirit to the present version, but may
// differ in detail to address new problems or concerns.
//
//   Each version is given a distinguishing version number. If the
// Library as you received it specifies that a certain numbered version
// of the GNU Lesser General Public License "or any later version"
// applies to it, you have the option of following the terms and
// conditions either of that published version or of any later version
// published by the Free Software Foundation. If the Library as you
// received it does not specify a version number of the GNU Lesser
// General Public License, you may choose any version of the GNU Lesser
// General Public License ever published by the Free Software Foundation.
//
//   If the Library as you received it specifies that a proxy can decide
// whether future versions of the GNU Lesser General Public License shall
// apply, that proxy's public statement of acceptance of any version is
// permanent authorization for you to choose that version for the
// Library.

use pyo3::prelude::*;
use pyo3::Py;
use std::collections::BTreeMap;
use binlex::controlflow::Function as InnerFunction;
use binlex::controlflow::Graph as InnerGraph;
use binlex::controlflow::FunctionJsonDeserializer as InnerFunctionJsonDeserializer;
use crate::genetics::Chromosome;
use crate::genetics::ChromosomeSimilarity;
use crate::Config;
use crate::controlflow::Graph;
use std::sync::Arc;
use std::sync::Mutex;
use pyo3::types::PyBytes;
use crate::controlflow::Block;
use pyo3::types::PyList;
use crate::Architecture;
use binlex::Binary as InnerBinary;

#[pyclass]
pub struct FunctionJsonDeserializer {
    pub inner: Arc<Mutex<InnerFunctionJsonDeserializer>>,
}

#[pymethods]
impl FunctionJsonDeserializer {
    #[new]
    #[pyo3(text_signature = "(string, config)")]
    pub fn new(py: Python, string: String, config: Py<Config>) -> PyResult<Self> {
        let inner_config = config.borrow(py).inner.lock().unwrap().clone();
        let inner = InnerFunctionJsonDeserializer::new(string, inner_config)?;
        Ok(Self {
           inner: Arc::new(Mutex::new(inner)),
        })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn architecture(&self) -> PyResult<Architecture> {
        let inner = self.inner.lock().unwrap().architecture()
            .map_err(|err| pyo3::exceptions::PyRuntimeError::new_err(format!("{}", err)))?;
        Ok(Architecture {
            inner: inner
        })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn bytes(&self, py: Python) -> PyResult<Option<Py<PyBytes>>> {
        let binding = self.inner.lock().unwrap();
        let string = binding.json.bytes.clone();
        if string.is_none() { return Ok(None); }
        let bytes = InnerBinary::from_hex(&string.unwrap())
            .map_err(|err| pyo3::exceptions::PyRuntimeError::new_err(format!("{}", err)))?;
        let result = PyBytes::new_bound(py, &bytes);
        Ok(Some(result.into()))
    }

    #[pyo3(text_signature = "($self, rhs)")]
    pub fn compare(&self, py: Python, rhs: Py<FunctionJsonDeserializer>) -> PyResult<Option<ChromosomeSimilarity>> {
        let binding = rhs.borrow(py);
        let rhs_inner = binding.inner.lock().unwrap();
        let similarity = self.inner.lock().unwrap().compare(&rhs_inner)?;
        if similarity.is_none() { return Ok(None); }
        Ok(Some(ChromosomeSimilarity {
            inner: Arc::new(Mutex::new(similarity.unwrap()))
        }))
    }

    #[pyo3(text_signature = "($self, rhs_functions)")]
    pub fn compare_many(&self, py: Python, rhs_functions: Py<PyList>) -> PyResult<BTreeMap<u64, ChromosomeSimilarity>> {
        // Initialize the function deserializer
        let function = InnerFunctionJsonDeserializer::new(
            self.json()?,
            self.inner.lock().unwrap().config.clone(),
        )?;

        // Prepare a vector to hold tasks (deserializers)
        let mut tasks = Vec::<InnerFunctionJsonDeserializer>::new();

        // Bind the Python list
        let list = rhs_functions.bind(py);

        // Collect items from the Python list
        let items: Vec<Py<PyAny>> = list.iter().map(|item| item.into()).collect();

        // Iterate over each item to deserialize and collect tasks
        for item in items {
            let py_item = item.bind(py);
            if !py_item.is_instance_of::<FunctionJsonDeserializer>() {
                return Err(pyo3::exceptions::PyTypeError::new_err(
                    "All items in rhs_functions must be instances of FunctionJsonDeserializer",
                ));
            }

            // Attempt to extract the deserializer
            let rhs: Option<Py<FunctionJsonDeserializer>> = py_item.extract().ok();
            if let Some(rhs_binding) = rhs {
                let rhs_borrowed = rhs_binding.borrow(py);
                let task: InnerFunctionJsonDeserializer = rhs_borrowed.inner.lock().unwrap().clone();
                tasks.push(task);
            }
        }

        // Perform the comparisons sequentially
        let mut results = BTreeMap::new();
        for rhs_function in tasks.iter() {
            if let Ok(Some(similarity)) = function.compare(rhs_function) {
                results.insert(
                    rhs_function.address(),
                    ChromosomeSimilarity {
                        inner: Arc::new(Mutex::new(similarity)),
                    },
                );
            }
        }

        Ok(results)
    }

    #[pyo3(text_signature = "($self)")]
    pub fn address(&self) -> u64 {
        self.inner.lock().unwrap().address()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn number_of_instructions(&self) -> usize {
        self.inner.lock().unwrap().number_of_instructions()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn number_of_blocks(&self) -> usize {
        self.inner.lock().unwrap().number_of_blocks()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn average_instructions_per_block(&self) -> f64 {
        self.inner.lock().unwrap().average_instructions_per_block()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn entropy(&self) -> Option<f64> {
        self.inner.lock().unwrap().entropy()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn edges(&self) -> usize {
        self.inner.lock().unwrap().edges()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn sha256(&self) -> Option<String> {
        self.inner.lock().unwrap().sha256()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn minhash(&self) -> Option<String> {
        self.inner.lock().unwrap().minhash()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn tlsh(&self) -> Option<String> {
        self.inner.lock().unwrap().tlsh()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn tlsh_ratio(&self) -> f64 {
        self.inner.lock().unwrap().tlsh_ratio()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn minhash_ratio(&self) -> f64 {
        self.inner.lock().unwrap().minhash_ratio()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn chromosome_minhash_ratio(&self) -> f64 {
        self.inner.lock().unwrap().chromosome_minhash_ratio()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn chromosome_tlsh_ratio(&self) -> f64 {
        self.inner.lock().unwrap().chromosome_tlsh_ratio()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn prologue(&self) -> bool {
        self.inner.lock().unwrap().prologue()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn chromosome(&self) -> Chromosome {
        let inner_chromosome = self.inner.lock().unwrap().chromosome();
        Chromosome {
            inner: Arc::new(Mutex::new(inner_chromosome.unwrap()))
        }
    }

    #[pyo3(text_signature = "($self)")]
    pub fn to_dict(&self, py: Python) -> PyResult<Py<PyAny>> {
        let json_str = self.json()?;
        let json_module = py.import_bound("json")?;
        let py_dict = json_module.call_method1("loads", (json_str,))?;
        Ok(py_dict.into())
    }

    #[pyo3(text_signature = "($self)")]
    pub fn json(&self) -> PyResult<String> {
        self.inner
            .lock()
            .unwrap()
            .json()
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
    }

    #[pyo3(text_signature = "($self)")]
    pub fn print(&self) {
        self.inner
            .lock()
            .unwrap()
            .print()
    }

    pub fn __str__(&self) -> PyResult<String> {
        self.json()
    }
}

#[pyclass]
/// Represents a function within a control flow graph (CFG).
pub struct Function {
    /// The address of the function.
    pub address: u64,
    /// The control flow graph associated with the function.
    pub cfg: Py<Graph>,
    inner_function_cache: Arc<Mutex<Option<InnerFunction<'static>>>>,
}

impl Function {
    fn with_inner_function<F, R>(&self, py: Python, f: F) -> PyResult<R>
    where
        F: FnOnce(&InnerFunction<'static>) -> PyResult<R>,
    {
        let mut cache = self.inner_function_cache.lock().unwrap();

        if cache.is_none() {
            let binding = self.cfg.borrow(py);
            let inner = binding.inner.lock().unwrap();

            let inner_ref: &'static _ = unsafe { std::mem::transmute(&*inner) };
            let inner_block = InnerFunction::new(self.address, inner_ref)?;
            *cache = Some(inner_block);
        }

        f(cache.as_ref().unwrap())
    }
}

#[pymethods]
impl Function {
    #[new]
    #[pyo3(text_signature = "(address, cfg)")]
    /// Creates a new `Function` instance.
    ///
    /// # Arguments
    /// - `address` (`u64`): The address of the function.
    /// - `cfg` (`Graph`): The control flow graph associated with the function.
    ///
    /// # Returns
    /// - A new instance of `Function`.
    pub fn new(address: u64, cfg: Py<Graph>) -> PyResult<Self> {
        Ok(Self {
            address,
            cfg,
            inner_function_cache: Arc::new(Mutex::new(None)),
        })
    }

    pub fn address(&self) -> u64 {
        self.address
    }

    #[pyo3(text_signature = "($self)")]
    /// Returns the chromosome associated with this function.
    ///
    /// # Returns
    /// - `PyResult<Option<Chromosome>>`: The chromosome associated with this function
    pub fn chromosome(&self, py: Python) -> PyResult<Option<Chromosome>> {
        self.with_inner_function(py, |function| {
            let inner_config = self.cfg.borrow(py).inner.lock().unwrap().config.clone();
            let config = Py::new(py, Config {
                inner: Arc::new(Mutex::new(inner_config))
            }).unwrap();
            let pattern = function.pattern();
            if pattern.is_none() { return Ok(None); }
            let chromosome = Chromosome::new(py, pattern.unwrap(), config).ok();
            return Ok(chromosome);
        })
    }

    #[pyo3(text_signature = "($self, rhs)")]
    /// Compares this block with another returning the similarity.
    ///
    /// # Returns
    ///
    /// Returns an `Option<ChromosomeSimilarity>` reprenting the similarity between this block and another.
    pub fn compare(&self, py: Python, rhs: Py<Function>) -> PyResult<Option<ChromosomeSimilarity>> {
        self.with_inner_function(py, |function| {
            let rhs_address = rhs.borrow(py).address.clone();
            let rhs_binding_0 = rhs.borrow(py);
            let rhs_binding_1 = rhs_binding_0.cfg.borrow(py);
            let rhs_cfg = rhs_binding_1.inner.lock().unwrap();
            let rhs_inner = InnerFunction::new(rhs_address, &rhs_cfg).ok();
            if rhs_inner.is_none() { return Ok(None); }
            let inner = function.compare(&rhs_inner.unwrap())?;
            if inner.is_none() { return Ok(None); }
            let similarity = ChromosomeSimilarity {
                inner: Arc::new(Mutex::new(inner.unwrap())),
            };
            return Ok(Some(similarity));
        })
    }

    #[pyo3(text_signature = "($self, rhs_functions)")]
    pub fn compare_many(
        &self,
        py: Python,
        rhs_functions: Py<PyList>,
    ) -> PyResult<BTreeMap<u64, ChromosomeSimilarity>> {
        self.with_inner_function(py, |function| {
            let mut tasks = Vec::<(u64, Arc<Mutex<InnerGraph>>)>::new();

            // Bind the PyList to access its items
            let list = rhs_functions.bind(py);

            // Collect items into a Rust Vec for processing
            let items: Vec<Py<PyAny>> = list.iter().map(|item| item.into()).collect();

            // Iterate over each item to validate and collect necessary data
            for item in items {
                let py_item = item.bind(py);

                // Ensure the item is an instance of `Function`
                if !py_item.is_instance_of::<Function>() {
                    return Err(pyo3::exceptions::PyTypeError::new_err(
                        "all items in rhs_functions must be instances of Function",
                    ));
                }

                // Attempt to extract the `Function` instance
                let rhs: Option<Py<Function>> = py_item.extract().ok();
                if let Some(rhs_binding) = rhs {
                    let rhs_borrowed = rhs_binding.borrow(py);
                    let address = rhs_borrowed.address();
                    let rhs_cfg = Arc::clone(&rhs_borrowed.cfg.borrow(py).inner);
                    tasks.push((address, rhs_cfg));
                }
            }

            // Initialize the results map
            let mut results: BTreeMap<u64, ChromosomeSimilarity> = BTreeMap::new();

            // Sequentially process each task
            for (address, inner_cfg) in tasks.iter() {
                // Lock the inner configuration
                let c = inner_cfg.lock().map_err(|e| {
                    pyo3::exceptions::PyRuntimeError::new_err(format!(
                        "Failed to lock InnerGraph: {}",
                        e
                    ))
                })?;

                // Create a new InnerFunction instance
                if let Ok(rhs_function) = InnerFunction::new(*address, &c) {
                    // Compare the functions to get similarity
                    if let Ok(Some(similarity)) = function.compare(&rhs_function) {
                        // Insert the similarity result into the map
                        results.insert(
                            *address,
                            ChromosomeSimilarity {
                                inner: Arc::new(Mutex::new(similarity)),
                            },
                        );
                    }
                }
            }

            // Return the collected results
            Ok(results)
        })
    }

    // #[pyo3(text_signature = "($self, rhs_functions)")]
    // pub fn compare_many(&self, py: Python, rhs_functions: Py<PyList>) -> PyResult<BTreeMap<u64, ChromosomeSimilarity>> {
    //     self.with_inner_function(py, |function| {
    //         let mut tasks = Vec::<(u64, Arc<Mutex<InnerGraph>>)>::new();

    //         let list = rhs_functions.bind(py);

    //         let items: Vec<Py<PyAny>> = list.iter().map(|item| item.into()).collect();

    //         for item in items {
    //             let py_item = item.bind(py);
    //             if !py_item.is_instance_of::<Function>() {
    //                 return Err(pyo3::exceptions::PyTypeError::new_err(
    //                     "all items in rhs_functions must be instances of Function",
    //                 ));
    //             }
    //             let rhs: Option<Py<Function>> = py_item.extract().ok();
    //             if rhs.is_none() { continue; }
    //             let rhs_binding_0 = rhs.unwrap();
    //             let rhs_binding_1 = rhs_binding_0.borrow(py);
    //             let address = rhs_binding_1.address();
    //             let rhs_cfg = Arc::clone(&rhs_binding_1.cfg.borrow(py).inner);
    //             tasks.push((address, rhs_cfg));
    //         };

    //         let pool = ThreadPoolBuilder::new()
    //             .num_threads(function.cfg.config.general.threads)
    //             .build()
    //             .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(format!("{}", error)))?;

    //         let results: BTreeMap<u64, ChromosomeSimilarity> = pool.install(|| {
    //             tasks
    //                 .par_iter()
    //                 .filter_map(|(address, inner_cfg)| {
    //                     let c = inner_cfg.lock().unwrap();
    //                     let rhs_function = InnerFunction::new(*address, &c).ok()?;
    //                     let similarity = function.compare(&rhs_function).ok()?;
    //                     similarity.map(|similarity| {
    //                         (
    //                             *address,
    //                             ChromosomeSimilarity {
    //                                 inner: Arc::new(Mutex::new(similarity)),
    //                             },
    //                         )
    //                     })
    //                 })
    //                 .collect()
    //         });
    //         Ok(results)
    //     })
    // }

    #[pyo3(text_signature = "($self)")]
    pub fn chromosome_minhash_ratio(&self, py: Python) -> PyResult<f64> {
        self.with_inner_function(py, |function| {
            Ok(function.chromosome_minhash_ratio())
        })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn chromosome_tlsh_ratio(&self, py: Python) -> PyResult<f64> {
        self.with_inner_function(py, |function| {
            Ok(function.chromosome_tlsh_ratio())
        })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn minhash_ratio(&self, py: Python) -> PyResult<f64> {
        self.with_inner_function(py, |function| {
            Ok(function.minhash_ratio())
        })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn tlsh_ratio(&self, py: Python) -> PyResult<f64> {
        self.with_inner_function(py, |function| {
            Ok(function.tlsh_ratio())
        })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn cyclomatic_complexity(&self, py: Python) -> PyResult<usize> {
        self.with_inner_function(py, |function| {
            Ok(function.cyclomatic_complexity())
        })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn average_instructions_per_block(&self, py: Python) -> PyResult<f64> {
        self.with_inner_function(py, |function| {
            Ok(function.average_instructions_per_block())
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Returns the blocks associated with this function.
    ///
    /// # Returns
    /// - `PyResult<Vec<Block>>`: The blocks associated with this function
    pub fn blocks(&self, py: Python) -> PyResult<Vec<Block>> {
        self.with_inner_function(py, |function| {
            let mut result = Vec::<Block>::new();
            for (block_address, _) in &function.blocks {
                let block = Block::new(*block_address, self.cfg.clone_ref(py))
                    .expect("failed to get block");
                result.push(block);
            }
            return Ok(result);
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Returns the raw bytes of the function.
    ///
    /// # Returns
    /// - `bytes | None`: The raw bytes of the function, if available
    pub fn bytes(&self, py: Python) -> PyResult<Option<Py<PyBytes>>> {
        self.with_inner_function(py, |function| {
            if let Some(raw_bytes) = function.bytes() {
                let bytes = PyBytes::new_bound(py, &raw_bytes);
                Ok(Some(bytes.into()))
            } else {
                Ok(None)
            }
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Determines if the function starts with a prologue.
    ///
    /// # Returns
    /// - `bool`: `true` if the function starts with a prologue; otherwise, `false`.
    pub fn prologue(&self, py: Python) -> PyResult<bool> {
        self.with_inner_function(py, |function| Ok(function.prologue()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Returns the number of edges in the control flow graph.
    ///
    /// # Returns
    /// - `usize`: The number of edges.
    pub fn edges(&self, py: Python) -> PyResult<usize> {
        self.with_inner_function(py, |function| Ok(function.edges()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Returns the entropy of the function.
    ///
    /// # Returns
    /// - `Option<f64>`: The entropy value, if available.
    pub fn entropy(&self, py: Python) -> PyResult<Option<f64>> {
        self.with_inner_function(py, |function| Ok(function.entropy()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Returns the number of instructions in the function.
    ///
    /// # Returns
    /// - `usize`: The number of instructions.
    pub fn number_of_instructions(&self, py: Python) -> PyResult<usize> {
        self.with_inner_function(py, |function| Ok(function.number_of_instructions()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Returns the number of blocks in the function.
    ///
    /// # Returns
    /// - `usize`: The number of blocks.
    pub fn number_of_blocks(&self, py: Python) -> PyResult<usize> {
        self.with_inner_function(py, |function| Ok(function.number_of_blocks()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Returns a mapping of function calls within the current function.
    ///
    /// # Returns
    /// - `BTreeMap<u64, u64>`: A map of called functions' addresses and counts.
    pub fn functions(&self, py: Python) -> PyResult<BTreeMap<u64, u64>> {
        self.with_inner_function(py, |function| Ok(function.functions()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Returns the TLSH (Trend Micro Locality Sensitive Hash) of the function.
    ///
    /// # Returns
    /// - `Option<String>`: The TLSH hash, if available.
    pub fn tlsh(&self, py: Python) -> PyResult<Option<String>> {
        self.with_inner_function(py, |function| Ok(function.tlsh()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Returns the SHA-256 hash of the function.
    ///
    /// # Returns
    /// - `Option<String>`: The SHA-256 hash, if available.
    pub fn sha256(&self, py: Python) -> PyResult<Option<String>> {
        self.with_inner_function(py, |function| Ok(function.sha256()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Returns the MinHash of the function.
    ///
    /// # Returns
    /// - `Option<String>`: The MinHash, if available.
    pub fn minhash(&self, py: Python) -> PyResult<Option<String>> {
        self.with_inner_function(py, |function| Ok(function.minhash()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Returns the size of the function in bytes.
    ///
    /// # Returns
    /// - `usize`: The size of the function in bytes.
    pub fn size(&self, py: Python) -> PyResult<usize> {
        self.with_inner_function(py, |function| Ok(function.size()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Determines if the function's memory layout is contiguous.
    ///
    /// # Returns
    /// - `bool`: `True` if contiguous; otherwise, `False`.
    pub fn contiguous(&self, py: Python) -> PyResult<bool> {
        self.with_inner_function(py, |function| Ok(function.contiguous()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Returns the ending address of the function.
    ///
    /// # Returns
    /// - `int | None`: The ending address, if available.
    pub fn end(&self, py: Python) -> PyResult<Option<u64>> {
        self.with_inner_function(py, |function| Ok(function.end()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Prints a textual representation of the function in JSON.
    ///
    /// # Returns
    /// - `()` (unit): Output is sent to stdout.
    pub fn print(&self, py: Python) -> PyResult<()> {
        self.with_inner_function(py, |function| Ok(function.print()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Converts the function to a JSON dictionary representation.
    ///
    /// # Returns
    /// - `dict`: A Python dictionary representation of the function.
    pub fn to_dict(&self, py: Python) -> PyResult<Py<PyAny>> {
        let json_str = self.json(py)?;
        let json_module = py.import_bound("json")?;
        let py_dict = json_module.call_method1("loads", (json_str,))?;
        Ok(py_dict.into())
    }

    #[pyo3(text_signature = "($self)")]
    /// Converts the function to JSON representation.
    ///
    /// # Returns
    /// - `str`: JSON string representing the function.
    pub fn json(&self, py: Python) -> PyResult<String> {
        self.with_inner_function(py, |block| {
            block.json().map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
        })
    }

    /// When printed directly print the JSON representation of the function.
    pub fn __str__(&self, py: Python) -> PyResult<String> {
        self.json(py)
    }
}

#[pymodule]
#[pyo3(name = "function")]
pub fn function_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Function>()?;
    m.add_class::<FunctionJsonDeserializer>()?;
    py.import_bound("sys")?
        .getattr("modules")?
        .set_item("binlex.controlflow.function", m)?;
    m.setattr("__name__", "binlex.controlflow.function")?;
    Ok(())
}
