use std::cmp::{max, min};

//
// --[ Original LCS code remains unchanged ]--
//

// ===========
// 1) Helpers
// ===========

pub fn compute_mat_ih_iv<T>(a: &[T], b: &[T]) -> (Vec<Vec<usize>>, Vec<Vec<usize>>)
where
    T: Eq,
{
    let na = a.len();
    let nb = b.len();
    let mut ih = vec![vec![0; nb + 1]; na + 1];
    let mut iv = vec![vec![0; nb + 1]; na + 1];

    for j in 0..(nb + 1) {
        ih[0][j] = j;
    }
    for l in 0..(na + 1) {
        iv[l][0] = 0;
    }

    for l in 1..(na + 1) {
        for j in 1..(nb + 1) {
            if a[l - 1] != b[j - 1] {
                ih[l][j] = max(iv[l][j - 1], ih[l - 1][j]);
                iv[l][j] = min(iv[l][j - 1], ih[l - 1][j]);
            } else {
                ih[l][j] = iv[l][j - 1];
                iv[l][j] = ih[l - 1][j];
            }
        }
    }
    (ih, iv)
}

pub fn compute_vec_ig<T>(a: &[T], b: &[T]) -> Vec<usize>
where
    T: Eq,
{
    let na = a.len();
    let nb = b.len();
    let mut ih = vec![vec![0; nb + 1], vec![0; nb + 1]];
    let mut iv = vec![vec![0; nb + 1], vec![0; nb + 1]];

    for j in 0..(nb + 1) {
        ih[0][j] = j;
    }

    for l in 1..(na + 1) {
        iv[1][0] = 0;
        for j in 1..(nb + 1) {
            if a[l - 1] != b[j - 1] {
                ih[1][j] = max(iv[1][j - 1], ih[0][j]);
                iv[1][j] = min(iv[1][j - 1], ih[0][j]);
            } else {
                ih[1][j] = iv[1][j - 1];
                iv[1][j] = ih[0][j];
            }
        }
        ih.swap(0, 1);
        iv.swap(0, 1);
    }
    ih.into_iter().next().unwrap()
}

pub fn compute_vg_dg_from_ig<T>(
    a: &[T],
    b: &[T],
    ig: &Vec<usize>,
) -> (Vec<Option<usize>>, Vec<Option<usize>>)
where
    T: Eq,
{
    let na = a.len();
    let nb = b.len();
    let mut vg = vec![None; nb + 1];
    let mut dg = vec![Some(0); na + 1];

    let mut i = 1;
    for j in 1..(nb + 1) {
        if ig[j] == 0 {
            dg[i] = Some(j);
            i += 1;
        } else {
            vg[ig[j]] = Some(j);
        }
    }
    for l in i..(na + 1) {
        dg[l] = None;
    }
    (vg, dg)
}

pub fn compute_ig_vg_dg_from_ih_mat<T>(
    a: &[T],
    b: &[T],
    ih: &Vec<Vec<usize>>,
) -> (Vec<usize>, Vec<Option<usize>>, Vec<Option<usize>>)
where
    T: Eq,
{
    let ig = ih[ih.len() - 1].clone();
    let (vg, dg) = compute_vg_dg_from_ig(a, b, &ih[ih.len() - 1]);
    (ig, vg, dg)
}

pub fn alcs<T>(a: &[T], b: &[T]) -> (Vec<usize>, Vec<Option<usize>>, Vec<Option<usize>>)
where
    T: Eq,
{
    let ig = compute_vec_ig(a, b);
    let (vg, dg) = compute_vg_dg_from_ig(a, b, &ig);
    (ig, vg, dg)
}

pub fn alcs_mat<T>(
    a: &[T],
    b: &[T],
) -> (
    Vec<Vec<usize>>,
    Vec<Vec<usize>>,
    Vec<usize>,
    Vec<Option<usize>>,
    Vec<Option<usize>>,
)
where
    T: Eq,
{
    let (ih, iv) = compute_mat_ih_iv(a, b);
    let (ig, vg, dg) = compute_ig_vg_dg_from_ih_mat(a, b, &ih);
    (ih, iv, ig, vg, dg)
}

#[derive(Debug)]
pub struct Alcs {
    ig: Vec<usize>,
}

impl Alcs {
    pub fn new<T>(a: &[T], b: &[T]) -> Self
    where
        T: Eq,
    {
        Alcs {
            ig: compute_vec_ig(a, b),
        }
    }

    /// Returns an iterator yielding the LCS length for all substrings starting from position `i`
    pub fn suffix(&self, pos: usize) -> AlcsIterator {
        AlcsIterator::new(self, pos)
    }
}

#[derive(Debug)]
pub struct AlcsIterator<'a> {
    alcs: &'a Alcs,
    i: usize,
    j: usize,
    prev: usize,
}

impl<'a> AlcsIterator<'a> {
    fn new(alcs: &'a Alcs, pos: usize) -> Self {
        AlcsIterator {
            alcs,
            i: pos,
            j: pos + 1,
            prev: 0,
        }
    }
}

impl<'a> Iterator for AlcsIterator<'a> {
    type Item = (usize, usize, usize);

    fn next(&mut self) -> Option<Self::Item> {
        if self.j >= self.alcs.ig.len() {
            return None;
        }
        let cur = self.prev + (self.alcs.ig[self.j] <= self.i) as usize;
        self.prev = cur;
        self.j += 1;
        Some((self.i, self.j - 1, cur))
    }
}

//
// ===========
// 2) The old single best "score" function (LCS-based).
//    We keep it for backward-compatibility.
// ===========
//
fn score(b: &str, a: &str, tsh: Option<f32>) -> (f32, usize, usize) {
    let va = a.chars().collect::<Vec<char>>();
    let vb = b.chars().collect::<Vec<char>>();
    let alcs = Alcs::new(&va, &vb);
    let na = a.len();
    let nb = b.len();
    let many = match tsh {
        None => nb,
        Some(tsh) => (na as f32 / tsh) as usize,
    };
    let mut best = (0., 0, 0);
    for i in 0..nb {
        let mut maxrow = (0., 0, 0);
        for (start_i, j, lcs_len) in alcs.suffix(i).take(many) {
            let cur = lcs_len as f32 / max(j - start_i, na) as f32;
            if cur > maxrow.0 {
                maxrow = (cur, start_i, j);
            }
        }
        if maxrow >= best {
            best = maxrow;
        }
    }
    best
}

//
// ======================================================
// 3) New "sub-YARA–style" function: single '?' wildcard
//    and returning ALL matches above threshold
// ======================================================
//

/// Finds all sub-YARA–style matches (one `?` mismatch allowed)
/// in `b` that align (in order) to the pattern `a`.
///
/// Returns a vector of (score, (start, end), subyara_alignment),
/// sorted by descending score (best match first).
///
/// Score formula ∈ [0,1]:
///   score = (matched_count / a.len()) * (matched_count / alignment_len)
///
/// This rewards matches that cover a large portion of `a` and
/// are "dense" within the alignment slice of `b`.
pub fn find_subyara_matches(
    b: &str,
    a: &str,
    threshold: f32
) -> Vec<(f32, (usize, usize), String)> {
    let vb: Vec<char> = b.chars().collect();
    let va: Vec<char> = a.chars().collect();
    let nb = vb.len();
    let na = va.len();

    let mut results = Vec::new();

    // Slide `a` across `b`.
    for start_b in 0..nb {
        let mut mismatch_used = false;
        let mut alignment = String::new();
        let mut matched_count = 0;
        let mut end_b = start_b;
        let mut idx_a = 0;

        // As long as we have characters left in both b and a
        while end_b < nb && idx_a < na {
            if vb[end_b] == va[idx_a] {
                // Exact match
                alignment.push(va[idx_a]);
                matched_count += 1;
            } else if !mismatch_used {
                // Use our one wildcard mismatch
                alignment.push('?');
                mismatch_used = true;
            } else {
                // Already used our mismatch; stop
                break;
            }

            // Compute the alignment length so far in `b`
            let alignment_len = end_b - start_b + 1;

            // fraction of pattern matched:
            //    matched_count / a.len()
            // fraction of alignment matched:
            //    matched_count / alignment_len
            // final score = product of both => in [0,1].
            let frac_pattern = matched_count as f32 / na as f32;
            let frac_dense   = matched_count as f32 / alignment_len as f32;
            let score = frac_pattern * frac_dense;

            if score >= threshold {
                results.push((score, (start_b, end_b + 1), alignment.clone()));
            }

            end_b += 1;
            idx_a += 1;
        }
    }

    // Sort results by descending score (best first)
    results.sort_by(|(score_a, _, _), (score_b, _, _)| {
        score_b
            .partial_cmp(score_a)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    results
}



//
// ======================================================
// 4) Example extension of the FuzzyLCS trait to gather
//    *multiple* matches using the new subyara approach.
// ======================================================
//

pub trait FuzzyLCS<T: AsRef<str>>: AsRef<str> {
    /// Old single best-match function
    fn fuzzy_find_pos(&self, s: T, tsh: f32) -> Option<(f32, usize, usize)> {
        let s = score(self.as_ref(), s.as_ref(), Some(tsh));
        if s.0 > tsh {
            Some(s)
        } else {
            None
        }
    }

    /// Old single best-match substring
    fn fuzzy_find_str<'a>(&'a self, s: T, tsh: f32) -> Option<(f32, &'a str)> {
        let r = self.fuzzy_find_pos(s, tsh);
        r.map(|(score_val, start, end)| (score_val, &self.as_ref()[start..end]))
    }

    /// Old single yes/no
    fn fuzzy_contains(&self, s: T, tsh: f32) -> bool {
        self.fuzzy_find_pos(s, tsh).is_some()
    }

    // ================================
    // NEW: get multiple sub-YARA–style matches
    // ================================
    fn fuzzy_find_subyara_all(&self, pat: T, tsh: f32)
        -> Vec<(f32, (usize, usize), String)>
    {
        find_subyara_matches(self.as_ref(), pat.as_ref(), tsh)
    }
}

impl<S, T> FuzzyLCS<T> for S
where
    S: AsRef<str>,
    T: AsRef<str>,
{
}
