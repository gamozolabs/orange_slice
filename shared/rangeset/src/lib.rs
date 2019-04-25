#![no_std]
#![feature(const_fn)]

use core::cmp;

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct Range
{
    pub start: u64,
    pub end:   u64,
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct RangeSet {
    /// Fixed array of ranges in the set
    ranges: [Range; 32],

    /// Number of in use entries in `ranges`
    ///
    /// This is not a usize to make the structure fixed size so we can pass it
    /// directly from protected mode to long mode. Since `ranges` is fixed u32
    /// is plenty large for this use.
    in_use: u32,
}

impl RangeSet
{
    /// Create a new empty RangeSet
    pub const fn new() -> RangeSet
    {
        RangeSet {
            ranges: [Range { start: 0, end: 0 }; 32],
            in_use: 0,
        }
    }

    /// Get all the entries in the RangeSet as a slice
    pub fn entries(&self) -> &[Range]
    {
        &self.ranges[..self.in_use as usize]
    }

    /// Delete the Range contained in the RangeSet at `idx`
    fn delete(&mut self, idx: usize)
    {
        assert!(idx < self.in_use as usize, "Index out of bounds");

        for ii in idx..(self.in_use as usize)-1 {
            self.ranges.swap(ii, ii+1);
        }

        self.in_use -= 1;
    }

    /// Insert a new range into this RangeSet.
    ///
    /// If the range overlaps with an existing range then the ranges will
    /// be merged. If the range has no overlap with an existing range then
    /// it will simply be added to the set.
    pub fn insert(&mut self, mut range: Range)
    {
        assert!(range.start <= range.end, "Invalid range shape");

        /* Outside loop forever until we run out of merges with existing
         * ranges.
         */
        'try_merges: loop {
            for ii in 0..(self.in_use as usize) {
                let ent = self.ranges[ii];

                /* Check for overlap with an existing range.
                 * Note that we do a saturated add of one to each range.
                 * This is done so that two ranges that are 'touching' but
                 * not overlapping will be combined.
                 */
                if !overlaps(range.start, range.end.saturating_add(1),
                        ent.start, ent.end.saturating_add(1)){
                    continue;
                }

                /* There was overlap with an existing range. Make this range
                 * a combination of the existing ranges.
                 */
                range.start = cmp::min(range.start, ent.start);
                range.end   = cmp::max(range.end,   ent.end);

                /* Delete the old range, as the new one is now all inclusive */
                self.delete(ii);

                /* Start over looking for merges */
                continue 'try_merges;
            }

            break;
        }

        assert!((self.in_use as usize) < self.ranges.len(),
            "Too many entries in RangeSet on insert");

        /* Add the new range to the end */
        self.ranges[self.in_use as usize] = range;
        self.in_use += 1;
    }

    /// Remove `range` from the RangeSet
    ///
    /// Any range in the RangeSet which overlaps with `range` will be trimmed
    /// such that there is no more overlap. If this results in a range in
    /// the set becoming empty, the range will be removed entirely from the
    /// set.
    pub fn remove(&mut self, range: Range)
    {
        assert!(range.start <= range.end, "Invalid range shape");
        
        'try_subtractions: loop {
            for ii in 0..(self.in_use as usize) {
                let ent = self.ranges[ii];

                /* If there is no overlap, there is nothing to do with this
                 * range.
                 */
                if !overlaps(range.start, range.end, ent.start, ent.end) {
                    continue;
                }

                /* If this entry is entirely contained by the range to remove,
                 * then we can just delete it.
                 */
                if contains(ent.start, ent.end, range.start, range.end) {
                    self.delete(ii);
                    continue 'try_subtractions;
                }

                /* At this point we know there is overlap, but only partial.
                 * This means we need to adjust the size of the current range
                 * and potentially insert a new entry if the entry is split
                 * in two.
                 */

                if range.start <= ent.start {
                    /* If the overlap is on the low end of the range, adjust
                     * the start of the range to the end of the range we want
                     * to remove.
                     */
                    self.ranges[ii].start = range.end.saturating_add(1);
                } else if range.end >= ent.end {
                    /* If the overlap is on the high end of the range, adjust
                     * the end of the range to the start of the range we want
                     * to remove.
                     */
                    self.ranges[ii].end = range.start.saturating_sub(1);
                } else {
                    /* If the range to remove fits inside of the range then
                     * we need to split it into two ranges.
                     */
                    self.ranges[ii].start = range.end.saturating_add(1);

                    assert!((self.in_use as usize) < self.ranges.len(),
                        "Too many entries in RangeSet on split");

                    self.ranges[self.in_use as usize] = Range {
                        start: ent.start,
                        end:   range.start.saturating_sub(1),
                    };
                    self.in_use += 1;
                    continue 'try_subtractions;
                }
            }

            break;
        }
    }

    /// Subtracts a rangeset from `self`
    pub fn subtract(&mut self, rs: &RangeSet)
    {
        for &ent in rs.entries() {
            self.remove(ent);
        }
    }

    /// Compute the size of the range covered by this rangeset
    pub fn sum(&self) -> u64
    {
        self.entries().iter().fold(0u64, |acc, x| acc + (x.end - x.start) + 1)
    }

    /// Allocate `size` bytes of memory with `align` requirement for alignment
    ///
    /// A return value of NULL represents an error.
    ///
    /// This function attempts to allocate memory from the provided `rangeset`,
    /// fulfilling size and alignment requirements. The alignment must be a
    /// power of two and nonzero. This allows for a mask to be created by
    /// subtracting 1 from the mask.
    pub fn allocate(&mut self, size: u64, align: u64) -> *mut u8
    {
        /* Validate alignment is nonzero and a power of 2 */
        if align.count_ones() != 1 {
            return core::ptr::null_mut();
        }

        /* Zero sized allocations get 1 byte allocated */
        let size = if size <= 0 { 1 } else { size };

        /* Generate a mask for the specified alignment */
        let alignmask = align - 1;

        /* Go through each memory range in the rangeset */
        let mut allocation = None;
        for ent in self.entries() {
            /* Determine number of bytes required for front padding to satisfy
             * alignment requirments.
             */
            let align_fix = (align - (ent.start & alignmask)) & alignmask;

            /* Compute base and end of allocation as an inclusive range
             * [base, end]
             */
            let base = ent.start;
            let end  = base.checked_add(size - 1).unwrap().
                checked_add(align_fix).unwrap();

            /* Validate that this allocation is addressable in the current
             * processor state.
             */
            if base > core::usize::MAX as u64 || end > core::usize::MAX as u64 {
                continue;
            }

            /* Check that this entry has enough room to satisfy allocation */
            if end > ent.end {
                continue;
            }

            /* Allocation successful! */
            allocation = Some((base, end, (base + align_fix) as *mut u8));
            break;
        }

        match allocation {
            Some((base, end, ptr)) => {
                /* If allocation was successful, remove range from RangeSet and
                 * return!
                 */
                self.remove(Range { start: base, end: end });
                ptr
            },

            /* If allocation failed return null */
            None => core::ptr::null_mut(),
        }
    }
}

/// Determines of the two ranges [x1, x2] and [y1, y2] have any overlap
fn overlaps(mut x1: u64, mut x2: u64, mut y1: u64, mut y2: u64) -> bool
{
    /* Make sure x2 is always > x1 */
    if x1 > x2 {
        core::mem::swap(&mut x1, &mut x2);
    }

    /* Make sure y2 is always > y1 */
    if y1 > y2 {
        core::mem::swap(&mut y1, &mut y2);
    }

    /* Check if there is overlap */
    if x1 <= y2 && y1 <= x2 {
        return true;
    }

    false
}

/// Returns true if the entirity of [x1, x2] is contained inside [y1, y2], else
/// returns false.
fn contains(mut x1: u64, mut x2: u64, mut y1: u64, mut y2: u64) -> bool
{
    /* Make sure x2 is always > x1 */
    if x1 > x2 {
        core::mem::swap(&mut x1, &mut x2);
    }

    /* Make sure y2 is always > y1 */
    if y1 > y2 {
        core::mem::swap(&mut y1, &mut y2);
    }

    if x1 >= y1 && x2 <= y2 {
        return true;
    }

    false
}

