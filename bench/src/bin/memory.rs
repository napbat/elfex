//! Measure the heap use of each `elfex` operation with a counting global allocator.
//!
//! The binary runs each [`Operation`] on each input from [`inputs`] and prints a Markdown
//! table for each input. The columns are:
//!
//! - **Peak**: the highest heap size during the operation, minus the heap size at the start.
//! - **Allocated**: the sum of the sizes of all allocations. A `realloc` counts as one
//!   allocation of the new size.
//! - **Allocations**: the number of allocations, `realloc` calls included.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use elfex_bench::{BoxError, Operation, Prepared, inputs};

/// The heap size now.
static CURRENT: AtomicUsize = AtomicUsize::new(0);
/// The highest heap size since the last reset.
static PEAK: AtomicUsize = AtomicUsize::new(0);
/// The sum of all allocation sizes.
static TOTAL: AtomicUsize = AtomicUsize::new(0);
/// The number of allocations.
static COUNT: AtomicUsize = AtomicUsize::new(0);

/// A global allocator that uses `System` and counts the allocations.
struct Counting;

/// Record an allocation of `size` bytes.
fn record(size: usize) {
    COUNT.fetch_add(1, Ordering::Relaxed);
    TOTAL.fetch_add(size, Ordering::Relaxed);
    let now = CURRENT
        .fetch_add(size, Ordering::Relaxed)
        .saturating_add(size);
    PEAK.fetch_max(now, Ordering::Relaxed);
}

/// Record a deallocation of `size` bytes.
fn release(size: usize) {
    CURRENT.fetch_sub(size, Ordering::Relaxed);
}

#[expect(
    unsafe_code,
    reason = "a counting global allocator must implement the unsafe `GlobalAlloc` trait"
)]
// SAFETY: Each method forwards to `System` with the same arguments, so it keeps the
// `GlobalAlloc` contract of `System`. The counters do not allocate.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: The caller keeps the contract of `GlobalAlloc::alloc`.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            record(layout.size());
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: The caller keeps the contract of `GlobalAlloc::alloc_zeroed`.
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            record(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: The caller keeps the contract of `GlobalAlloc::dealloc`. `System` made
        // `pointer`, because all methods forward to `System`.
        unsafe { System.dealloc(pointer, layout) };
        release(layout.size());
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: The caller keeps the contract of `GlobalAlloc::realloc`. `System` made
        // `pointer`, because all methods forward to `System`.
        let new = unsafe { System.realloc(pointer, layout, new_size) };
        if !new.is_null() {
            release(layout.size());
            record(new_size);
        }
        new
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// The heap use of one run of an operation.
struct Usage {
    peak: usize,
    total: usize,
    count: usize,
}

/// Run the operation once without measurement, then measure one more run.
fn measure(run: &mut dyn FnMut() -> elfex::Result<usize>) -> elfex::Result<Usage> {
    run()?;
    let start = CURRENT.load(Ordering::Relaxed);
    PEAK.store(start, Ordering::Relaxed);
    let total = TOTAL.load(Ordering::Relaxed);
    let count = COUNT.load(Ordering::Relaxed);
    run()?;
    Ok(Usage {
        peak: PEAK.load(Ordering::Relaxed).saturating_sub(start),
        total: TOTAL.load(Ordering::Relaxed).saturating_sub(total),
        count: COUNT.load(Ordering::Relaxed).saturating_sub(count),
    })
}

/// Format a byte count with a binary unit and two decimals.
fn human(bytes: usize) -> String {
    const UNITS: [(usize, &str); 3] = [(1 << 30, "GiB"), (1 << 20, "MiB"), (1 << 10, "KiB")];
    for (unit, name) in UNITS {
        if bytes >= unit {
            let hundredths = bytes.saturating_mul(100) / unit;
            return format!("{}.{:02} {name}", hundredths / 100, hundredths % 100);
        }
    }
    format!("{bytes} B")
}

fn main() -> Result<(), BoxError> {
    let inputs = inputs()?;
    println!("# elfex heap use");
    for input in &inputs {
        let prepared = Prepared::new(input)?;
        println!();
        println!("## {} ({})", input.name, human(input.bytes.len()));
        println!();
        println!("| Operation | Peak | Allocated | Allocations |");
        println!("| --- | ---: | ---: | ---: |");
        for operation in Operation::ALL {
            let usage = operation.with_runner(&prepared, measure)??;
            println!(
                "| `{}` | {} | {} | {} |",
                operation.name(),
                human(usage.peak),
                human(usage.total),
                usage.count
            );
        }
    }
    Ok(())
}
