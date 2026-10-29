//! Criterion benchmarks of the `elfex` operations.
//!
//! The benchmark measures each [`Operation`] on each input from [`inputs`]: the synthetic
//! shared object and the files in `ELFEX_BENCH_FILES`. Each input is a benchmark group.

use std::time::Duration;

use criterion::{Criterion, SamplingMode, criterion_group, criterion_main};
use elfex_bench::{Operation, Prepared, inputs};

/// Measure all operations on all inputs.
fn operations(criterion: &mut Criterion) {
    let inputs = inputs().expect("the benchmark inputs must load");
    for input in &inputs {
        let prepared = Prepared::new(input).expect("the benchmark input must parse");
        let mut group = criterion.benchmark_group(input.name.as_str());
        // Some operations take more than 100 ms on a large file. Flat sampling with few
        // samples keeps the run time short.
        group
            .sampling_mode(SamplingMode::Flat)
            .sample_size(10)
            .warm_up_time(Duration::from_secs(1))
            .measurement_time(Duration::from_secs(3));
        for operation in Operation::ALL {
            operation
                .with_runner(&prepared, |run| {
                    group.bench_function(operation.name(), |bencher| {
                        bencher.iter(|| run().expect("the operation must succeed"));
                    });
                })
                .expect("the operation must prepare");
        }
        group.finish();
    }
}

criterion_group!(benches, operations);
criterion_main!(benches);
