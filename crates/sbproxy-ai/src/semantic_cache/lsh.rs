//! Deterministic multi table random projection candidate buckets.
//!
//! Locality sensitive hashing is candidate generation only. A bucket never
//! decides a hit: every candidate still passes schema, namespace, expiry,
//! dimension, finite vector, and exact cosine checks before a stored response
//! may be replayed. There is deliberately no bucket comparison API that could
//! be mistaken for a match.
//!
//! Bucket derivation is deterministic across processes and architectures. It
//! depends only on the configured seed string and the query vector, never on
//! a process random number generator, a hash map iteration order, or a per
//! process seed. Two nodes that share one configuration therefore agree on
//! the same buckets for the same vector.
//!
//! Projection storage scales with tables times planes rather than with the
//! embedding width: each plane keeps one 64 bit projection seed, and each
//! coordinate sign is derived on demand with a fixed SplitMix64 step. A
//! 1,536 dimension embedding therefore costs no projection matrix at all.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use smallvec::SmallVec;

use super::config::{SemanticLshConfig, MAX_EMBEDDING_DIMENSIONS, MAX_LSH_PLANES, MAX_LSH_TABLES};

/// Fixed domain for every projection seed in the v2 keyspace.
const LSH_DOMAIN: &[u8] = b"sbproxy-semcache-lsh-v2";

/// SplitMix64 increment applied once per coordinate index.
const SPLITMIX_GAMMA: u64 = 0x9E37_79B9_7F4A_7C15;
/// First SplitMix64 finalizer multiplier.
const SPLITMIX_MIX_ONE: u64 = 0xBF58_476D_1CE4_E5B9;
/// Second SplitMix64 finalizer multiplier.
const SPLITMIX_MIX_TWO: u64 = 0x94D0_49BB_1331_11EB;

/// One candidate bucket in one projection table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SemanticBucket {
    /// Zero based table identifier. Tables are unique and ordered.
    pub table: u8,
    /// Packed plane bits for this table, one bit per plane from the low bit.
    pub value: u64,
}

/// Closed failure set for projection construction and bucket derivation.
///
/// Every message is a fixed label. None of them can carry a prompt, a vector,
/// a seed, or any other operator or caller value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LshError {
    /// The configured table count is outside the supported range.
    #[error("semantic cache lsh table count is out of range")]
    TableCount,
    /// The configured plane count is outside the range one `u64` can pack.
    #[error("semantic cache lsh plane count is out of range")]
    PlaneCount,
    /// The configured seed is empty.
    #[error("semantic cache lsh seed is empty")]
    Seed,
    /// The embedding has no coordinates.
    #[error("semantic cache embedding vector is empty")]
    EmptyVector,
    /// The embedding is wider than the supported dimension limit.
    #[error("semantic cache embedding vector exceeds the dimension limit")]
    Dimensions,
    /// The embedding contains a NaN or an infinity.
    #[error("semantic cache embedding vector is not finite")]
    NonFinite,
    /// The embedding has a zero or non finite norm.
    #[error("semantic cache embedding vector has a zero norm")]
    ZeroNorm,
}

/// Deterministic multi table random projection index.
pub struct RandomProjectionLsh {
    /// Number of independent projection tables.
    tables: u8,
    /// Number of hyperplanes per table.
    planes: u8,
    /// One projection seed per table and plane, in table major order.
    ///
    /// Storage is tables times planes. It never scales with the embedding
    /// width, so no dimension sized projection matrix is persisted.
    seeds: Vec<u64>,
}

impl RandomProjectionLsh {
    /// Build the index from validated LSH configuration.
    ///
    /// Construction fails closed on an out of range table count, an out of
    /// range plane count, or an empty seed, so a bad configuration can never
    /// shift past the width of a `u64`.
    pub fn from_config(config: &SemanticLshConfig) -> Result<Self, LshError> {
        if config.tables == 0 || config.tables > MAX_LSH_TABLES {
            return Err(LshError::TableCount);
        }
        if config.planes == 0 || config.planes > MAX_LSH_PLANES {
            return Err(LshError::PlaneCount);
        }
        if config.seed.is_empty() {
            return Err(LshError::Seed);
        }

        let count = usize::from(config.tables) * usize::from(config.planes);
        let mut seeds = Vec::with_capacity(count);
        for table in 0..config.tables {
            for plane in 0..config.planes {
                seeds.push(projection_seed(config.seed.as_bytes(), table, plane));
            }
        }
        Ok(Self {
            tables: config.tables,
            planes: config.planes,
            seeds,
        })
    }

    /// Derive one candidate bucket per table for a query or stored vector.
    ///
    /// The vector is normalized once, then each plane accumulates a dot
    /// product against a Rademacher projection in `f64`. A sum greater than
    /// or equal to zero sets that plane bit. The result is a candidate set:
    /// the caller must still rerank with exact cosine similarity.
    pub fn buckets(&self, embedding: &[f32]) -> Result<SmallVec<[SemanticBucket; 8]>, LshError> {
        let normalized = normalize(embedding)?;
        let planes = usize::from(self.planes);
        let mut buckets = SmallVec::new();
        for table in 0..self.tables {
            let mut value = 0u64;
            for plane in 0..self.planes {
                let seed = self.seeds[usize::from(table) * planes + usize::from(plane)];
                let mut sum = 0f64;
                for (index, coordinate) in normalized.iter().enumerate() {
                    sum += rademacher(seed, index) * coordinate;
                }
                if sum >= 0.0 {
                    value |= 1u64 << plane;
                }
            }
            buckets.push(SemanticBucket { table, value });
        }
        Ok(buckets)
    }
}

/// Derive the fixed projection seed for one table and plane.
///
/// The digest covers the fixed domain, the length prefixed operator seed
/// bytes, the table byte, and the plane byte. The first eight digest bytes
/// are read in big endian order, so the seed is identical on every
/// architecture.
fn projection_seed(seed: &[u8], table: u8, plane: u8) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(LSH_DOMAIN);
    hasher.update(u64::try_from(seed.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(seed);
    hasher.update([table]);
    hasher.update([plane]);
    let digest: [u8; 32] = hasher.finalize().into();
    let mut head = [0u8; 8];
    head.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(head)
}

/// Derive the Rademacher coefficient for one coordinate of one plane.
///
/// This replaces a stored projection matrix with a fixed SplitMix64 step, so
/// the mapping is portable and costs no SHA-256 call per embedding element.
fn rademacher(projection_seed: u64, index: usize) -> f64 {
    // The dimension limit keeps every index far inside u64 range.
    let offset = u64::try_from(index).unwrap_or(u64::MAX);
    let mut z = projection_seed.wrapping_add(offset.wrapping_mul(SPLITMIX_GAMMA));
    z = (z ^ (z >> 30)).wrapping_mul(SPLITMIX_MIX_ONE);
    z = (z ^ (z >> 27)).wrapping_mul(SPLITMIX_MIX_TWO);
    z ^= z >> 31;
    if (z & 1) == 1 {
        1.0
    } else {
        -1.0
    }
}

/// Validate and L2 normalize one embedding in `f64`.
fn normalize(embedding: &[f32]) -> Result<Vec<f64>, LshError> {
    if embedding.is_empty() {
        return Err(LshError::EmptyVector);
    }
    if embedding.len() > MAX_EMBEDDING_DIMENSIONS {
        return Err(LshError::Dimensions);
    }
    let mut square_sum = 0f64;
    for coordinate in embedding {
        if !coordinate.is_finite() {
            return Err(LshError::NonFinite);
        }
        square_sum += f64::from(*coordinate) * f64::from(*coordinate);
    }
    let norm = square_sum.sqrt();
    if !norm.is_finite() || norm <= 0.0 {
        return Err(LshError::ZeroNorm);
    }
    Ok(embedding
        .iter()
        .map(|coordinate| f64::from(*coordinate) / norm)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vector behind the deterministic table fixture.
    const FIXTURE_VECTOR: [f32; 3] = [0.8, 0.6, 0.0];
    /// Seed behind the deterministic table fixture.
    const FIXTURE_SEED: &str = "sbproxy-semantic-v2";

    fn fixture_config() -> SemanticLshConfig {
        SemanticLshConfig {
            tables: 8,
            planes: 6,
            seed: FIXTURE_SEED.to_string(),
            ..SemanticLshConfig::default()
        }
    }

    /// Expected fixture buckets, transcribed from the documented v2
    /// projection rather than from the production code path.
    ///
    /// The transcription pins the domain label, the length prefixed seed
    /// encoding, the big endian seed read, the SplitMix64 constants, the
    /// Rademacher mapping, and the plane bit order. A change to any of them
    /// renames every deployed bucket, so it must fail here first.
    fn expected_fixture_buckets() -> SmallVec<[SemanticBucket; 8]> {
        let config = fixture_config();
        let norm = FIXTURE_VECTOR
            .iter()
            .map(|value| f64::from(*value) * f64::from(*value))
            .sum::<f64>()
            .sqrt();
        let unit: Vec<f64> = FIXTURE_VECTOR
            .iter()
            .map(|value| f64::from(*value) / norm)
            .collect();

        let mut expected = SmallVec::new();
        for table in 0..config.tables {
            let mut value = 0u64;
            for plane in 0..config.planes {
                let mut hasher = Sha256::new();
                hasher.update(b"sbproxy-semcache-lsh-v2");
                hasher.update((config.seed.len() as u64).to_be_bytes());
                hasher.update(config.seed.as_bytes());
                hasher.update([table]);
                hasher.update([plane]);
                let digest: [u8; 32] = hasher.finalize().into();
                let mut head = [0u8; 8];
                head.copy_from_slice(&digest[..8]);
                let seed = u64::from_be_bytes(head);

                let mut sum = 0f64;
                for (index, coordinate) in unit.iter().enumerate() {
                    let mut z = seed.wrapping_add((index as u64).wrapping_mul(SPLITMIX_GAMMA));
                    z = (z ^ (z >> 30)).wrapping_mul(SPLITMIX_MIX_ONE);
                    z = (z ^ (z >> 27)).wrapping_mul(SPLITMIX_MIX_TWO);
                    z ^= z >> 31;
                    let sign = if (z & 1) == 1 { 1.0 } else { -1.0 };
                    sum += sign * coordinate;
                }
                if sum >= 0.0 {
                    value |= 1u64 << plane;
                }
            }
            expected.push(SemanticBucket { table, value });
        }
        expected
    }

    /// Deterministic search for a seed that collides two orthogonal vectors.
    ///
    /// One table with one plane splits the space in two, so some seed must
    /// place both vectors on the same side. Searching for it keeps the test
    /// independent of any particular digest value.
    fn collision_config() -> SemanticLshConfig {
        let left = normalized([1.0, 0.0, 0.0]);
        let right = normalized([0.0, 1.0, 0.0]);
        for candidate in 0..64u32 {
            let config = SemanticLshConfig {
                tables: 1,
                planes: 1,
                seed: format!("collision-seed-{candidate}"),
                ..SemanticLshConfig::default()
            };
            let lsh = RandomProjectionLsh::from_config(&config).unwrap();
            if shares_at_least_one_bucket(&lsh, &left, &right) {
                return config;
            }
        }
        panic!("no colliding seed in the search space");
    }

    fn normalized(values: [f32; 3]) -> Vec<f32> {
        let norm = values.iter().map(|value| value * value).sum::<f32>().sqrt();
        values.iter().map(|value| value / norm).collect()
    }

    fn cosine(left: &[f32], right: &[f32]) -> f32 {
        left.iter().zip(right).map(|(a, b)| a * b).sum()
    }

    fn shares_at_least_one_bucket(lsh: &RandomProjectionLsh, left: &[f32], right: &[f32]) -> bool {
        let left = lsh.buckets(left).unwrap();
        let right = lsh.buckets(right).unwrap();
        left.iter().any(|bucket| right.contains(bucket))
    }

    #[test]
    fn deterministic_tables_match_a_fixed_fixture() {
        let lsh = RandomProjectionLsh::from_config(&fixture_config()).unwrap();
        let buckets = lsh.buckets(&[0.8, 0.6, 0.0]).unwrap();
        assert_eq!(buckets.len(), 8);
        assert_eq!(buckets, expected_fixture_buckets());
    }

    #[test]
    fn exact_reranking_is_required_after_a_bucket_collision() {
        let lsh = RandomProjectionLsh::from_config(&collision_config()).unwrap();
        let left = normalized([1.0, 0.0, 0.0]);
        let right = normalized([0.0, 1.0, 0.0]);
        assert!(shares_at_least_one_bucket(&lsh, &left, &right));
        assert_eq!(cosine(&left, &right), 0.0);
    }

    #[test]
    fn the_same_vector_produces_one_bucket_per_table() {
        let config = fixture_config();
        let lsh = RandomProjectionLsh::from_config(&config).unwrap();
        let buckets = lsh.buckets(&[0.1, -0.2, 0.3, 0.4]).unwrap();
        assert_eq!(buckets.len(), usize::from(config.tables));
        for bucket in &buckets {
            // Only the configured planes may occupy bits in the value.
            assert!(bucket.value < (1u64 << config.planes));
        }
    }

    #[test]
    fn table_ids_are_unique_and_ordered() {
        let lsh = RandomProjectionLsh::from_config(&fixture_config()).unwrap();
        let buckets = lsh.buckets(&[0.5, 0.5, 0.5]).unwrap();
        let tables: Vec<u8> = buckets.iter().map(|bucket| bucket.table).collect();
        assert_eq!(tables, (0..8u8).collect::<Vec<u8>>());
    }

    #[test]
    fn the_same_seed_is_deterministic_across_instances() {
        let first = RandomProjectionLsh::from_config(&fixture_config()).unwrap();
        let second = RandomProjectionLsh::from_config(&fixture_config()).unwrap();
        let vector = [0.3, -0.7, 0.2, 0.9, -0.1];
        assert_eq!(
            first.buckets(&vector).unwrap(),
            second.buckets(&vector).unwrap()
        );
        assert_eq!(first.seeds, second.seeds);
    }

    #[test]
    fn changing_the_seed_changes_at_least_one_bucket() {
        let other = SemanticLshConfig {
            seed: "sbproxy-semantic-other".to_string(),
            ..fixture_config()
        };
        let first = RandomProjectionLsh::from_config(&fixture_config()).unwrap();
        let second = RandomProjectionLsh::from_config(&other).unwrap();
        let vector = [0.3, -0.7, 0.2, 0.9, -0.1];
        assert_ne!(
            first.buckets(&vector).unwrap(),
            second.buckets(&vector).unwrap()
        );
    }

    #[test]
    fn projection_seed_storage_scales_with_tables_times_planes_not_dimensions() {
        let config = SemanticLshConfig {
            tables: 4,
            planes: 5,
            ..fixture_config()
        };
        let lsh = RandomProjectionLsh::from_config(&config).unwrap();
        assert_eq!(lsh.seeds.len(), 20);

        // A far wider embedding still costs the same projection storage.
        let wide = vec![0.01f32; 4096];
        assert!(lsh.buckets(&wide).is_ok());
        assert_eq!(lsh.seeds.len(), 20);
    }

    #[test]
    fn zero_length_vectors_fail() {
        let lsh = RandomProjectionLsh::from_config(&fixture_config()).unwrap();
        assert_eq!(lsh.buckets(&[]), Err(LshError::EmptyVector));
    }

    #[test]
    fn all_zero_vectors_fail() {
        let lsh = RandomProjectionLsh::from_config(&fixture_config()).unwrap();
        assert_eq!(lsh.buckets(&[0.0, 0.0, 0.0]), Err(LshError::ZeroNorm));
        assert_eq!(lsh.buckets(&[0.0, -0.0]), Err(LshError::ZeroNorm));
    }

    #[test]
    fn nan_and_infinity_fail() {
        let lsh = RandomProjectionLsh::from_config(&fixture_config()).unwrap();
        assert_eq!(lsh.buckets(&[f32::NAN, 1.0]), Err(LshError::NonFinite));
        assert_eq!(lsh.buckets(&[f32::INFINITY, 1.0]), Err(LshError::NonFinite));
        let negative = [f32::NEG_INFINITY, 1.0];
        assert_eq!(lsh.buckets(&negative), Err(LshError::NonFinite));
    }

    #[test]
    fn dimensions_above_the_limit_fail() {
        let lsh = RandomProjectionLsh::from_config(&fixture_config()).unwrap();
        let at_limit = vec![0.01f32; MAX_EMBEDDING_DIMENSIONS];
        let over_limit = vec![0.01f32; MAX_EMBEDDING_DIMENSIONS + 1];
        assert!(lsh.buckets(&at_limit).is_ok());
        assert_eq!(lsh.buckets(&over_limit), Err(LshError::Dimensions));
    }

    #[test]
    fn planes_above_the_limit_fail_before_shifting_a_u64() {
        let over = SemanticLshConfig {
            planes: MAX_LSH_PLANES + 1,
            ..fixture_config()
        };
        let zero = SemanticLshConfig {
            planes: 0,
            ..fixture_config()
        };
        let at_limit = SemanticLshConfig {
            planes: MAX_LSH_PLANES,
            ..fixture_config()
        };
        assert_eq!(
            RandomProjectionLsh::from_config(&over).err(),
            Some(LshError::PlaneCount)
        );
        assert_eq!(
            RandomProjectionLsh::from_config(&zero).err(),
            Some(LshError::PlaneCount)
        );
        // The widest accepted plane count still shifts inside one u64.
        let lsh = RandomProjectionLsh::from_config(&at_limit).unwrap();
        assert!(lsh.buckets(&[0.4, 0.6]).is_ok());
    }

    #[test]
    fn tables_above_the_limit_fail() {
        let over = SemanticLshConfig {
            tables: MAX_LSH_TABLES + 1,
            ..fixture_config()
        };
        let zero = SemanticLshConfig {
            tables: 0,
            ..fixture_config()
        };
        assert_eq!(
            RandomProjectionLsh::from_config(&over).err(),
            Some(LshError::TableCount)
        );
        assert_eq!(
            RandomProjectionLsh::from_config(&zero).err(),
            Some(LshError::TableCount)
        );
    }

    #[test]
    fn an_empty_seed_fails() {
        let empty = SemanticLshConfig {
            seed: String::new(),
            ..fixture_config()
        };
        assert_eq!(
            RandomProjectionLsh::from_config(&empty).err(),
            Some(LshError::Seed)
        );
    }
}
