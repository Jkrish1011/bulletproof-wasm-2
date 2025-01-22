use wasm_bindgen::prelude::*;

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;

#[derive(Serialize, Deserialize)]
#[wasm_bindgen]
pub struct BetProofData {
    commitment: Vec<u8>,
    proof: Vec<u8>,
    nullifier: Vec<u8>,
    blinding_factor: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[wasm_bindgen]
pub struct BetVerificationData {
    commitment: Vec<u8>,
    proof: Vec<u8>,
}

// Constants for range proof
const RANGE_BIT_SIZE: usize = 32; // For bet amounts up to 2^32

#[wasm_bindgen]
pub struct BulletproofGenerator {
    bp_gens: BulletproofGens,
    pc_gens: PedersenGens,
}

#[wasm_bindgen]
impl BulletproofGenerator {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        let bp_gens = BulletproofGens::new(RANGE_BIT_SIZE, 1);
        let pc_gens = PedersenGens::default();

        Self { bp_gens, pc_gens }
    }

    // Generate proof for a bet amount
    pub fn generate_bet_proof(&self, amount: u64) -> Result<JsValue, JsError> {
        // Create random blinding factor
        let mut rng = OsRng;
        let blinding = Scalar::random(&mut rng);

        // Value to prove (bet amount)
        let value = amount;

        // Create a transcript for the range proof
        let mut prover_transcript = Transcript::new(b"bet_range_proof");

        // Generate the range proof
        let (proof, commitment) = RangeProof::prove_single(
            &self.bp_gens,
            &self.pc_gens,
            &mut prover_transcript,
            value,
            &blinding,
            RANGE_BIT_SIZE,
        )
        .map_err(|e| JsError::new(&format!("Proof generation failed: {}", e)))?;

        // Generate nullifier (unique identifier for the bet)
        let nullifier = generate_nullifier(&commitment.to_bytes(), &blinding.to_bytes());

        // Package the proof data
        let proof_data = BetProofData {
            commitment: commitment.to_bytes().to_vec(),
            proof: proof.to_bytes(),
            nullifier: nullifier.to_vec(),
            blinding_factor: blinding.to_bytes().to_vec(),
        };

        // Serialize to JS
        Ok(serde_wasm_bindgen::to_value(&proof_data)?)
    }

    // Verify a bet proof
    pub fn verify_bet_proof(&self, verification_data: JsValue) -> Result<bool, JsError> {
        // Deserialize verification data
        let data: BetVerificationData = serde_wasm_bindgen::from_value(verification_data)?;

        let commitment_slice: &[u8] = &data.commitment;
        let commitment_bytes: &[u8] = commitment_slice.try_into()?;
        // Reconstruct commitment point
        let commitment = CompressedRistretto::from_slice(commitment_bytes).unwrap();

        // Create verification transcript
        let mut verifier_transcript = Transcript::new(b"bet_range_proof");

        // Verify the range proof
        RangeProof::from_bytes(&data.proof)
            .map_err(|_| JsError::new("Invalid proof bytes"))?
            .verify_single(
                &self.bp_gens,
                &self.pc_gens,
                &mut verifier_transcript,
                &commitment,
                RANGE_BIT_SIZE,
            )
            .map_err(|e| JsError::new(&format!("Proof verification failed: {}", e)))?;

        Ok(true)
    }
}

// Helper function to generate nullifier
fn generate_nullifier(commitment: &[u8], blinding: &[u8]) -> Vec<u8> {
    let mut transcript = Transcript::new(b"bet_nullifier");
    transcript.append_message(b"commitment", commitment);
    transcript.append_message(b"blinding", blinding);

    let mut nullifier = vec![0u8; 32];
    transcript.challenge_bytes(b"nullifier", &mut nullifier);
    nullifier
}

// src/utils.rs
#[wasm_bindgen]
pub fn parse_bet_amount(amount_str: &str) -> Result<u64, JsError> {
    amount_str
        .parse::<u64>()
        .map_err(|_| JsError::new("Invalid bet amount"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_generation_and_verification() {
        let generator = BulletproofGenerator::new();

        // Generate proof for bet amount of 1000
        let proof_data = generator
            .generate_bet_proof(1000)
            .expect("Proof generation should succeed");

        // Verify the generated proof
        let verification_result = generator
            .verify_bet_proof(proof_data)
            .expect("Proof verification should succeed");

        assert!(verification_result);
    }

    #[test]
    fn test_different_bet_amounts() {
        let generator = BulletproofGenerator::new();
        let test_amounts = vec![100, 1000, 10000, 100000];

        for amount in test_amounts {
            let proof_data = generator
                .generate_bet_proof(amount)
                .expect("Proof generation should succeed");
            let verification_result = generator
                .verify_bet_proof(proof_data)
                .expect("Proof verification should succeed");
            assert!(verification_result);
        }
    }
}
