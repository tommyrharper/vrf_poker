//! Drawing cards using VRFs

extern crate schnorrkel;
use hexdisplay::*;
use merlin::Transcript;
use schnorrkel::{
    vrf::{VRFInOut, VRFPreOut, VRFProof},
    Keypair, PublicKey,
};
use sp_core::*;

const NUM_DRAWS: u8 = 8;
const NUM_CARDS: u16 = 52;

// struct Player {
//     keypair: Keypair,
//     vrf_seed: VRFPreOut,
//     draw: u16,
//     signature: [u8; 97],
// }

// impl Player {
//     fn new() -> Self {
//         Player {
//             keypair: create_player(),
//             vrf_seed: VRFPreOut::new(),
//         }
//     }
// }

fn main() {
    let player_1 = create_player();
    let player_2 = create_player();

    let hash = create_initial_hash(player_1.public, player_2.public);

    let (player_1_card, player_1_card_signature) = commit_my_card(&player_1, &hash);
    let (player_2_card, player_2_card_signature) = commit_my_card(&player_2, &hash);

    println!("Player 1 card: {}", player_1_card);
    println!("Player 2 card: {}", player_2_card);

    if player_1_card > player_2_card {
        println!("Player 1 wins!");
    } else if player_2_card > player_1_card {
        println!("Player 2 wins!");
    } else {
        println!("It's a tie!");
    }

    let player_1_checked_card =
        check_other_players_card(&player_1.public, &player_1_card_signature, &hash).unwrap();
    let player_2_checked_card =
        check_other_players_card(&player_2.public, &player_2_card_signature, &hash).unwrap();

    println!("Confirmed - Player 1 card: {:?}", player_1_checked_card);
    println!("Confirmed - Player 2 card: {:?}", player_2_checked_card);

    if player_1_checked_card > player_2_checked_card {
        println!("Confirmed - player 1 wins!");
    } else if player_2_checked_card > player_1_checked_card {
        println!("Confirmed - player 2 wins!");
    } else {
        println!("Confirmed - It's a tie!");
    }
}

fn create_initial_hash(public_key_1: PublicKey, public_key_2: PublicKey) -> [u8; 32] {
    let first_bytes = &public_key_1.to_bytes()[..];
    let second_bytes = &public_key_2.to_bytes()[..];
    let joined_bytes = [first_bytes, second_bytes].concat();
    twox_256(&joined_bytes)
}

fn check_other_players_card(public_key: &PublicKey, signature: &[u8; 97], hash: &[u8; 32]) -> Option<u16> {
    let VRF_seed = hash;
    let reveal_card = recieve(public_key, signature, VRF_seed);
    reveal_card
}

fn create_player() -> Keypair {
    let mut csprng = rand_core::OsRng;
    let mut keypair = Keypair::generate_with(&mut csprng);
    keypair
}

fn commit_my_card(player: &Keypair, hash: &[u8; 32]) -> (u16, [u8; 97]) {
    let VRF_seed = hash;
    let mut draw = draws(player, VRF_seed);

    let (card, signature) = draw[0];

    (card, signature)
}

/// Processes VRF inputs, checking validity of the number of draws
fn draw_transcript(seed: &[u8; 32], draw_num: u8) -> Option<Transcript> {
    if draw_num > NUM_DRAWS {
        return None;
    }
    let mut t = Transcript::new(b"Card Draw Transcript");
    t.append_message(b"seed", seed);
    t.append_u64(b"draw", draw_num as u64);
    Some(t)
}

/// Computes actual card draw from VRF inputs & outputs together
fn find_card(io: &VRFInOut) -> Option<u16> {
    let b: [u8; 8] = io.make_bytes(b"card");
    // We make one in half the draws invalid so nobody knows how many cards anyone else has
    // if b[7] & 0x80 { return None; }
    Some((u64::from_le_bytes(b) % (NUM_CARDS as u64)) as u16)
}

/// Attempts to draw a card
fn try_draw(keypair: &Keypair, seed: &[u8; 32], draw_num: u8) -> Option<(u16, [u8; 97])> {
    let t = draw_transcript(seed, draw_num)?;
    let (io, proof, _) = keypair.vrf_sign(t);
    let card = find_card(&io)?;
    let mut vrf_signature = [0u8; 97];
    // the first 32 bytes are io
    vrf_signature[..32].copy_from_slice(&io.to_preout().to_bytes()[..]);
    // the next 64 bytes are the proof
    vrf_signature[32..96].copy_from_slice(&proof.to_bytes()[..]);
    // the final byte is the draw number
    vrf_signature[96] = draw_num;
    Some((card, vrf_signature))
}

/// Draws all our cards for the give seed
fn draws(keypair: &Keypair, seed: &[u8; 32]) -> Vec<(u16, [u8; 97])> {
    (0..NUM_DRAWS)
        .filter_map(|i| try_draw(keypair, seed, i))
        .collect()
}

/// Verifies a card play
///
/// We depend upon application code to enforce the public key and seed
/// being chosen correctly.
///
/// We encode the draw number into the vrf signature since an honest
/// application has no use for this, outside the verification check in
/// `draw_transcript`.
fn recieve(public: &PublicKey, vrf_signature: &[u8; 97], seed: &[u8; 32]) -> Option<u16> {
    let t = draw_transcript(seed, vrf_signature[96])?;
    let out = VRFPreOut::from_bytes(&vrf_signature[..32]).ok()?;
    let proof = VRFProof::from_bytes(&vrf_signature[32..96]).ok()?;
    // We need not understand the error type here, but someone might
    // care about invalid signatures vs invalid card draws.
    println!("transcript drawn");
    let (io, _) = public.vrf_verify(t, &out, &proof).ok()?;
    println!("verified");
    find_card(&io)
}
