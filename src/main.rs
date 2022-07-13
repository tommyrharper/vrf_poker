//! Drawing cards using VRFs

extern crate schnorrkel;
use merlin::Transcript;
use schnorrkel::{
    vrf::{VRFInOut, VRFPreOut, VRFProof},
    Keypair, PublicKey,
};
use sp_core::*;

const NUM_DRAWS: u8 = 8;
const NUM_CARDS: u16 = 52;

struct Player {
    keypair: Keypair,
    card: Option<u16>,
    pub signature: Option<[u8; 97]>,
    pub revealed_card: Option<u16>,
}

impl Player {
    fn new() -> Self {
        let mut csprng = rand_core::OsRng;
        Player {
            keypair: Keypair::generate_with(&mut csprng),
            signature: None,
            card: None,
            revealed_card: None,
        }
    }

    fn public_key(&self) -> &PublicKey {
        &self.keypair.public
    }

    fn commit_card(&mut self, VRF_seed: &[u8; 32]) -> (u16, [u8; 97]) {
        let draw = draws(&self.keypair, VRF_seed);
        let (card, signature) = draw[0];
        self.card = Some(card);
        self.signature = Some(signature);
        (card, signature)
    }

    fn reveal_card(&mut self, VRF_seed: &[u8; 32]) -> Option<u16> {
        let signature = self.signature.unwrap();
        let reveal_card = recieve(&self.public_key(), &signature, VRF_seed);
        self.revealed_card = reveal_card;
        reveal_card
    }
}

struct Game {
    players: [Player; 2],
    vrf_seed: [u8; 32],
}

impl Game {
    fn new(players: [Player; 2]) -> Self {
        let vrf_seed = create_initial_hash(players[0].public_key(), players[1].public_key());
        Game { players, vrf_seed }
    }

    fn commit_cards(&mut self) {
        self.players[0].commit_card(&self.vrf_seed);
        self.players[1].commit_card(&self.vrf_seed);
    }

    fn reveal_cards(&mut self) {
        self.players[0].reveal_card(&self.vrf_seed);
        self.players[1].reveal_card(&self.vrf_seed);
        self.complete_round();
    }

    fn complete_round(&self) {
        let player_1 = &self.players[0];
        let player_2 = &self.players[1];

        println!("Player 1 card: {:?}", player_1.revealed_card);
        println!("Player 2 card: {:?}", player_2.revealed_card);

        match (player_1.revealed_card, player_2.revealed_card) {
            (Some(card_1), Some(card_2)) if card_1 > card_2 => {
                println!("Confirmed - Player 1 wins!")
            }
            (Some(card_1), Some(card_2)) if card_1 < card_2 => {
                println!("Confirmed - Player 2 wins!")
            }
            (Some(card_1), Some(card_2)) if card_1 == card_2 => println!("Confirmed - It's a tie!"),
            _ => panic!("No one won!?!?!"),
        }
    }
}

fn main() {
    let player_1 = Player::new();
    let player_2 = Player::new();
    let mut game = Game::new([player_1, player_2]);

    game.commit_cards();
    game.reveal_cards();
}

fn create_initial_hash(public_key_1: &PublicKey, public_key_2: &PublicKey) -> [u8; 32] {
    let first_bytes = &public_key_1.to_bytes()[..];
    let second_bytes = &public_key_2.to_bytes()[..];
    let joined_bytes = [first_bytes, second_bytes].concat();
    twox_256(&joined_bytes)
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
    let (io, _) = public.vrf_verify(t, &out, &proof).ok()?;
    find_card(&io)
}
