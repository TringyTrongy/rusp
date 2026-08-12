//! The Rusp code word list.
//!
//! 1024 words, so every word contributes exactly 10 bits of entropy to a
//! transfer code. Properties that matter for a code a human has to read out
//! loud and another human has to type:
//!
//! * lowercase ASCII only, 4-6 characters,
//! * every word is uniquely identified by its first three characters,
//! * sorted, so lookup on parse is a binary search.
//!
//! Derivation: filtered from the EFF Long Wordlist (`eff_large_wordlist.txt`)
//! by keeping words of 4-6 lowercase ASCII letters with a distinct 3-character
//! prefix (1052 candidates), then selecting 1024 of them at an even stride so
//! the alphabet stays evenly covered.
//!
//! The EFF Long Wordlist is by the Electronic Frontier Foundation, licensed
//! under CC BY 3.0 US (<https://creativecommons.org/licenses/by/3.0/us/>).
//! See <https://www.eff.org/dice> for the original list and its rationale.

/// Number of words in [`WORDS`]. A power of two, so uniform sampling needs no
/// rejection loop and each word is worth exactly 10 bits.
pub const WORD_COUNT: usize = 1024;

/// Bits of entropy contributed by a single code word.
pub const BITS_PER_WORD: u32 = WORD_COUNT.trailing_zeros();

/// The word list, sorted lexicographically.
pub static WORDS: [&str; WORD_COUNT] = [
    "abacus", "abide", "ablaze", "abroad", "absurd", "accent", "aching", "acid", "acorn", "acre",
    "acting", "afar", "affair", "aflame", "afoot", "afraid", "aged", "aghast", "agile", "agony",
    "agreed", "ahead", "ahoy", "aide", "ajar", "alarm", "album", "alias", "almost", "aloe", "alto",
    "alumni", "always", "amaze", "amber", "amends", "amid", "ample", "amuck", "anchor", "anemia",
    "anger", "animal", "ankle", "annex", "anthem", "anvil", "anyhow", "aorta", "apache", "appear",
    "april", "aptly", "aqua", "area", "argue", "arise", "armed", "aroma", "array", "arson",
    "ascend", "ashen", "aside", "askew", "asleep", "aspect", "astute", "atlas", "atom", "atrium",
    "attach", "audio", "august", "avatar", "avenge", "avid", "avoid", "await", "awhile", "awning",
    "awoke", "awry", "axis", "babble", "backed", "badass", "baffle", "bagel", "baked", "balmy",
    "bamboo", "banana", "barbed", "bash", "batboy", "bauble", "blade", "bleach", "blimp", "blob",
    "bluff", "boat", "bobbed", "body", "bogged", "boil", "bolt", "bonded", "book", "boss",
    "botany", "bounce", "bovine", "boxcar", "breach", "briar", "broken", "brunch", "bubble",
    "bucked", "buddy", "buffed", "buggy", "bulb", "bunch", "busboy", "buzz", "cabana", "cache",
    "caddie", "cage", "cake", "calm", "cameo", "canal", "cape", "carat", "case", "catchy",
    "caucus", "caviar", "cedar", "celery", "cement", "census", "chafe", "chief", "choice",
    "chrome", "chubby", "cider", "cinch", "circle", "citric", "civic", "clad", "clean", "client",
    "cloak", "clump", "coach", "cobalt", "cocoa", "coerce", "coffee", "coil", "coke", "cola",
    "coma", "conch", "cope", "coral", "cosmic", "cotton", "couch", "cover", "cozily", "cradle",
    "crease", "crib", "croak", "crumb", "cube", "cuddle", "cupid", "curdle", "cushy", "cycle",
    "cymbal", "dagger", "daily", "dance", "dares", "dash", "data", "dawn", "daybed", "deacon",
    "debate", "decade", "deduce", "deed", "deface", "degree", "deity", "delay", "demise", "denial",
    "depict", "derail", "detail", "deuce", "device", "dial", "dice", "dill", "dime", "diner",
    "dipped", "ditch", "diving", "dizzy", "doable", "docile", "dodge", "doily", "dole", "domain",
    "donor", "doodle", "dork", "dosage", "dotted", "douche", "dove", "down", "doze", "drab",
    "dreamt", "dried", "drone", "drudge", "dubbed", "ducky", "dude", "duffel", "dugout", "duke",
    "duller", "dupe", "duress", "dusk", "duty", "duvet", "dwarf", "each", "eagle", "earful",
    "easel", "eaten", "ebay", "ebony", "ecard", "echo", "eclair", "edge", "editor", "effort",
    "egging", "either", "eject", "elated", "elbow", "eldest", "eleven", "elite", "elope", "elude",
    "elves", "email", "embark", "emcee", "emit", "emote", "empty", "enable", "encode", "ended",
    "energy", "engine", "enrage", "ensure", "envoy", "enzyme", "epic", "equal", "erased", "errand",
    "erupt", "eskimo", "essay", "estate", "ether", "evade", "even", "evict", "evoke", "exact",
    "excess", "exert", "exhale", "exile", "exodus", "expand", "extent", "fable", "facial", "fade",
    "falcon", "fame", "fancy", "faster", "faucet", "feast", "fedora", "feeble", "feisty", "feline",
    "femur", "ferret", "fester", "fetal", "fever", "fiber", "fiddle", "fifth", "figure", "filing",
    "finale", "five", "flail", "fled", "flick", "float", "flyer", "foam", "foil", "folic",
    "fondly", "food", "fossil", "foyer", "frail", "freely", "friday", "frolic", "fruit", "frying",
    "gaffe", "gains", "gala", "game", "gander", "garage", "gating", "gave", "gawk", "gazing",
    "gear", "gecko", "geek", "geiger", "gender", "gerbil", "getup", "giant", "giblet", "giddy",
    "gift", "giggle", "gilled", "girdle", "given", "gizmo", "glade", "glider", "gloomy", "glue",
    "gnarly", "goal", "goes", "going", "golf", "gonad", "good", "gopher", "gore", "gossip",
    "gothic", "gout", "gown", "grab", "grid", "groggy", "grub", "guide", "gulf", "gummy", "gurgle",
    "gush", "guts", "hacked", "haiku", "half", "hamlet", "handed", "happy", "harbor", "hash",
    "hatbox", "haunt", "haven", "hazard", "headed", "hedge", "hefty", "helium", "hence", "herald",
    "hubcap", "huddle", "huff", "hula", "human", "hunger", "hurdle", "hush", "hybrid", "icing",
    "icky", "icon", "idiocy", "idly", "igloo", "ignore", "iguana", "image", "impale", "iodine",
    "ipad", "iphone", "ipod", "irate", "iron", "issue", "item", "itunes", "ivory", "jackal",
    "jailer", "jargon", "jaunt", "java", "jawed", "jazz", "jeep", "jelly", "jersey", "jester",
    "jiffy", "jigsaw", "jimmy", "jingle", "jockey", "jogger", "jolly", "jovial", "joyous", "judge",
    "juggle", "juice", "july", "jumble", "june", "jurist", "justly", "kabob", "karate", "kebab",
    "keenly", "kelp", "kennel", "kept", "kettle", "kick", "kiln", "kimono", "kindle", "kisser",
    "kite", "kiwi", "knee", "knoll", "koala", "kooky", "kosher", "kudos", "kung", "ladder",
    "lagged", "lair", "lance", "lapdog", "lard", "lash", "latch", "launch", "lavish", "lazily",
    "left", "legacy", "lemon", "lend", "lesser", "letter", "level", "liable", "life", "likely",
    "lilac", "limb", "line", "lion", "liquid", "lisp", "litmus", "lived", "lizard", "lucid",
    "lugged", "lumber", "lunacy", "lurch", "lushly", "luxury", "lying", "lyrics", "macaw",
    "maimed", "maker", "malt", "mama", "manger", "march", "mascot", "math", "mauve", "maybe",
    "moaner", "mobile", "mocha", "modify", "molar", "monday", "moody", "morale", "mosaic",
    "motion", "mouse", "move", "mower", "much", "mulch", "mumble", "muppet", "mural", "museum",
    "mutate", "muzzle", "myself", "myth", "nacho", "nail", "name", "nanny", "narrow", "native",
    "navy", "nearby", "nebula", "nectar", "negate", "neon", "nephew", "nerd", "nest", "neuron",
    "never", "next", "nibble", "niece", "nifty", "nimble", "ninja", "nuclei", "nugget", "number",
    "nutmeg", "nuzzle", "nylon", "oasis", "object", "oblong", "oboe", "obtain", "occupy", "ocean",
    "octane", "ogle", "oink", "okay", "omega", "omit", "onion", "online", "onset", "onto",
    "onward", "onyx", "oops", "ooze", "opal", "open", "opium", "oppose", "other", "otter", "ouch",
    "ought", "ounce", "outage", "oval", "oven", "oxford", "oxygen", "oyster", "ozone", "paced",
    "padded", "pagan", "palace", "panama", "papaya", "parade", "pasta", "patchy", "pauper",
    "paver", "payday", "pebble", "pecan", "pellet", "pencil", "perch", "pesky", "petal", "phobia",
    "phrase", "plank", "pleat", "plod", "pluck", "poach", "poem", "pogo", "pointy", "poker",
    "polar", "poncho", "pope", "pork", "poser", "pouch", "power", "prance", "precut", "pried",
    "probe", "prude", "public", "pucker", "pueblo", "pull", "puma", "pupil", "purely", "pusher",
    "putt", "puzzle", "python", "quack", "quench", "quiet", "quote", "rabid", "race", "radar",
    "raffle", "rage", "raider", "rake", "rally", "ramble", "ranch", "rare", "rascal", "ravage",
    "reach", "rebate", "recall", "refill", "regain", "rehab", "rejoin", "relax", "remake",
    "rename", "reopen", "repair", "rerun", "resale", "reuse", "reveal", "reward", "rhyme",
    "ribbon", "rice", "ridden", "rift", "rigid", "rimmed", "rind", "riot", "ripple", "rise",
    "ritzy", "rival", "roamer", "robe", "rocker", "rogue", "roman", "rope", "roster", "rotten",
    "rover", "royal", "rubbed", "ruckus", "rudder", "ruined", "rule", "rumble", "runner", "rural",
    "ruse", "sacred", "safari", "saga", "said", "sake", "salad", "same", "sandal", "sappy", "sash",
    "satin", "saucy", "savage", "scabby", "scenic", "scheme", "scion", "scoff", "scrap", "scuba",
    "second", "sedan", "seldom", "senate", "sepia", "sequel", "series", "sesame", "settle",
    "shabby", "sheath", "shield", "shock", "shrank", "shun", "siding", "sierra", "sift", "simile",
    "singer", "siren", "sister", "sitcom", "sixth", "size", "skater", "sketch", "skid", "skype",
    "slab", "sled", "sliced", "slogan", "sludge", "small", "smell", "smile", "smock", "smudge",
    "snack", "sneak", "snide", "snooze", "snub", "speak", "sphere", "spider", "spleen", "spoils",
    "sprain", "spud", "squad", "stable", "steam", "stick", "straw", "stucco", "stylus", "suave",
    "sublet", "such", "sudden", "suffix", "sugar", "suing", "sulfur", "supper", "surely", "sushi",
    "swab", "swear", "swipe", "swoop", "swung", "syrup", "system", "tabby", "tackle", "take",
    "talcum", "tamale", "tank", "taps", "target", "task", "tattle", "taunt", "tavern", "thank",
    "thee", "thigh", "thrash", "thud", "tiara", "tibia", "tidal", "tiger", "tile", "timid",
    "tingle", "tipoff", "tiring", "tissue", "trace", "treat", "triage", "trophy", "truce", "tubby",
    "tulip", "tumble", "turban", "tusk", "tutor", "tweak", "twice", "tycoon", "tying", "tyke",
    "udder", "ultra", "umpire", "unable", "unbend", "unclad", "undead", "unease", "unfair",
    "unholy", "unify", "unkind", "unless", "unmade", "unpack", "unread", "unsafe", "untidy",
    "unused", "unwary", "unzip", "upbeat", "update", "upheld", "upload", "upon", "upper", "uproar",
    "upside", "uptake", "upward", "urban", "urchin", "urgent", "usable", "used", "usher", "usual",
    "utmost", "utopia", "utter", "vacant", "valid", "vanish", "varied", "veal", "vegan", "velcro",
    "vendor", "verify", "vessel", "veto", "viable", "vibes", "vice", "video", "viewer", "violet",
    "viper", "viral", "visa", "vixen", "voice", "volley", "voter", "vowed", "voyage", "wafer",
    "waged", "wake", "walk", "wand", "wasabi", "watch", "waving", "whacky", "wheat", "whiff",
    "whole", "wick", "widely", "wife", "wimp", "wince", "wipe", "wired", "wisdom", "wizard",
    "wobble", "wolf", "womb", "woof", "word", "wound", "woven", "wrath", "wreath", "wrist", "xbox",
    "xerox", "yahoo", "yard", "yeah", "yelp", "yield", "yippee", "yodel", "yoga", "yonder", "yoyo",
    "yummy", "zebra", "zero", "zesty", "zippy", "zodiac", "zombie", "zone",
];

/// True when `word` is one of the Rusp code words.
pub fn contains(word: &str) -> bool {
    WORDS.binary_search(&word).is_ok()
}

/// Position of `word` in [`WORDS`], if present.
pub fn index_of(word: &str) -> Option<usize> {
    WORDS.binary_search(&word).ok()
}

/// Number of characters that uniquely identify a word in the list.
pub const UNIQUE_PREFIX: usize = 3;

/// Guess which list word a mistyped word was meant to be.
///
/// Every word in [`WORDS`] has a distinct [`UNIQUE_PREFIX`]-character prefix,
/// so a shared prefix narrows the field to at most one candidate. Returns
/// `None` when there is no single obvious answer — a wrong guess here would be
/// worse than silence, since the user has to retype the code either way.
pub fn suggest(word: &str) -> Option<&'static str> {
    if !word.is_ascii() || word.len() < UNIQUE_PREFIX {
        return None;
    }
    let prefix = &word[..UNIQUE_PREFIX];
    let start = WORDS.partition_point(|w| *w < prefix);
    let candidate = *WORDS.get(start)?;
    if !candidate.starts_with(prefix) || candidate == word {
        return None;
    }
    // Guard against "harmonica" confidently becoming "harbor".
    if candidate.len().abs_diff(word.len()) > 2 {
        return None;
    }
    Some(candidate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn list_is_a_power_of_two() {
        assert_eq!(WORDS.len(), WORD_COUNT);
        assert!(WORD_COUNT.is_power_of_two());
        assert_eq!(BITS_PER_WORD, 10);
    }

    #[test]
    fn list_is_sorted_and_unique() {
        assert!(WORDS.windows(2).all(|w| w[0] < w[1]), "list must be sorted");
        assert_eq!(WORDS.iter().collect::<HashSet<_>>().len(), WORD_COUNT);
    }

    #[test]
    fn words_are_short_lowercase_ascii() {
        for w in WORDS {
            assert!(
                (4..=6).contains(&w.len()),
                "`{w}` should be 4-6 characters long"
            );
            assert!(
                w.bytes().all(|b| b.is_ascii_lowercase()),
                "`{w}` should be lowercase ascii"
            );
        }
    }

    #[test]
    fn three_characters_identify_a_word() {
        let prefixes: HashSet<&str> = WORDS.iter().map(|w| &w[..UNIQUE_PREFIX]).collect();
        assert_eq!(prefixes.len(), WORD_COUNT);
    }

    #[test]
    fn lookup_round_trips() {
        for (i, w) in WORDS.iter().enumerate() {
            assert!(contains(w));
            assert_eq!(index_of(w), Some(i));
        }
        assert!(!contains("notaruspword"));
        assert_eq!(index_of("notaruspword"), None);
    }

    #[test]
    fn suggestions_are_useful_but_cautious() {
        assert_eq!(suggest("harbour"), Some("harbor"));
        assert_eq!(suggest("cottn"), Some("cotton"));
        // Exact matches are not "suggestions".
        assert_eq!(suggest("harbor"), None);
        // Nothing in the list starts with these.
        assert_eq!(suggest("qqqq"), None);
        // Too short to disambiguate.
        assert_eq!(suggest("ha"), None);
        // Non-ASCII must not panic on slicing.
        assert_eq!(suggest("héllo"), None);
        // Wildly different length: refuse rather than mislead.
        assert_eq!(suggest("harmonically"), None);
    }
}
